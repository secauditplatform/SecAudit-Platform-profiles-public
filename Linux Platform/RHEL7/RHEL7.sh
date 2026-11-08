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

RHEL7_FIND_CAP="${RHEL7_FIND_CAP:-${CRE_FIND_CAP:-20}}"
CRE_FIND_CAP="${RHEL7_FIND_CAP}"
RHEL7_CMD_CAP="${RHEL7_CMD_CAP:-${CRE_CMD_CAP:-12}}"
CRE_CMD_CAP="${RHEL7_CMD_CAP}"
RHEL7_DNF_CAP="${RHEL7_DNF_CAP:-${CRE_DNF_CAP:-30}}"
CRE_DNF_CAP="${RHEL7_DNF_CAP}"
RHEL7_ALLOW_CONTAINER_KMOD="${RHEL7_ALLOW_CONTAINER_KMOD:-${CRE_ALLOW_CONTAINER_KMOD:-${LINUX_CRE_ALLOW_CONTAINER_MODULES:-${ALMA_CRE_ALLOW_CONTAINER_MODULES:-0}}}}"
CRE_ALLOW_CONTAINER_KMOD="${RHEL7_ALLOW_CONTAINER_KMOD}"
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
        sec_audit_report_pass "$num" "${label} (waived: RHEL7_ALLOW_CONTAINER_KMOD=1)"
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

sec_audit_chkconfig_service_line() {
  chkconfig --list "$1" 2>/dev/null | awk -v s="$1" '$1==s {print; exit}'
}

sec_audit_chkconfig_is_off() {
    local svc="$1" line
    line=$(sec_audit_chkconfig_service_line "$svc")
    [ -z "$line" ] && return 0
    echo "$line" | grep -qE ':[[:space:]]*on' && return 1
    return 0
}

sec_audit_chkconfig_is_on() {
    local svc="$1" line
    line=$(sec_audit_chkconfig_service_line "$svc")
    [ -n "$line" ] && echo "$line" | grep -qE ':[[:space:]]*on'
}

sec_audit_pkg_is_absent() { ! sec_audit_pkg_is_installed "$1"; }

sec_audit_sysctl_files_have() {
    local key="$1" want="$2" esc f
    esc=${key//./\\.}
    for f in /etc/sysctl.conf /etc/sysctl.d/*.conf; do
        [ -f "$f" ] || continue
        grep -qE "^[[:space:]]*${esc}[[:space:]]*=[[:space:]]*${want}\b" "$f" 2>/dev/null && return 0
    done
    return 1
}

sec_audit_req_sysctl_runtime() {
    local n="$1" key="$2" want="$3" label="$4"
    if sec_audit_sysctl_runtime_equals "$key" "$want"; then
        echo "RULE${n}= PASS: ${label}"
    else
        echo "RULE${n}= FAIL: ${label} (kernel $(sec_audit_sysctl_runtime_raw "$key" 2>/dev/null || echo '?') expected ${want})"
    fi
}

sec_audit_ipv6_enabled() {
    [ -f /proc/net/if_inet6 ] && grep -qv '^[[:space:]]*$' /proc/net/if_inet6 2>/dev/null
}

sec_audit_sshd_config_active_line() {
    local key="$1"
    grep -iE "^[[:space:]]*${key}[[:space:]]+" /etc/ssh/sshd_config 2>/dev/null | grep -vE '^[[:space:]]*#' | tail -1
}

sec_audit_sshd_config_value() {
    local line
    line=$(sec_audit_sshd_config_active_line "$1")
    [ -z "$line" ] && return 0
    echo "$line" | awk '{print $2}'
}

sec_audit_sshd_config_effective_yes() {
    local v
    v=$(sec_audit_sshd_config_value "$1" | tr '[:upper:]' '[:lower:]')
    [ "$v" = "yes" ] || [ "$v" = "true" ] || [ "$v" = "1" ]
}

sec_audit_sshd_config_effective_no() {
    local v
    v=$(sec_audit_sshd_config_value "$1" | tr '[:upper:]' '[:lower:]')
    [ -z "$v" ] && return 0
    [ "$v" = "no" ] || [ "$v" = "false" ] || [ "$v" = "0" ]
}

_AUDIT_RULES_FILES_READY=0
_AUDIT_RULES_FILES_CACHE=""
_auditctl_l_ready=0
_auditctl_l_cache=""

sec_audit_audit_rules_files_ensure() {
    [ "${_AUDIT_RULES_FILES_READY:-0}" -eq 1 ] && return 0
    _AUDIT_RULES_FILES_READY=1
    shopt -s nullglob
    _AUDIT_RULES_FILES_CACHE=$(cat /etc/audit/rules.d/*.rules /etc/audit/audit.rules 2>/dev/null)
    shopt -u nullglob
}

sec_audit_auditctl_l_ensure() {
    [ "${_auditctl_l_ready:-0}" -eq 1 ] && return 0
    _auditctl_l_ready=1
    if sec_audit_have_bin auditctl; then
        _auditctl_l_cache=$(auditctl -l 2>/dev/null) || _auditctl_l_cache=""
    else
        _auditctl_l_cache=""
    fi
}

sec_audit_stat_uid_name() {
    stat -c '%U' "$1" 2>/dev/null
}

sec_audit_stat_gid_name() {
    stat -c '%G' "$1" 2>/dev/null
}

sec_audit_cron_path_perm_ok() {
    local p="$1"
    [ -e "$p" ] || return 1
    sec_audit_assert_path_access "$p" 600 root root || \
    sec_audit_assert_path_access "$p" 700 root root
}

sec_audit_pam_stack_files() {
    local f
    for f in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
        [ -f "$f" ] && printf '%s\n' "$f"
    done
}

sec_audit_pam_auth_has_tally2() {
    local f deny unlock
    deny=5
    unlock=900
    for f in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
        [ -f "$f" ] || continue
        grep -qE '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_tally2\.so' "$f" 2>/dev/null || return 1
        grep -E 'pam_tally2\.so' "$f" | grep -q "deny=${deny}" || return 1
        grep -E 'pam_tally2\.so' "$f" | grep -q "unlock_time=${unlock}" || return 1
    done
    return 0
}

FIND_SCAN_DIRS="/home /root /etc /boot /bin /sbin /tmp /usr/bin /usr/sbin /usr/lib /usr/lib64 /var"

sec_audit_find_sticky_world_writable_count() {
    local c=0 d
    for d in $FIND_SCAN_DIRS; do
        [ -d "$d" ] || continue
        c=$((c + $(sec_audit_soft_find --timeout=120 "$d" -xdev -type d \( -perm -0002 ! -perm -1000 \) 2>/dev/null | wc -l)))
    done
    echo "$c"
}

sec_audit_find_world_writable_file_count() {
    local c=0 d
    for d in $FIND_SCAN_DIRS; do
        [ -d "$d" ] || continue
        c=$((c + $(sec_audit_soft_find --timeout=120 "$d" -xdev -type f -perm -0002 2>/dev/null | wc -l)))
    done
    echo "$c"
}

sec_audit_find_nouser_count() {
    local c=0 d
    for d in $FIND_SCAN_DIRS; do
        [ -d "$d" ] || continue
        c=$((c + $(sec_audit_soft_find --timeout=120 "$d" -xdev -nouser 2>/dev/null | wc -l)))
    done
    echo "$c"
}

sec_audit_find_nogroup_count() {
    local c=0 d
    for d in $FIND_SCAN_DIRS; do
        [ -d "$d" ] || continue
        c=$((c + $(sec_audit_soft_find --timeout=120 "$d" -xdev -nogroup 2>/dev/null | wc -l)))
    done
    echo "$c"
}

sec_audit_find_suid_count() {
    local c=0 d
    for d in $FIND_SCAN_DIRS; do
        [ -d "$d" ] || continue
        c=$((c + $(sec_audit_soft_find --timeout=120 "$d" -xdev -type f -perm -4000 2>/dev/null | wc -l)))
    done
    echo "$c"
}

sec_audit_find_sgid_count() {
    local c=0 d
    for d in $FIND_SCAN_DIRS; do
        [ -d "$d" ] || continue
        c=$((c + $(sec_audit_soft_find --timeout=120 "$d" -xdev -type f -perm -2000 2>/dev/null | wc -l)))
    done
    echo "$c"
}

sec_audit_yum_gpgcheck_global_ok() {
    local v
    [ -f /etc/yum.conf ] || return 1
    v=$(grep -iE '^[[:space:]]*gpgcheck[[:space:]]*=' /etc/yum.conf | tail -1 | awk -F= '{print $2}' | tr -d '[:space:]')
    [ "$v" = "1" ]
}

sec_audit_yum_repo_gpgcheck0_enabled() {
    local f
    [ -d /etc/yum.repos.d ] || return 1
    for f in /etc/yum.repos.d/*.repo; do
        [ -f "$f" ] || continue
        awk '
            BEGIN{sec="";en=1;gc=1}
            /^\[/ {sec=$0; sub(/\[|\]/,"",sec); en=1; gc=1; next}
            /^gpgcheck=/ {gsub(/#.*/,""); split($0,a,"="); if(tolower(a[2]) ~ /^0|false|no/) gc=0}
            /^enabled=/ {gsub(/#.*/,""); split($0,a,"="); if(tolower(a[2]) ~ /^0|false|no/) en=0}
            END{}
            /gpgcheck=0/ && /enabled=1/ {found=1}
        ' "$f" 2>/dev/null | grep -q . && return 0
    done
    grep -rE '^[[:space:]]*gpgcheck[[:space:]]*=[[:space:]]*0' /etc/yum.repos.d/*.repo 2>/dev/null | grep -vE '^[[:space:]]*#' | grep -q .
}

sec_audit_grub_conf_path() {
    if [ -f /boot/grub/grub.conf ]; then
        echo /boot/grub/grub.conf
    elif [ -f /boot/grub/grub.cfg ]; then
        echo /boot/grub/grub.cfg
    fi
}

sec_audit_grub_kernel_lines() {
    local g
    g=$(sec_audit_grub_conf_path)
    [ -n "$g" ] && grep -E '^[[:space:]]*kernel[[:space:]]' "$g" 2>/dev/null
}

sec_audit_systemctl_is_masked() {
    local u
    u=$(systemctl is-enabled "$1" 2>/dev/null | head -1 | tr -d '\r')
    [ "$u" = "masked" ] || [ "$u" = "disabled" ] || [ "$u" = "not-found" ]
}

sec_audit_sshd_effective_usable() {
    _sshd_t_ensure
    if ! sec_audit_have_bin sshd; then
        return 1
    fi
    [[ -n "${_sshd_t_cache//[[:space:]]/}" ]]
}

sec_audit_pam_stacks_grep_P() {
    local pattern="$1" p stacks
    stacks="$(pam_stack_paths_password_system)"
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
    stacks="$(pam_stack_paths_password_system)"
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
if sec_audit_kmod_is_blocked cramfs; then
    sec_audit_report_pass 1 "mounting of cramfs filesystems is disabled"
else
    sec_audit_report_fail 1 "cramfs module loaded or not disabled via modprobe"
fi

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
# RULE42:
if yum check-update --security 2>/dev/null | grep -q 'No packages needed for security'; then
    sec_audit_report_pass 127 "no security updates pending"
else
    sec_audit_report_fail 127 "security updates may be available (run yum check-update --security)"
fi

# RULE44:
if sec_audit_pkg_is_installed ntp || sec_audit_pkg_is_installed chrony; then
    sec_audit_report_pass 29 "time synchronization package installed (ntp or chrony)"
else
    sec_audit_report_fail 29 "neither ntp nor chrony installed (manual: verify time sync)"
fi

# RULE45:
_ok=0
if [ -f /etc/ntp.conf ]; then
    grep -qE '^[[:space:]]*restrict' /etc/ntp.conf && grep -qE '^[[:space:]]*(server|pool)' /etc/ntp.conf && _ok=1
    [ -f /etc/sysconfig/ntpd ] && grep -qE '^OPTIONS=.*-u ntp:ntp' /etc/sysconfig/ntpd && _ok=1
fi
if [ "${_ok:-0}" -eq 1 ]; then
    sec_audit_report_pass 30 "ntp configured (restrict, server/pool, OPTIONS)"
else
    sec_audit_report_fail 30 "ntp not fully configured"
fi

# RULE46:
_ok=0
if [ -f /etc/chrony.conf ]; then
    grep -qE '^[[:space:]]*(server|pool)' /etc/chrony.conf && _ok=1
fi
if [ "${_ok:-0}" -eq 1 ]; then
    sec_audit_report_pass 31 "chrony server/pool configured"
else
    sec_audit_report_fail 31 "chrony not configured or not in use"
fi

# RULE47:
sec_audit_assert_service_unused 47 avahi "avahi daemon services are not in use" "avahi daemon services are installed and enabled or actively running" "avahi-daemon.socket" "avahi-daemon.service"
# RULE48:
sec_audit_assert_service_unused 48 cups "print server services are not in use" "print server services are installed and enabled or actively running" "cups.socket" "cups.service"
# RULE49:
if sec_audit_pkg_is_absent dhcp && sec_audit_systemctl_is_masked dhcpd; then
    sec_audit_report_pass 34 "dhcp not installed and dhcpd off"
elif sec_audit_pkg_is_absent dhcp; then
    sec_audit_report_pass 34 "dhcp not installed"
else
    sec_audit_report_fail 34 "dhcp installed or dhcpd enabled"
fi

# RULE50:
if sec_audit_pkg_is_absent openldap-servers && sec_audit_systemctl_is_masked slapd; then
    sec_audit_report_pass 35 "openldap-servers not installed and slapd off"
elif sec_audit_pkg_is_absent openldap-servers; then
    sec_audit_report_pass 35 "openldap-servers not installed"
else
    sec_audit_report_fail 35 "openldap-servers installed or slapd enabled"
fi

# RULE55:
sec_audit_req_sysctl_runtime 55 net.ipv4.ip_forward 0 "IP forwarding disabled (ipv4)"

# RULE56:
if sec_audit_sysctl_files_have net.ipv4.ip_forward 0; then
    echo "RULE52.2= PASS: net.ipv4.ip_forward=0 in sysctl config"
else
    echo "RULE52.2= FAIL: net.ipv4.ip_forward not set to 0 on disk"
fi

# RULE57:
_ok=1
sec_audit_sysctl_runtime_equals net.ipv4.conf.all.send_redirects 0 || _ok=0
sec_audit_sysctl_runtime_equals net.ipv4.conf.default.send_redirects 0 || _ok=0
if [ "${_ok:-0}" -eq 1 ]; then
    sec_audit_report_pass 53 "packet redirect sending disabled"
else
    sec_audit_report_fail 53 "send_redirects not 0 for all/default"
fi

# RULE58:
_ok=1
sec_audit_sysctl_runtime_equals net.ipv4.conf.all.accept_source_route 0 || _ok=0
sec_audit_sysctl_runtime_equals net.ipv4.conf.default.accept_source_route 0 || _ok=0
if sec_audit_ipv6_enabled; then
    sec_audit_sysctl_runtime_equals net.ipv6.conf.all.accept_source_route 0 || _ok=0
    sec_audit_sysctl_runtime_equals net.ipv6.conf.default.accept_source_route 0 || _ok=0
fi
if [ "${_ok:-0}" -eq 1 ]; then
    sec_audit_report_pass 54 "source routed packets not accepted"
else
    sec_audit_report_fail 54 "accept_source_route not disabled"
fi

# RULE59:
_ok=1
sec_audit_sysctl_runtime_equals net.ipv4.conf.all.accept_redirects 0 || _ok=0
sec_audit_sysctl_runtime_equals net.ipv4.conf.default.accept_redirects 0 || _ok=0
if sec_audit_ipv6_enabled; then
    sec_audit_sysctl_runtime_equals net.ipv6.conf.all.accept_redirects 0 || _ok=0
    sec_audit_sysctl_runtime_equals net.ipv6.conf.default.accept_redirects 0 || _ok=0
fi
if [ "${_ok:-0}" -eq 1 ]; then
    sec_audit_report_pass 55 "ICMP redirects not accepted"
else
    sec_audit_report_fail 55 "accept_redirects not disabled"
fi

# RULE60:
_ok=1
sec_audit_sysctl_runtime_equals net.ipv4.conf.all.secure_redirects 0 || _ok=0
sec_audit_sysctl_runtime_equals net.ipv4.conf.default.secure_redirects 0 || _ok=0
if [ "${_ok:-0}" -eq 1 ]; then
    sec_audit_report_pass 56 "secure ICMP redirects not accepted"
else
    sec_audit_report_fail 56 "secure_redirects not disabled"
fi

# RULE61:
_ok=1
sec_audit_sysctl_runtime_equals net.ipv4.conf.all.log_martians 1 || _ok=0
sec_audit_sysctl_runtime_equals net.ipv4.conf.default.log_martians 1 || _ok=0
if [ "${_ok:-0}" -eq 1 ]; then
    sec_audit_report_pass 57 "suspicious packets logged (log_martians=1)"
else
    sec_audit_report_fail 57 "log_martians not enabled"
fi

# RULE62:
sec_audit_req_sysctl_runtime 62 net.ipv4.icmp_echo_ignore_broadcasts 1 "broadcast ICMP ignored"

# RULE63:
sec_audit_req_sysctl_runtime 63 net.ipv4.icmp_ignore_bogus_error_responses 1 "bogus ICMP responses ignored"

# RULE64:
_ok=1
sec_audit_sysctl_runtime_equals net.ipv4.conf.all.rp_filter 1 || _ok=0
sec_audit_sysctl_runtime_equals net.ipv4.conf.default.rp_filter 1 || _ok=0
if [ "${_ok:-0}" -eq 1 ]; then
    sec_audit_report_pass 60 "reverse path filtering enabled"
else
    sec_audit_report_fail 60 "rp_filter not enabled"
fi

# RULE65:
sec_audit_req_sysctl_runtime 65 net.ipv4.tcp_syncookies 1 "TCP SYN cookies enabled"

# RULE66:
_ok=1
sec_audit_sysctl_runtime_equals net.ipv6.conf.all.accept_ra 0 || _ok=0
sec_audit_sysctl_runtime_equals net.ipv6.conf.default.accept_ra 0 || _ok=0
if sec_audit_ipv6_enabled; then
    [ "${_ok:-0}" -eq 1 ] || _ok=0
fi
if ! sec_audit_ipv6_enabled || [ "${_ok:-0}" -eq 1 ]; then
    sec_audit_report_pass 62 "IPv6 router advertisements not accepted (or IPv6 disabled)"
else
    sec_audit_report_fail 62 "IPv6 accept_ra not disabled"
fi

# RULE70:
if grep -qiE '^[[:space:]]*max_log_file_action[[:space:]]*=[[:space:]]*keep_logs' /etc/audit/auditd.conf 2>/dev/null; then
    sec_audit_report_pass 66 "audit logs retained (max_log_file_action=keep_logs)"
else
    sec_audit_report_fail 66 "max_log_file_action not keep_logs"
fi

# RULE71:
if grep -qiE '^[[:space:]]*max_log_file[[:space:]]*=' /etc/audit/auditd.conf 2>/dev/null; then
    sec_audit_report_pass 71 "audit log storage size configured (max_log_file set)"
else
    sec_audit_report_fail 71 "max_log_file not set in auditd.conf"
fi

# RULE72:
if grep -qiE '^[[:space:]]*space_left_action[[:space:]]*=[[:space:]]*email' /etc/audit/auditd.conf 2>/dev/null; then
    sec_audit_report_pass 72 "space_left_action=email when audit disk full"
else
    sec_audit_report_fail 72 "space_left_action not email"
fi

# RULE73:
if grep -qiE '^[[:space:]]*action_mail_acct[[:space:]]*=' /etc/audit/auditd.conf 2>/dev/null; then
    sec_audit_report_pass 73 "action_mail_acct configured in auditd.conf"
else
    sec_audit_report_fail 73 "action_mail_acct not configured"
fi

# RULE74:
if grep -qiE '^[[:space:]]*admin_space_left_action[[:space:]]*=[[:space:]]*halt' /etc/audit/auditd.conf 2>/dev/null; then
    sec_audit_report_pass 672 "admin_space_left_action=halt"
else
    sec_audit_report_fail 672 "admin_space_left_action not halt"
fi

# RULE78:
if grep -rqE '^[^#]*\.\*[^@]*@[^[:space:]]+' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null; then
    sec_audit_report_pass 692 "rsyslog forwards logs to remote host"
else
    sec_audit_report_fail 692 "no remote log host in rsyslog config"
fi

# RULE79:
_listen=0
grep -rqE '\$ModLoad imtcp|\$InputTCPServerRun' /etc/rsyslog.conf /etc/rsyslog.d 2>/dev/null && _listen=1
if [ "${_listen:-0}" -eq 0 ]; then
    sec_audit_report_pass 693 "rsyslog not accepting remote TCP logs (or not configured as collector)"
else
    sec_audit_report_fail 693 "rsyslog configured to accept remote logs via TCP"
fi

# RULE80:
if sec_audit_systemd_is_enabled crond; then
    sec_audit_report_pass 73 "crond enabled"
else
    sec_audit_report_fail 73 "crond not enabled"
fi

# RULE81:
if sec_audit_cron_path_perm_ok /etc/crontab; then
    sec_audit_report_pass 74 "/etc/crontab permissions OK (600/700 root)"
else
    sec_audit_report_fail 74 "/etc/crontab permissions (expected 600 root:root)"
fi

# RULE82:
if sec_audit_cron_path_perm_ok /etc/cron.hourly; then
    sec_audit_report_pass 75 "/etc/cron.hourly permissions OK (600/700 root)"
else
    sec_audit_report_fail 75 "/etc/cron.hourly permissions (expected 600 root:root)"
fi

# RULE83:
if sec_audit_cron_path_perm_ok /etc/cron.daily; then
    sec_audit_report_pass 76 "/etc/cron.daily permissions OK (600/700 root)"
else
    sec_audit_report_fail 76 "/etc/cron.daily permissions (expected 600 root:root)"
fi

# RULE84:
if sec_audit_cron_path_perm_ok /etc/cron.weekly; then
    sec_audit_report_pass 77 "/etc/cron.weekly permissions OK (600/700 root)"
else
    sec_audit_report_fail 77 "/etc/cron.weekly permissions (expected 600 root:root)"
fi

# RULE85:
if sec_audit_cron_path_perm_ok /etc/cron.monthly; then
    sec_audit_report_pass 78 "/etc/cron.monthly permissions OK (600/700 root)"
else
    sec_audit_report_fail 78 "/etc/cron.monthly permissions (expected 600 root:root)"
fi

# RULE86:
if sec_audit_cron_path_perm_ok /etc/cron.d; then
    sec_audit_report_pass 79 "/etc/cron.d permissions OK (600/700 root)"
else
    sec_audit_report_fail 79 "/etc/cron.d permissions (expected 600 root:root)"
fi

# RULE87:
_ok=1
[ -f /etc/cron.deny ] && _ok=0
[ -f /etc/cron.allow ] || _ok=0
[ -f /etc/cron.allow ] && sec_audit_assert_path_access /etc/cron.allow 600 root root || _ok=0
if [ "${_ok:-0}" -eq 1 ]; then
    sec_audit_report_pass 802 "cron restricted (/etc/cron.allow, no cron.deny)"
else
    sec_audit_report_fail 802 "cron access not restricted correctly"
fi

# RULE88:
_ok=1
[ -f /etc/at.deny ] && _ok=0
[ -f /etc/at.allow ] || _ok=0
[ -f /etc/at.allow ] && sec_audit_assert_path_access /etc/at.allow 600 root root || _ok=0
if [ "${_ok:-0}" -eq 1 ]; then
    sec_audit_report_pass 812 "at restricted (/etc/at.allow, no at.deny)"
else
    sec_audit_report_fail 812 "at access not restricted correctly"
fi

# RULE113:
if sec_audit_assert_path_access /etc/passwd 644 root root; then
    sec_audit_report_pass 106 "/etc/passwd mode 644 root:root"
else
    sec_audit_report_fail 106 "/etc/passwd permissions (expected 644 root:root, got $(sec_audit_path_mode_octal /etc/passwd 2>/dev/null))"
fi

# RULE117:
if sec_audit_assert_path_access /etc/group 644 root root; then
    sec_audit_report_pass 108 "/etc/group mode 644 root:root"
else
    sec_audit_report_fail 108 "/etc/group permissions (expected 644 root:root, got $(sec_audit_path_mode_octal /etc/group 2>/dev/null))"
fi

# RULE123:
if sec_audit_assert_path_access /etc/shadow- 000 root root; then
    sec_audit_report_pass 111 "/etc/shadow- mode 000 root:root"
else
    sec_audit_report_fail 111 "/etc/shadow- permissions (expected 000 root:root, got $(sec_audit_path_mode_octal /etc/shadow- 2>/dev/null))"
fi

# RULE127:
if sec_audit_assert_path_access /etc/gshadow- 000 root root; then
    sec_audit_report_pass 113 "/etc/gshadow- mode 000 root:root"
else
    sec_audit_report_fail 113 "/etc/gshadow- permissions (expected 000 root:root, got $(sec_audit_path_mode_octal /etc/gshadow- 2>/dev/null))"
fi

# RULE129:
CRITICAL_PATHS="/bin /sbin /usr/bin /usr/sbin /etc /var /home"
if sec_audit_find_hit_timeout sec_audit_soft_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type f -perm -0002 -print; then
    sec_audit_report_fail 129 "incomplete_scan: world-writable file search timed out under critical paths"
elif sec_audit_find_hit_timeout sec_audit_soft_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type d -perm -0002 -print; then
    sec_audit_report_fail 129 "incomplete_scan: world-writable directory search timed out under critical paths"
else
    WW_FILES=$(sec_audit_soft_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type f -perm -0002 -print 2>/dev/null | wc -l)
    WW_DIRS=$(sec_audit_soft_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type d -perm -0002 -print 2>/dev/null | wc -l)
    if [ "${WW_FILES:-0}" -eq 0 ] && [ "${WW_DIRS:-0}" -eq 0 ]; then
        sec_audit_report_pass 129 "No critical world writable files or directories found"
    else
        sec_audit_report_fail 129 "Found potential world-writable items ($WW_FILES files, $WW_DIRS dirs)"
    fi
fi
# RULE130:
_c=$(sec_audit_find_nouser_count)
if [ "${_c:-0}" -eq 0 ]; then
    sec_audit_report_pass 115 "no unowned files or directories (count=0)"
else
    sec_audit_report_fail 115 "${_c} unowned files or directories exist"
fi

# RULE131:
_c=$(sec_audit_find_nogroup_count)
if [ "${_c:-0}" -eq 0 ]; then
    sec_audit_report_pass 1151 "no ungrouped files or directories (count=0)"
else
    sec_audit_report_fail 1151 "${_c} ungrouped files or directories exist"
fi

# RULE132:
_c=$(sec_audit_find_suid_count)
sec_audit_report_pass 116 "SUID audit complete (count=${_c:-0}; review list manually)"
# RULE133:
_c=$(sec_audit_find_sgid_count)
sec_audit_report_pass 117 "SGID audit complete (count=${_c:-0}; review list manually)"
# RULE134:
_bad=$(awk -F: '($2==""){print $1}' /etc/shadow)
if [ -z "$_bad" ]; then
    sec_audit_report_pass 118 "no empty password fields in /etc/shadow"
else
    sec_audit_report_fail 118 "accounts with empty passwords: $_bad"
fi

# RULE139:
if sec_audit_kmod_is_blocked usb-storage; then
    sec_audit_report_pass 165 "usb-storage module disabled"
else
    sec_audit_report_fail 165 "usb-storage not disabled"
fi

# RULE140:
if sec_audit_yum_gpgcheck_global_ok && ! sec_audit_yum_repo_gpgcheck0_enabled; then
    sec_audit_report_pass 166 "gpgcheck globally enabled"
else
    sec_audit_report_fail 166 "gpgcheck not globally enabled or repo has gpgcheck=0"
fi

# RULE142:
if ! rpm -qa 'xorg-x11-server*' 2>/dev/null | grep -q .; then
    sec_audit_report_pass 183 "X11 server components not installed"
else
    sec_audit_report_fail 183 "xorg-x11-server packages installed"
fi

# RULE143:
if sec_audit_pkg_is_installed audit && sec_audit_pkg_is_installed audit-libs; then
    sec_audit_report_pass 195 "audit and audit-libs installed"
else
    sec_audit_report_fail 195 "audit packages not installed"
fi

# RULE144:
_lim=""
if sec_audit_grub_kernel_lines | grep -qoE 'audit_backlog_limit=[0-9]+'; then
    _lim=$(sec_audit_grub_kernel_lines | grep -oE 'audit_backlog_limit=[0-9]+' | head -1 | cut -d= -f2)
fi
if [ -n "$_lim" ] && [ "$_lim" -ge 8192 ] 2>/dev/null; then
    sec_audit_report_pass 196 "audit_backlog_limit=${_lim} (>=8192)"
else
    sec_audit_report_fail 196 "audit_backlog_limit not >=8192 in grub kernel line"
fi

# RULE145:
if sec_audit_audit_rule_on_disk_and_loaded time-change || sec_audit_audit_rule_on_disk_and_loaded adjtimex; then
    sec_audit_report_pass 197 "time-change events collected (audit rules loaded)"
else
    sec_audit_report_fail 197 "time-change audit rules missing on disk or not loaded"
fi

# RULE146:
if sec_audit_audit_rule_on_disk_and_loaded identity || sec_audit_audit_rules_file_grep -qE 'name=(identity|usergroup)'; then
    sec_audit_report_pass 198 "identity/usergroup audit events configured"
else
    sec_audit_report_fail 198 "identity audit rules missing"
fi

# RULE147:
if sec_audit_audit_rules_file_grep -q perm_mod && sec_audit_auditctl_list_grep -q perm_mod; then
    sec_audit_report_pass 201 "perm_mod audit rules on disk and loaded"
else
    sec_audit_report_fail 201 "perm_mod audit rules incomplete"
fi

# RULE148:
if sec_audit_audit_rules_file_grep -q scope && sec_audit_auditctl_list_grep -q scope; then
    sec_audit_report_pass 203 "scope (sudoers) changes collected"
else
    sec_audit_report_fail 203 "scope audit rules missing"
fi

# RULE149:
if sec_audit_audit_rules_file_grep -q actions && sec_audit_auditctl_list_grep -q actions; then
    sec_audit_report_pass 149 "sudo actions collected"
else
    sec_audit_report_fail 149 "actions audit rules missing"
fi

# RULE150:
if sec_audit_audit_rules_file_grep -q modules && sec_audit_auditctl_list_grep -q modules; then
    sec_audit_report_pass 205 "kernel module load/unload collected"
else
    sec_audit_report_fail 205 "modules audit rules missing"
fi

# RULE151:
if sec_audit_pkg_is_installed rsyslog; then
    sec_audit_report_pass 206 "rsyslog installed"
else
    sec_audit_report_fail 206 "rsyslog not installed"
fi

# RULE163:
_bad=$(awk -F: '($2!="x"){print $1}' /etc/passwd)
if [ -z "$_bad" ]; then
    sec_audit_report_pass 227 "all accounts use shadowed passwords (x in passwd)"
else
    sec_audit_report_fail 227 "non-shadowed passwd entries: $_bad"
fi

# RULE172:
_ok=0
sec_audit_audit_rules_file_grep -qE 'utmp|wtmp|btmp' && sec_audit_auditctl_list_grep -qE 'utmp|wtmp|btmp' && _ok=1
if [ "${_ok:-0}" -eq 1 ]; then
    sec_audit_report_pass 245 "session initiation files audited"
else
    sec_audit_report_fail 245 "utmp/wtmp/btmp audit rules incomplete"
fi

# RULE173:
_ok=0
sec_audit_audit_rules_file_grep -qE 'lastlog|faillock|logins' && sec_audit_auditctl_list_grep -qE 'lastlog|faillock|logins' && _ok=1
if [ "${_ok:-0}" -eq 1 ]; then
    sec_audit_report_pass 246 "login/logout events audited"
else
    sec_audit_report_fail 246 "login audit rules incomplete"
fi

# RULE174:
if sec_audit_audit_rules_file_grep -q delete && sec_audit_auditctl_list_grep -q delete; then
    sec_audit_report_pass 247 "file deletion events audited"
else
    sec_audit_report_fail 247 "delete audit rules missing"
fi

# RULE202:
if sec_audit_pkg_is_absent ypbind; then
    sec_audit_report_pass 47 "ypbind not installed"
else
    sec_audit_report_fail 47 "ypbind client/server package installed"
fi

# RULE203:
if sec_audit_pkg_is_absent rsh; then
    sec_audit_report_pass 48 "rsh not installed"
else
    sec_audit_report_fail 48 "rsh client/server package installed"
fi

# RULE204:
if sec_audit_pkg_is_absent talk; then
    sec_audit_report_pass 49 "talk not installed"
else
    sec_audit_report_fail 49 "talk client/server package installed"
fi

# RULE205:
if sec_audit_pkg_is_absent telnet; then
    sec_audit_report_pass 50 "telnet not installed"
else
    sec_audit_report_fail 50 "telnet client/server package installed"
fi

# RULE206:
if sec_audit_pkg_is_absent openldap-clients; then
    sec_audit_report_pass 51 "openldap-clients not installed"
else
    sec_audit_report_fail 51 "openldap-clients client/server package installed"
fi

# RULE5:
if ! sec_audit_mount_is_dedicated /tmp; then
    sec_audit_report_fail 1191 "/tmp not mounted; cannot verify nodev"
elif sec_audit_mount_has_option /tmp nodev; then
    sec_audit_report_pass 1191 "nodev option set on /tmp partition"
else
    sec_audit_report_fail 1191 "nodev option not set on /tmp partition"
fi

# RULE6:
sec_audit_assert_service_unused 6 autofs "autofs services are not in use" "autofs services are installed and enabled or actively running" "autofs.service"
# RULE7:
if ! sec_audit_mount_is_dedicated /tmp; then
    sec_audit_report_fail 1193 "/tmp not mounted; cannot verify noexec"
elif sec_audit_mount_has_option /tmp noexec; then
    sec_audit_report_pass 1193 "noexec option set on /tmp partition"
else
    sec_audit_report_fail 1193 "noexec option not set on /tmp partition"
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
# RULE8:
if sec_audit_path_is_isolated_volume /var; then
    sec_audit_report_pass 121 "separate partition exists for /var"
else
    sec_audit_report_fail 121 "no separate partition for /var"
fi

# RULE10:
if sec_audit_path_is_isolated_volume /var/tmp; then
    if sec_audit_mount_is_persisted /var/tmp; then
        sec_audit_report_pass 10 "separate partition exists for /var/tmp"
    else
        sec_audit_report_fail 10 "dedicated mount for /var/tmp is runtime-only (missing fstab or systemd .mount persistence)"
    fi
else
    sec_audit_report_fail 10 "no compliant dedicated mount for /var/tmp"
fi
# RULE11:
if ! sec_audit_mount_is_dedicated /var/tmp; then
    sec_audit_report_fail 1212 "/var/tmp not mounted; cannot verify nosuid"
elif sec_audit_mount_has_option /var/tmp nosuid; then
    sec_audit_report_pass 1212 "nosuid option set on /var/tmp partition"
else
    sec_audit_report_fail 1212 "nosuid option not set on /var/tmp partition"
fi

# RULE12:
if ! sec_audit_mount_is_dedicated /var/tmp; then
    sec_audit_report_fail 1213 "/var/tmp not mounted; cannot verify noexec"
elif sec_audit_mount_has_option /var/tmp noexec; then
    sec_audit_report_pass 1213 "noexec option set on /var/tmp partition"
else
    sec_audit_report_fail 1213 "noexec option not set on /var/tmp partition"
fi

# RULE8:
if sec_audit_path_is_isolated_volume /var; then
    sec_audit_report_pass 122 "separate partition exists for /var"
else
    sec_audit_report_fail 122 "no separate partition for /var"
fi

# RULE8:
if sec_audit_path_is_isolated_volume /var; then
    sec_audit_report_pass 123 "separate partition exists for /var"
else
    sec_audit_report_fail 123 "no separate partition for /var"
fi

# RULE8:
if sec_audit_path_is_isolated_volume /var; then
    sec_audit_report_pass 124 "separate partition exists for /var"
else
    sec_audit_report_fail 124 "no separate partition for /var"
fi

# RULE16:
if sec_audit_path_is_isolated_volume /home; then
    if sec_audit_mount_is_persisted /home; then
        sec_audit_report_pass 16 "separate partition exists for /home"
    else
        sec_audit_report_fail 16 "dedicated mount for /home is runtime-only (missing fstab or systemd .mount persistence)"
    fi
else
    sec_audit_report_fail 16 "no compliant dedicated mount for /home"
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
if ! sec_audit_mount_is_dedicated /dev/shm; then
    sec_audit_report_fail 126 "/dev/shm not mounted; cannot verify nosuid"
elif sec_audit_mount_has_option /dev/shm nosuid; then
    sec_audit_report_pass 126 "nosuid option set on /dev/shm partition"
else
    sec_audit_report_fail 126 "nosuid option not set on /dev/shm partition"
fi

# RULE19:
if ! sec_audit_mount_is_dedicated /dev/shm; then
    sec_audit_report_fail 1261 "/dev/shm not mounted; cannot verify noexec"
elif sec_audit_mount_has_option /dev/shm noexec; then
    sec_audit_report_pass 1261 "noexec option set on /dev/shm partition"
else
    sec_audit_report_fail 1261 "noexec option not set on /dev/shm partition"
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
if [ "${_fail50:-0}" -eq 0 ]; then
    sec_audit_report_pass 24 "access to bootloader config is configured"
else
    sec_audit_report_fail 24 "/boot/grub2/grub.cfg (or EFI grub.cfg) owner/mode is not root:root with mode 600"
fi
# RULE26:
if sec_audit_grub_cfg_matches '^[[:space:]]*set superusers' && sec_audit_grub_cfg_matches 'password_pbkdf2'; then
    sec_audit_report_pass 26 "bootloader password is set (grub.cfg under /boot/grub2 or EFI)"
else
    sec_audit_report_fail 26 "GRUB bootloader superuser/password_pbkdf2 is not configured as required in grub.cfg"
fi
# RULE26:
_g=$(sec_audit_grub_conf_path)
if [ -n "$_g" ] && grep -qE '^[[:space:]]*password[[:space:]]' "$_g" 2>/dev/null && grep -qiE 'superuser' "$_g" 2>/dev/null; then
    sec_audit_report_pass 12111 "grub superuser/password configured"
else
    sec_audit_report_fail 12111 "grub superuser or password not configured"
fi

# RULE27:
_ok=1
grep -qE '^[[:space:]]*\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0' /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null || _ok=0
sec_audit_sysctl_runtime_equals fs.suid_dumpable 0 || _ok=0
if [ "${_ok:-0}" -eq 1 ]; then
    sec_audit_report_pass 14 "core dumps restricted (limits and fs.suid_dumpable=0)"
else
    sec_audit_report_fail 14 "core dump restrictions incomplete"
fi

# RULE28:
_nx=0
if grep -qE '(pae|nx)' /proc/cpuinfo 2>/dev/null; then _nx=1; fi
if grep -q 'noexec[0-9]*=off' /proc/cmdline 2>/dev/null; then _nx=0; fi
if [ "${_nx:-0}" -eq 1 ]; then
    sec_audit_report_pass 15 "XD/NX (PAE) support appears enabled"
else
    sec_audit_report_fail 15 "XD/NX support not detected or disabled in kernel cmdline"
fi

# RULE29:
if sec_audit_sysctl_runtime_equals kernel.randomize_va_space 2; then
    sec_audit_report_pass 16 "ASLR enabled (kernel.randomize_va_space=2)"
else
    sec_audit_report_fail 16 "kernel.randomize_va_space is not 2"
fi

# RULE30:
if sec_audit_pkg_is_absent prelink; then
    sec_audit_report_pass 17 "prelink is not installed"
else
    sec_audit_report_fail 17 "prelink package is installed"
fi

# RULE31:
if sec_audit_grub_kernel_lines | grep -qE '(selinux=0|enforcing=0)'; then
    sec_audit_report_fail 18 "SELinux disabled in bootloader kernel line"
else
    sec_audit_report_pass 18 "SELinux not disabled in bootloader configuration"
fi

# RULE219:
_ge46=$(getenforce 2>/dev/null || true)
_cfg46=$(grep -Pi '^\h*SELINUX=\K\w+' /etc/selinux/config 2>/dev/null | head -n1 || true)
if [[ "$_ge46" != "Enforcing" ]]; then
    sec_audit_report_fail 219 "getenforce is '${_ge46:-unknown}', expected Enforcing"
elif [[ "$_cfg46" != "enforcing" ]]; then
    sec_audit_report_fail 219 "runtime Enforcing but /etc/selinux/config SELINUX=${_cfg46:-unset} (will revert after reboot)"
else
    sec_audit_report_pass 219 "the SELinux mode is enforcing (runtime and config)"
fi
# RULE32:
_t=""
[ -f /etc/selinux/config ] && _t=$(grep -E '^[[:space:]]*SELINUXTYPE=' /etc/selinux/config | tail -1 | awk -F= '{print $2}' | tr -d ' ')
case "$_t" in targeted|mls)
    sec_audit_report_pass 20 "SELINUXTYPE=${_t}"
    ;;
*)
    sec_audit_report_fail 20 "SELINUXTYPE not targeted or mls (got: ${_t:-unset})"
    ;;
esac

# RULE33:
if sec_audit_pkg_is_absent setroubleshoot; then
    sec_audit_report_pass 21 "setroubleshoot is not installed"
else
    sec_audit_report_fail 21 "setroubleshoot package is installed"
fi

# RULE34:
if sec_audit_pkg_is_absent mcstrans; then
    sec_audit_report_pass 22 "mcstrans is not installed"
else
    sec_audit_report_fail 22 "mcstrans package is installed"
fi

# RULE35:
if sec_audit_pkg_is_installed libselinux; then
    sec_audit_report_pass 23 "libselinux is installed"
else
    sec_audit_report_fail 23 "libselinux is not installed"
fi

# RULE36:
if [ -s /etc/motd ] && ! sec_audit_banner_exposes_os /etc/motd; then
    sec_audit_report_pass 24 "motd banner configured without OS info tokens"
elif [ ! -s /etc/motd ]; then
    sec_audit_report_fail 24 "motd not configured"
else
    sec_audit_report_fail 24 "motd contains prohibited OS information tokens"
fi

# RULE37:
if [ -s /etc/issue ] && ! sec_audit_banner_exposes_os /etc/issue; then
    sec_audit_report_pass 25 "issue banner configured without OS info tokens"
elif [ ! -s /etc/issue ]; then
    sec_audit_report_fail 25 "issue not configured"
else
    sec_audit_report_fail 25 "issue contains prohibited OS information tokens"
fi

# RULE38:
if [ -s /etc/issue.net ] && ! sec_audit_banner_exposes_os /etc/issue.net; then
    sec_audit_report_pass 26 "issue.net banner configured without OS info tokens"
elif [ ! -s /etc/issue.net ]; then
    sec_audit_report_fail 26 "issue.net not configured"
else
    sec_audit_report_fail 26 "issue.net contains prohibited OS information tokens"
fi

# RULE39:
if sec_audit_assert_path_access /etc/motd 644 root root; then
    sec_audit_report_pass 27 "permissions on /etc/motd are 644 root:root"
else
    sec_audit_report_fail 27 "/etc/motd permissions/owner (expected 644 root:root, got mode $(sec_audit_path_mode_octal /etc/motd 2>/dev/null) owner $(sec_audit_stat_uid_name /etc/motd 2>/dev/null))"
fi

# RULE40:
if sec_audit_assert_path_access /etc/issue 644 root root; then
    sec_audit_report_pass 271 "permissions on /etc/issue are 644 root:root"
else
    sec_audit_report_fail 271 "/etc/issue permissions/owner (expected 644 root:root, got mode $(sec_audit_path_mode_octal /etc/issue 2>/dev/null) owner $(sec_audit_stat_uid_name /etc/issue 2>/dev/null))"
fi

# RULE41:
if sec_audit_assert_path_access /etc/issue.net 644 root root; then
    sec_audit_report_pass 272 "permissions on /etc/issue.net are 644 root:root"
else
    sec_audit_report_fail 272 "/etc/issue.net permissions/owner (expected 644 root:root, got mode $(sec_audit_path_mode_octal /etc/issue.net 2>/dev/null) owner $(sec_audit_stat_uid_name /etc/issue.net 2>/dev/null))"
fi

# RULE43:
if sec_audit_pkg_is_absent xinetd; then
    sec_audit_report_pass 28 "xinetd is not installed"
else
    sec_audit_report_fail 28 "xinetd package is installed"
fi

# RULE51:
sec_audit_assert_service_unused 51 nfs-utils "network file system services are not in use" "network file system services are installed and enabled or actively running" "nfs-server.service"
# RULE195:
if sec_audit_pkg_is_absent vsftpd; then
    sec_audit_report_pass 37 "vsftpd not installed"
else
    sec_audit_report_fail 37 "vsftpd package installed"
fi

# RULE196:
if sec_audit_pkg_is_absent httpd; then
    sec_audit_report_pass 38 "httpd not installed"
else
    sec_audit_report_fail 38 "httpd package installed"
fi

# RULE197:
if sec_audit_pkg_is_absent dovecot; then
    sec_audit_report_pass 39 "dovecot not installed"
else
    sec_audit_report_fail 39 "dovecot package installed"
fi

# RULE198:
sec_audit_assert_service_unused 198 samba "samba file server services are not in use" "samba file server services are installed and enabled or actively running" "smb.service"
# RULE199:
if sec_audit_pkg_is_absent squid; then
    sec_audit_report_pass 41 "squid not installed"
else
    sec_audit_report_fail 41 "squid package installed"
fi

# RULE52:
sec_audit_assert_service_unused 52 net-snmp "snmp services are not in use" "snmp services are installed and enabled or actively running" "snmpd.service"
# RULE53:
_bad=""
if sec_audit_have_bin ss; then
    _bad=$(ss -lntu 2>/dev/null | grep -E ':25[[:space:]]' | grep -Ev '127\.0\.0\.1:25|::1:25' | head -3)
elif sec_audit_have_bin netstat; then
    _bad=$(netstat -lntu 2>/dev/null | grep -E ':25[[:space:]]' | grep -Ev '127\.0\.0\.1:25' | head -3)
fi
if [ -z "$_bad" ]; then
    sec_audit_report_pass 43 "MTA not listening on non-loopback port 25"
else
    sec_audit_report_fail 43 "MTA listening externally: $_bad"
fi

# RULE200:
if sec_audit_pkg_is_absent ypserv; then
    sec_audit_report_pass 44 "ypserv not installed"
else
    sec_audit_report_fail 44 "ypserv package installed"
fi

# RULE54:
sec_audit_assert_service_unused 54 telnet-server "telnet server services are not in use" "telnet server services are installed and enabled or actively running" "telnet.socket"
# RULE56:
if sec_audit_sysctl_files_have net.ipv4.ip_forward 0; then
    echo "RULE52.1= PASS: net.ipv4.ip_forward=0 in sysctl config"
else
    echo "RULE52.1= FAIL: net.ipv4.ip_forward not set to 0 on disk"
fi

# RULE62:
sec_audit_req_sysctl_runtime 62 net.ipv4.icmp_echo_ignore_broadcasts 1 "broadcast ICMP ignored"

# RULE63:
sec_audit_req_sysctl_runtime 63 net.ipv4.icmp_ignore_bogus_error_responses 1 "bogus ICMP responses ignored"

# RULE65:
sec_audit_req_sysctl_runtime 65 net.ipv4.tcp_syncookies 1 "TCP SYN cookies enabled"

# RULE67:
if sec_audit_kmod_is_blocked dccp; then
    sec_audit_report_pass 63 "DCCP module disabled"
else
    sec_audit_report_fail 63 "DCCP not disabled"
fi

# RULE68:
if sec_audit_kmod_is_blocked sctp; then
    sec_audit_report_pass 64 "SCTP module disabled"
else
    sec_audit_report_fail 64 "SCTP not disabled"
fi

# RULE74:
if grep -qiE '^[[:space:]]*admin_space_left_action[[:space:]]*=[[:space:]]*halt' /etc/audit/auditd.conf 2>/dev/null; then
    sec_audit_report_pass 67 "admin_space_left_action=halt"
else
    sec_audit_report_fail 67 "admin_space_left_action not halt"
fi

# RULE74:
if grep -qiE '^[[:space:]]*admin_space_left_action[[:space:]]*=[[:space:]]*halt' /etc/audit/auditd.conf 2>/dev/null; then
    sec_audit_report_pass 671 "admin_space_left_action=halt"
else
    sec_audit_report_fail 671 "admin_space_left_action not halt"
fi

# RULE90:
_v=$(sec_audit_sshd_config_value LogLevel | tr '[:upper:]' '[:lower:]')
case "$_v" in info|verbose|'')
    sec_audit_report_pass 84 "SSH LogLevel appropriate (${_v:-default})"
    ;;
*)
    sec_audit_report_fail 84 "SSH LogLevel is $_v (expected INFO or VERBOSE)"
    ;;
esac

# RULE91:
if sec_audit_sshd_config_effective_no X11Forwarding || sec_audit_sshd_config_value X11Forwarding | grep -qi '^no$'; then
    sec_audit_report_pass 85 "SSH X11Forwarding disabled"
else
    sec_audit_report_fail 85 "SSH X11Forwarding enabled"
fi

# RULE92:
_v=$(sec_audit_sshd_config_value MaxAuthTries)
[ -z "$_v" ] && _v=6
if [ "$_v" -le 4 ] 2>/dev/null; then
    sec_audit_report_pass 86 "MaxAuthTries=${_v}"
else
    sec_audit_report_fail 86 "MaxAuthTries=${_v} (expected 4 or less)"
fi

# RULE93:
if sec_audit_sshd_config_effective_yes IgnoreRhosts; then
    sec_audit_report_pass 87 "SSH IgnoreRhosts enabled"
else
    sec_audit_report_fail 87 "SSH IgnoreRhosts not yes"
fi

# RULE94:
if sec_audit_sshd_config_effective_no HostbasedAuthentication; then
    sec_audit_report_pass 88 "SSH HostbasedAuthentication disabled"
else
    sec_audit_report_fail 88 "SSH HostbasedAuthentication enabled"
fi

# RULE95:
if sec_audit_sshd_config_effective_no PermitRootLogin; then
    sec_audit_report_pass 89 "SSH root login disabled"
else
    sec_audit_report_fail 89 "SSH PermitRootLogin not disabled"
fi

# RULE96:
if sec_audit_sshd_config_effective_no PermitEmptyPasswords; then
    sec_audit_report_pass 90 "SSH PermitEmptyPasswords disabled"
else
    sec_audit_report_fail 90 "SSH PermitEmptyPasswords not disabled"
fi

# RULE97:
if sec_audit_sshd_config_effective_no PermitUserEnvironment; then
    sec_audit_report_pass 91 "SSH PermitUserEnvironment disabled"
else
    sec_audit_report_fail 91 "SSH PermitUserEnvironment not disabled"
fi

# RULE98:
_line=$(sec_audit_sshd_config_active_line MACs)
if [ -z "$_line" ]; then
    sec_audit_report_fail 92 "SSH MACs not set (weak defaults may apply)"
elif echo "$_line" | grep -qiE 'hmac-md5|hmac-sha1[^-]|umac-64@openssh'; then
    sec_audit_report_fail 92 "weak MAC algorithms in SSH config"
else
    sec_audit_report_pass 92 "SSH MACs exclude weak algorithms"
fi

# RULE100:
_v=$(sec_audit_sshd_config_value ClientAliveCountMax)
[ -z "$_v" ] && _v=3
if [ "$_v" -ge 1 ] && [ "$_v" -le 3 ] 2>/dev/null; then
    sec_audit_report_pass 931 "ClientAliveCountMax=${_v}"
else
    sec_audit_report_fail 931 "ClientAliveCountMax=${_v} (expected 1-3)"
fi

# RULE100:
_v=$(sec_audit_sshd_config_value ClientAliveCountMax)
[ -z "$_v" ] && _v=3
if [ "$_v" -ge 1 ] && [ "$_v" -le 3 ] 2>/dev/null; then
    sec_audit_report_pass 932 "ClientAliveCountMax=${_v}"
else
    sec_audit_report_fail 932 "ClientAliveCountMax=${_v} (expected 1-3)"
fi

# RULE101:
_v=$(sec_audit_sshd_config_value LoginGraceTime)
[ -z "$_v" ] && _v=120
if [ "$_v" -le 60 ] 2>/dev/null; then
    sec_audit_report_pass 94 "LoginGraceTime=${_v}"
else
    sec_audit_report_fail 94 "LoginGraceTime=${_v} (expected 60 or less)"
fi

# RULE102:
_v=$(sec_audit_sshd_config_value Banner)
if [ -n "$_v" ] && [ -f "$_v" ]; then
    sec_audit_report_pass 95 "SSH Banner configured (${_v})"
else
    sec_audit_report_fail 95 "SSH Banner not configured"
fi

# RULE103:
_ok=1
for _f in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
    [ -f "$_f" ] || continue
    grep -q pam_cracklib.so "$_f" 2>/dev/null || _ok=0
done
if [ "${_ok:-0}" -eq 1 ]; then
    echo "RULE96.1= PASS: pam_cracklib configured in PAM stacks"
else
    echo "RULE96.1= FAIL: pam_cracklib missing from system-auth/password-auth"
fi

# RULE103:
_ok=1
for _f in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
    [ -f "$_f" ] || continue
    grep -q pam_cracklib.so "$_f" 2>/dev/null || _ok=0
done
if [ "${_ok:-0}" -eq 1 ]; then
    echo "RULE96.2= PASS: pam_cracklib configured in PAM stacks"
else
    echo "RULE96.2= FAIL: pam_cracklib missing from system-auth/password-auth"
fi

# RULE105:
_ok=1
for _f in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
    [ -f "$_f" ] || continue
    grep -qE 'pam_unix\.so.*remember=' "$_f" 2>/dev/null || _ok=0
done
if [ "${_ok:-0}" -eq 1 ]; then
    echo "RULE96.4= PASS: password remember limit in PAM"
else
    echo "RULE96.4= FAIL: password reuse (remember) not configured in PAM"
fi

# RULE106:
_ok=1
for _f in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
    [ -f "$_f" ] || continue
    grep -qE 'pam_unix\.so.*sha512' "$_f" 2>/dev/null || _ok=0
done
if [ "${_ok:-0}" -eq 1 ]; then
    sec_audit_report_pass 971 "SHA-512 password hashing in PAM"
else
    sec_audit_report_fail 971 "pam_unix sha512 not set in PAM stacks"
fi

# RULE212:
_max=$(awk '/^PASS_MAX_DAYS/{print $2; exit}' /etc/login.defs)
[ -z "$_max" ] && _max=99999
if [ "$_max" -le 365 ] 2>/dev/null; then
    sec_audit_report_pass 98 "PASS_MAX_DAYS=${_max} (<=365)"
else
    sec_audit_report_fail 98 "PASS_MAX_DAYS=${_max} (expected <=365)"
fi

# RULE107:
_min=$(awk '/^PASS_MIN_DAYS/{print $2; exit}' /etc/login.defs)
[ -z "$_min" ] && _min=0
if [ "$_min" -ge 7 ] 2>/dev/null; then
    sec_audit_report_pass 99 "PASS_MIN_DAYS=${_min}"
else
    sec_audit_report_fail 99 "PASS_MIN_DAYS=${_min} (expected >=7)"
fi

# RULE108:
_w=$(awk '/^PASS_WARN_AGE/{print $2; exit}' /etc/login.defs)
[ -z "$_w" ] && _w=7
if [ "$_w" -ge 7 ] 2>/dev/null; then
    sec_audit_report_pass 100 "PASS_WARN_AGE=${_w}"
else
    sec_audit_report_fail 100 "PASS_WARN_AGE=${_w} (expected >=7)"
fi

# RULE213:
_inact=$(grep -i INACTIVE /etc/default/useradd 2>/dev/null | tail -1 | awk -F= '{print $2}' | tr -d ' ')
[ -z "$_inact" ] && _inact=$(useradd -D 2>/dev/null | grep INACTIVE | awk '{print $3}')
[ -z "$_inact" ] && _inact=-1
if [ "$_inact" != "-1" ] && [ "$_inact" -le 30 ] 2>/dev/null; then
    sec_audit_report_pass 101 "inactive password lock ${_inact} days"
else
    sec_audit_report_fail 101 "INACTIVE not <=30 days"
fi

# RULE110:
_gid=$(awk -F: '$1=="root"{print $4}' /etc/passwd)
if [ "${_gid:-1}" = "0" ]; then
    sec_audit_report_pass 103 "root default group GID 0"
else
    sec_audit_report_fail 103 "root GID is ${_gid} (expected 0)"
fi

# RULE111:
_bad=$(grep -rEv '^[[:space:]]*#|umask' /etc/profile /etc/bashrc /etc/profile.d/*.sh 2>/dev/null | grep -i umask | awk '{print $2}' | while read -r _u; do
    _o=$(printf '%o' $((8#${_u:-022} & 8#777)) 2>/dev/null)
    [ -n "$_o" ] && [ "$_o" -le 27 ] 2>/dev/null || echo bad
    done | grep -c bad)
if [ "${_bad:-0}" -eq 0 ]; then
    sec_audit_report_pass 1042 "default umask 027 or more restrictive"
else
    sec_audit_report_fail 1042 "umask not restrictive enough in profile"
fi

# RULE112:
_ok=0
for _f in /etc/bashrc /etc/profile /etc/profile.d/*.sh; do
    [ -f "$_f" ] || continue
    grep -qE 'TMOUT=([1-9]|[1-8][0-9]{1,2}|900)' "$_f" 2>/dev/null && grep -qE 'readonly[[:space:]]+TMOUT|export[[:space:]]+TMOUT' "$_f" 2>/dev/null && _ok=1
done
if [ "${_ok:-0}" -eq 1 ]; then
    sec_audit_report_pass 1051 "TMOUT configured (1-900) with readonly/export"
else
    sec_audit_report_fail 1051 "TMOUT not configured in shell profiles"
fi

# RULE1:
if sec_audit_kmod_is_blocked cramfs; then
    sec_audit_report_pass 1061 "mounting of cramfs filesystems is disabled"
else
    sec_audit_report_fail 1061 "cramfs module loaded or not disabled via modprobe"
fi

# RULE115:
if sec_audit_assert_path_access /etc/shadow 000 root root; then
    sec_audit_report_pass 107 "/etc/shadow mode 000 root:root"
else
    sec_audit_report_fail 107 "/etc/shadow permissions (expected 000 root:root, got $(sec_audit_path_mode_octal /etc/shadow 2>/dev/null))"
fi

# RULE1:
if sec_audit_kmod_is_blocked cramfs; then
    sec_audit_report_pass 1071 "mounting of cramfs filesystems is disabled"
else
    sec_audit_report_fail 1071 "cramfs module loaded or not disabled via modprobe"
fi

# RULE1:
if sec_audit_kmod_is_blocked cramfs; then
    sec_audit_report_pass 1081 "mounting of cramfs filesystems is disabled"
else
    sec_audit_report_fail 1081 "cramfs module loaded or not disabled via modprobe"
fi

# RULE119:
if sec_audit_assert_path_access /etc/gshadow 000 root root; then
    sec_audit_report_pass 109 "/etc/gshadow mode 000 root:root"
else
    sec_audit_report_fail 109 "/etc/gshadow permissions (expected 000 root:root, got $(sec_audit_path_mode_octal /etc/gshadow 2>/dev/null))"
fi

# RULE1:
if sec_audit_kmod_is_blocked cramfs; then
    sec_audit_report_pass 1091 "mounting of cramfs filesystems is disabled"
else
    sec_audit_report_fail 1091 "cramfs module loaded or not disabled via modprobe"
fi

# RULE121:
if sec_audit_assert_path_access /etc/passwd- 644 root root; then
    sec_audit_report_pass 110 "/etc/passwd- mode 644 root:root"
else
    sec_audit_report_fail 110 "/etc/passwd- permissions (expected 644 root:root, got $(sec_audit_path_mode_octal /etc/passwd- 2>/dev/null))"
fi

# RULE1:
if sec_audit_kmod_is_blocked cramfs; then
    sec_audit_report_pass 1101 "mounting of cramfs filesystems is disabled"
else
    sec_audit_report_fail 1101 "cramfs module loaded or not disabled via modprobe"
fi

# RULE1:
if sec_audit_kmod_is_blocked cramfs; then
    sec_audit_report_pass 1111 "mounting of cramfs filesystems is disabled"
else
    sec_audit_report_fail 1111 "cramfs module loaded or not disabled via modprobe"
fi

# RULE125:
if sec_audit_assert_path_access /etc/group- 644 root root; then
    sec_audit_report_pass 112 "/etc/group- mode 644 root:root"
else
    sec_audit_report_fail 112 "/etc/group- permissions (expected 644 root:root, got $(sec_audit_path_mode_octal /etc/group- 2>/dev/null))"
fi

# RULE1:
if sec_audit_kmod_is_blocked cramfs; then
    sec_audit_report_pass 1121 "mounting of cramfs filesystems is disabled"
else
    sec_audit_report_fail 1121 "cramfs module loaded or not disabled via modprobe"
fi

# RULE1:
if sec_audit_kmod_is_blocked cramfs; then
    sec_audit_report_pass 1131 "mounting of cramfs filesystems is disabled"
else
    sec_audit_report_fail 1131 "cramfs module loaded or not disabled via modprobe"
fi

# RULE156:
_bad=""
for _k in /etc/ssh/ssh_host_*_key.pub; do
    [ -f "$_k" ] || continue
    _m=$(sec_audit_path_mode_octal "$_k")
    [ "$_m" != "644" ] && [ "$_m" != "600" ] && _bad="$_bad $_k"
done
if [ -z "$_bad" ]; then
    sec_audit_report_pass 212 "SSH public host keys permissions OK"
else
    sec_audit_report_fail 212 "SSH public keys wrong mode:$_bad"
fi

# RULE157:
if grep -qiE '^[[:space:]]*(AllowUsers|AllowGroups|DenyUsers|DenyGroups)[[:space:]]' /etc/ssh/sshd_config 2>/dev/null; then
    sec_audit_report_pass 213 "SSH access limited via Allow/Deny directives"
else
    sec_audit_report_fail 213 "SSH access not limited (no Allow/Deny users/groups)"
fi

# RULE158:
_line=$(sec_audit_sshd_config_active_line Ciphers)
if [ -n "$_line" ] && ! echo "$_line" | grep -qiE '3des-cbc|aes128-cbc|aes256-cbc|arcfour|blowfish-cbc'; then
    sec_audit_report_pass 214 "SSH Ciphers exclude weak algorithms"
elif [ -z "$_line" ]; then
    sec_audit_report_fail 214 "Ciphers not set (weak defaults may apply)"
else
    sec_audit_report_fail 214 "weak Ciphers in sshd_config"
fi

# RULE159:
_line=$(sec_audit_sshd_config_active_line KexAlgorithms)
if [ -n "$_line" ] && ! echo "$_line" | grep -qiE 'diffie-hellman-group1-sha1|group14-sha1|group-exchange-sha1'; then
    sec_audit_report_pass 216 "SSH KexAlgorithms exclude weak DH"
elif [ -z "$_line" ]; then
    sec_audit_report_fail 216 "KexAlgorithms not set"
else
    sec_audit_report_fail 216 "weak KexAlgorithms present"
fi

# RULE160:
if sec_audit_sshd_config_effective_yes UsePAM; then
    sec_audit_report_pass 217 "SSH UsePAM enabled"
else
    sec_audit_report_fail 217 "SSH UsePAM not enabled"
fi

# RULE5:
if ! sec_audit_mount_is_dedicated /tmp; then
    sec_audit_report_fail 1191 "/tmp not mounted; cannot verify nodev"
elif sec_audit_mount_has_option /tmp nodev; then
    sec_audit_report_pass 1191 "nodev option set on /tmp partition"
else
    sec_audit_report_fail 1191 "nodev option not set on /tmp partition"
fi

# RULE6:
if ! sec_audit_mount_is_dedicated /tmp; then
    sec_audit_report_fail 1192 "/tmp not mounted; cannot verify nosuid"
elif sec_audit_mount_has_option /tmp nosuid; then
    sec_audit_report_pass 1192 "nosuid option set on /tmp partition"
else
    sec_audit_report_fail 1192 "nosuid option not set on /tmp partition"
fi

# RULE7:
if ! sec_audit_mount_is_dedicated /tmp; then
    sec_audit_report_fail 1193 "/tmp not mounted; cannot verify noexec"
elif sec_audit_mount_has_option /tmp noexec; then
    sec_audit_report_pass 1193 "noexec option set on /tmp partition"
else
    sec_audit_report_fail 1193 "noexec option not set on /tmp partition"
fi

# RULE8:
if sec_audit_path_is_isolated_volume /var; then
    sec_audit_report_pass 120 "separate partition exists for /var"
else
    sec_audit_report_fail 120 "no separate partition for /var"
fi

# RULE8:
if sec_audit_path_is_isolated_volume /var; then
    sec_audit_report_pass 121 "separate partition exists for /var"
else
    sec_audit_report_fail 121 "no separate partition for /var"
fi

# RULE10:
if ! sec_audit_mount_is_dedicated /var/tmp; then
    sec_audit_report_fail 1211 "/var/tmp not mounted; cannot verify nodev"
elif sec_audit_mount_has_option /var/tmp nodev; then
    sec_audit_report_pass 1211 "nodev option set on /var/tmp partition"
else
    sec_audit_report_fail 1211 "nodev option not set on /var/tmp partition"
fi

# RULE11:
if ! sec_audit_mount_is_dedicated /var/tmp; then
    sec_audit_report_fail 1212 "/var/tmp not mounted; cannot verify nosuid"
elif sec_audit_mount_has_option /var/tmp nosuid; then
    sec_audit_report_pass 1212 "nosuid option set on /var/tmp partition"
else
    sec_audit_report_fail 1212 "nosuid option not set on /var/tmp partition"
fi

# RULE12:
if ! sec_audit_mount_is_dedicated /var/tmp; then
    sec_audit_report_fail 1213 "/var/tmp not mounted; cannot verify noexec"
elif sec_audit_mount_has_option /var/tmp noexec; then
    sec_audit_report_pass 1213 "noexec option set on /var/tmp partition"
else
    sec_audit_report_fail 1213 "noexec option not set on /var/tmp partition"
fi

# RULE8:
if sec_audit_path_is_isolated_volume /var; then
    sec_audit_report_pass 122 "separate partition exists for /var"
else
    sec_audit_report_fail 122 "no separate partition for /var"
fi

# RULE8:
if sec_audit_path_is_isolated_volume /var; then
    sec_audit_report_pass 123 "separate partition exists for /var"
else
    sec_audit_report_fail 123 "no separate partition for /var"
fi

# RULE8:
if sec_audit_path_is_isolated_volume /var; then
    sec_audit_report_pass 124 "separate partition exists for /var"
else
    sec_audit_report_fail 124 "no separate partition for /var"
fi

# RULE16:
if ! sec_audit_mount_is_dedicated /home; then
    sec_audit_report_fail 1241 "/home not mounted; cannot verify nodev"
elif sec_audit_mount_has_option /home nodev; then
    sec_audit_report_pass 1241 "nodev option set on /home partition"
else
    sec_audit_report_fail 1241 "nodev option not set on /home partition"
fi

# RULE17:
if ! sec_audit_mount_is_dedicated /dev/shm; then
    sec_audit_report_fail 1242 "/dev/shm not mounted; cannot verify nodev"
elif sec_audit_mount_has_option /dev/shm nodev; then
    sec_audit_report_pass 1242 "nodev option set on /dev/shm partition"
else
    sec_audit_report_fail 1242 "nodev option not set on /dev/shm partition"
fi

# RULE18:
if ! sec_audit_mount_is_dedicated /dev/shm; then
    sec_audit_report_fail 126 "/dev/shm not mounted; cannot verify nosuid"
elif sec_audit_mount_has_option /dev/shm nosuid; then
    sec_audit_report_pass 126 "nosuid option set on /dev/shm partition"
else
    sec_audit_report_fail 126 "nosuid option not set on /dev/shm partition"
fi

# RULE19:
if ! sec_audit_mount_is_dedicated /dev/shm; then
    sec_audit_report_fail 1261 "/dev/shm not mounted; cannot verify noexec"
elif sec_audit_mount_has_option /dev/shm noexec; then
    sec_audit_report_pass 1261 "noexec option set on /dev/shm partition"
else
    sec_audit_report_fail 1261 "noexec option not set on /dev/shm partition"
fi

# RULE24:
_g=$(sec_audit_grub_conf_path)
if [ -n "$_g" ] && [ "$(sec_audit_path_mode_octal "$_g")" = "600" ] && [ "$(sec_audit_stat_uid_name "$_g")" = "root" ]; then
    sec_audit_report_pass 11 "bootloader config ${_g} mode 600 root"
else
    sec_audit_report_fail 11 "bootloader config permissions (expected 600 root:root on grub.conf)"
fi

# RULE26:
_g=$(sec_audit_grub_conf_path)
if [ -n "$_g" ] && grep -qE '^[[:space:]]*password[[:space:]]' "$_g" 2>/dev/null && grep -qiE 'superuser' "$_g" 2>/dev/null; then
    sec_audit_report_pass 12 "grub superuser/password configured"
else
    sec_audit_report_fail 12 "grub superuser or password not configured"
fi

# RULE26:
_g=$(sec_audit_grub_conf_path)
if [ -n "$_g" ] && grep -qE '^[[:space:]]*password[[:space:]]' "$_g" 2>/dev/null && grep -qiE 'superuser' "$_g" 2>/dev/null; then
    sec_audit_report_pass 12111 "grub superuser/password configured"
else
    sec_audit_report_fail 12111 "grub superuser or password not configured"
fi

# RULE27:
_ok=1
grep -qE '^[[:space:]]*\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0' /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null || _ok=0
sec_audit_sysctl_runtime_equals fs.suid_dumpable 0 || _ok=0
if [ "${_ok:-0}" -eq 1 ]; then
    sec_audit_report_pass 14 "core dumps restricted (limits and fs.suid_dumpable=0)"
else
    sec_audit_report_fail 14 "core dump restrictions incomplete"
fi

# RULE28:
_nx=0
if grep -qE '(pae|nx)' /proc/cpuinfo 2>/dev/null; then _nx=1; fi
if grep -q 'noexec[0-9]*=off' /proc/cmdline 2>/dev/null; then _nx=0; fi
if [ "${_nx:-0}" -eq 1 ]; then
    sec_audit_report_pass 15 "XD/NX (PAE) support appears enabled"
else
    sec_audit_report_fail 15 "XD/NX support not detected or disabled in kernel cmdline"
fi

# RULE29:
if sec_audit_sysctl_runtime_equals kernel.randomize_va_space 2; then
    sec_audit_report_pass 16 "ASLR enabled (kernel.randomize_va_space=2)"
else
    sec_audit_report_fail 16 "kernel.randomize_va_space is not 2"
fi

# RULE30:
if sec_audit_pkg_is_absent prelink; then
    sec_audit_report_pass 17 "prelink is not installed"
else
    sec_audit_report_fail 17 "prelink package is installed"
fi

# RULE31:
if sec_audit_grub_kernel_lines | grep -qE '(selinux=0|enforcing=0)'; then
    sec_audit_report_fail 18 "SELinux disabled in bootloader kernel line"
else
    sec_audit_report_pass 18 "SELinux not disabled in bootloader configuration"
fi

# RULE219:
_m=$(getenforce 2>/dev/null)
case "$_m" in
Enforcing|Permissive)
    sec_audit_report_pass 19 "SELinux mode ${_m}"
    ;;
*)
    sec_audit_report_fail 19 "SELinux not enforcing/permissive (${_m:-Disabled})"
    ;;
esac

# RULE32:
_t=""
[ -f /etc/selinux/config ] && _t=$(grep -E '^[[:space:]]*SELINUXTYPE=' /etc/selinux/config | tail -1 | awk -F= '{print $2}' | tr -d ' ')
case "$_t" in targeted|mls)
    sec_audit_report_pass 20 "SELINUXTYPE=${_t}"
    ;;
*)
    sec_audit_report_fail 20 "SELINUXTYPE not targeted or mls (got: ${_t:-unset})"
    ;;
esac

# RULE33:
if sec_audit_pkg_is_absent setroubleshoot; then
    sec_audit_report_pass 21 "setroubleshoot is not installed"
else
    sec_audit_report_fail 21 "setroubleshoot package is installed"
fi

# RULE34:
if sec_audit_pkg_is_absent mcstrans; then
    sec_audit_report_pass 22 "mcstrans is not installed"
else
    sec_audit_report_fail 22 "mcstrans package is installed"
fi

# RULE35:
if sec_audit_pkg_is_installed libselinux; then
    sec_audit_report_pass 23 "libselinux is installed"
else
    sec_audit_report_fail 23 "libselinux is not installed"
fi

# RULE36:
if [ -s /etc/motd ] && ! sec_audit_banner_exposes_os /etc/motd; then
    sec_audit_report_pass 24 "motd banner configured without OS info tokens"
elif [ ! -s /etc/motd ]; then
    sec_audit_report_fail 24 "motd not configured"
else
    sec_audit_report_fail 24 "motd contains prohibited OS information tokens"
fi

# RULE37:
if [ -s /etc/issue ] && ! sec_audit_banner_exposes_os /etc/issue; then
    sec_audit_report_pass 25 "issue banner configured without OS info tokens"
elif [ ! -s /etc/issue ]; then
    sec_audit_report_fail 25 "issue not configured"
else
    sec_audit_report_fail 25 "issue contains prohibited OS information tokens"
fi

# RULE38:
if [ -s /etc/issue.net ] && ! sec_audit_banner_exposes_os /etc/issue.net; then
    sec_audit_report_pass 26 "issue.net banner configured without OS info tokens"
elif [ ! -s /etc/issue.net ]; then
    sec_audit_report_fail 26 "issue.net not configured"
else
    sec_audit_report_fail 26 "issue.net contains prohibited OS information tokens"
fi

# RULE39:
if sec_audit_assert_path_access /etc/motd 644 root root; then
    sec_audit_report_pass 27 "permissions on /etc/motd are 644 root:root"
else
    sec_audit_report_fail 27 "/etc/motd permissions/owner (expected 644 root:root, got mode $(sec_audit_path_mode_octal /etc/motd 2>/dev/null) owner $(sec_audit_stat_uid_name /etc/motd 2>/dev/null))"
fi

# RULE40:
if sec_audit_assert_path_access /etc/issue 644 root root; then
    sec_audit_report_pass 271 "permissions on /etc/issue are 644 root:root"
else
    sec_audit_report_fail 271 "/etc/issue permissions/owner (expected 644 root:root, got mode $(sec_audit_path_mode_octal /etc/issue 2>/dev/null) owner $(sec_audit_stat_uid_name /etc/issue 2>/dev/null))"
fi

# RULE41:
if sec_audit_assert_path_access /etc/issue.net 644 root root; then
    sec_audit_report_pass 272 "permissions on /etc/issue.net are 644 root:root"
else
    sec_audit_report_fail 272 "/etc/issue.net permissions/owner (expected 644 root:root, got mode $(sec_audit_path_mode_octal /etc/issue.net 2>/dev/null) owner $(sec_audit_stat_uid_name /etc/issue.net 2>/dev/null))"
fi

# RULE43:
if sec_audit_pkg_is_absent xinetd; then
    sec_audit_report_pass 28 "xinetd is not installed"
else
    sec_audit_report_fail 28 "xinetd package is installed"
fi

# RULE51:
if sec_audit_pkg_is_absent nfs-utils; then
    sec_audit_report_pass 36 "nfs-utils not installed"
elif sec_audit_systemctl_is_masked nfs; then
    sec_audit_report_pass 36 "nfs-utils present but nfs service disabled"
else
    sec_audit_report_fail 36 "nfs service enabled"
fi

# RULE195:
if sec_audit_pkg_is_absent vsftpd; then
    sec_audit_report_pass 37 "vsftpd not installed"
else
    sec_audit_report_fail 37 "vsftpd package installed"
fi

# RULE196:
if sec_audit_pkg_is_absent httpd; then
    sec_audit_report_pass 38 "httpd not installed"
else
    sec_audit_report_fail 38 "httpd package installed"
fi

# RULE197:
if sec_audit_pkg_is_absent dovecot; then
    sec_audit_report_pass 39 "dovecot not installed"
else
    sec_audit_report_fail 39 "dovecot package installed"
fi

# RULE198:
if sec_audit_pkg_is_absent samba; then
    sec_audit_report_pass 40 "samba not installed"
else
    sec_audit_report_fail 40 "samba package installed"
fi

# RULE199:
if sec_audit_pkg_is_absent squid; then
    sec_audit_report_pass 41 "squid not installed"
else
    sec_audit_report_fail 41 "squid package installed"
fi

# RULE52:
if sec_audit_pkg_is_absent net-snmp; then
    sec_audit_report_pass 42 "net-snmp not installed"
else
    sec_audit_report_fail 42 "net-snmp package installed"
fi

# RULE53:
_bad=""
if sec_audit_have_bin ss; then
    _bad=$(ss -lntu 2>/dev/null | grep -E ':25[[:space:]]' | grep -Ev '127\.0\.0\.1:25|::1:25' | head -3 | xargs)
elif sec_audit_have_bin netstat; then
    _bad=$(netstat -lntu 2>/dev/null | grep -E ':25[[:space:]]' | grep -Ev '127\.0\.0\.1:25' | head -3)
fi
if [ -z "$_bad" ]; then
    sec_audit_report_pass 43 "MTA not listening on non-loopback port 25"
else
    sec_audit_report_fail 43 "MTA listening externally: $_bad"
fi

# RULE200:
if sec_audit_pkg_is_absent ypserv; then
    sec_audit_report_pass 44 "ypserv not installed"
else
    sec_audit_report_fail 44 "ypserv package installed"
fi

# RULE54:
if sec_audit_pkg_is_absent telnet-server; then
    sec_audit_report_pass 45 "telnet-server not installed"
else
    sec_audit_report_fail 45 "telnet-server package installed"
fi

# RULE56:
if sec_audit_sysctl_files_have net.ipv4.ip_forward 0; then
    echo "RULE52.1= PASS: net.ipv4.ip_forward=0 in sysctl config"
else
    echo "RULE52.1= FAIL: net.ipv4.ip_forward not set to 0 on disk"
fi

# RULE62:
sec_audit_assert_sysctl_equals 62 net.ipv4.icmp_echo_ignore_broadcasts 1 "broadcast ICMP ignored"

# RULE63:
sec_audit_assert_sysctl_equals 63 net.ipv4.icmp_ignore_bogus_error_responses 1 "bogus ICMP responses ignored"

# RULE65:
sec_audit_assert_sysctl_equals 65 net.ipv4.tcp_syncookies 1 "TCP SYN cookies enabled"

# RULE67:
if sec_audit_kmod_is_blocked dccp; then
    sec_audit_report_pass 63 "DCCP module disabled"
else
    sec_audit_report_fail 63 "DCCP not disabled"
fi

# RULE68:
if sec_audit_kmod_is_blocked sctp; then
    sec_audit_report_pass 64 "SCTP module disabled"
else
    sec_audit_report_fail 64 "SCTP not disabled"
fi

# RULE74:
if grep -qiE '^[[:space:]]*admin_space_left_action[[:space:]]*=[[:space:]]*halt' /etc/audit/auditd.conf 2>/dev/null; then
    sec_audit_report_pass 67 "admin_space_left_action=halt"
else
    sec_audit_report_fail 67 "admin_space_left_action not halt"
fi

# RULE74:
if grep -qiE '^[[:space:]]*admin_space_left_action[[:space:]]*=[[:space:]]*halt' /etc/audit/auditd.conf 2>/dev/null; then
    sec_audit_report_pass 671 "admin_space_left_action=halt"
else
    sec_audit_report_fail 671 "admin_space_left_action not halt"
fi

# RULE90:
_v=$(sec_audit_sshd_config_value LogLevel | tr '[:upper:]' '[:lower:]')
case "$_v" in info|verbose|'')
    sec_audit_report_pass 84 "SSH LogLevel appropriate (${_v:-default})"
    ;;
*)
    sec_audit_report_fail 84 "SSH LogLevel is $_v (expected INFO or VERBOSE)"
    ;;
esac

# RULE91:
if sec_audit_sshd_config_effective_no X11Forwarding || sec_audit_sshd_config_value X11Forwarding | grep -qi '^no$'; then
    sec_audit_report_pass 85 "SSH X11Forwarding disabled"
else
    sec_audit_report_fail 85 "SSH X11Forwarding enabled"
fi

# RULE92:
_v=$(sec_audit_sshd_config_value MaxAuthTries)
[ -z "$_v" ] && _v=6
if [ "$_v" -le 4 ] 2>/dev/null; then
    sec_audit_report_pass 86 "MaxAuthTries=${_v}"
else
    sec_audit_report_fail 86 "MaxAuthTries=${_v} (expected 4 or less)"
fi

# RULE93:
if sec_audit_sshd_config_effective_yes IgnoreRhosts; then
    sec_audit_report_pass 87 "SSH IgnoreRhosts enabled"
else
    sec_audit_report_fail 87 "SSH IgnoreRhosts not yes"
fi

# RULE94:
if sec_audit_sshd_config_effective_no HostbasedAuthentication; then
    sec_audit_report_pass 88 "SSH HostbasedAuthentication disabled"
else
    sec_audit_report_fail 88 "SSH HostbasedAuthentication enabled"
fi

# RULE95:
if sec_audit_sshd_config_effective_no PermitRootLogin; then
    sec_audit_report_pass 89 "SSH root login disabled"
else
    sec_audit_report_fail 89 "SSH PermitRootLogin not disabled"
fi

# RULE96:
if sec_audit_sshd_config_effective_no PermitEmptyPasswords; then
    sec_audit_report_pass 90 "SSH PermitEmptyPasswords disabled"
else
    sec_audit_report_fail 90 "SSH PermitEmptyPasswords not disabled"
fi

# RULE97:
if sec_audit_sshd_config_effective_no PermitUserEnvironment; then
    sec_audit_report_pass 91 "SSH PermitUserEnvironment disabled"
else
    sec_audit_report_fail 91 "SSH PermitUserEnvironment not disabled"
fi

# RULE98:
_line=$(sec_audit_sshd_config_active_line MACs)
if [ -z "$_line" ]; then
    sec_audit_report_fail 92 "SSH MACs not set (weak defaults may apply)"
elif echo "$_line" | grep -qiE 'hmac-md5|hmac-sha1[^-]|umac-64@openssh'; then
    sec_audit_report_fail 92 "weak MAC algorithms in SSH config"
else
    sec_audit_report_pass 92 "SSH MACs exclude weak algorithms"
fi

# RULE100:
_v=$(sec_audit_sshd_config_value ClientAliveCountMax)
[ -z "$_v" ] && _v=3
if [ "$_v" -ge 1 ] && [ "$_v" -le 3 ] 2>/dev/null; then
    sec_audit_report_pass 931 "ClientAliveCountMax=${_v}"
else
    sec_audit_report_fail 931 "ClientAliveCountMax=${_v} (expected 1-3)"
fi

# RULE100:
_v=$(sec_audit_sshd_config_value ClientAliveCountMax)
[ -z "$_v" ] && _v=3
if [ "$_v" -ge 1 ] && [ "$_v" -le 3 ] 2>/dev/null; then
    sec_audit_report_pass 932 "ClientAliveCountMax=${_v}"
else
    sec_audit_report_fail 932 "ClientAliveCountMax=${_v} (expected 1-3)"
fi

# RULE101:
_v=$(sec_audit_sshd_config_value LoginGraceTime)
[ -z "$_v" ] && _v=120
if [ "$_v" -le 60 ] 2>/dev/null; then
    sec_audit_report_pass 94 "LoginGraceTime=${_v}"
else
    sec_audit_report_fail 94 "LoginGraceTime=${_v} (expected 60 or less)"
fi

# RULE102:
_v=$(sec_audit_sshd_config_value Banner)
if [ -n "$_v" ] && [ -f "$_v" ]; then
    sec_audit_report_pass 95 "SSH Banner configured (${_v})"
else
    sec_audit_report_fail 95 "SSH Banner not configured"
fi

# RULE103:
_ok=1
for _f in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
    [ -f "$_f" ] || continue
    grep -q pam_cracklib.so "$_f" 2>/dev/null || _ok=0
done
if [ "${_ok:-0}" -eq 1 ]; then
    echo "RULE96.1= PASS: pam_cracklib configured in PAM stacks"
else
    echo "RULE96.1= FAIL: pam_cracklib missing from system-auth/password-auth"
fi

# RULE103:
_ok=1
for _f in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
    [ -f "$_f" ] || continue
    grep -q pam_cracklib.so "$_f" 2>/dev/null || _ok=0
done
if [ "${_ok:-0}" -eq 1 ]; then
    echo "RULE96.2= PASS: pam_cracklib configured in PAM stacks"
else
    echo "RULE96.2= FAIL: pam_cracklib missing from system-auth/password-auth"
fi

# RULE105:
_ok=1
for _f in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
    [ -f "$_f" ] || continue
    grep -qE 'pam_unix\.so.*remember=' "$_f" 2>/dev/null || _ok=0
done
if [ "${_ok:-0}" -eq 1 ]; then
    echo "RULE96.4= PASS: password remember limit in PAM"
else
    echo "RULE96.4= FAIL: password reuse (remember) not configured in PAM"
fi

# RULE106:
_ok=1
for _f in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
    [ -f "$_f" ] || continue
    grep -qE 'pam_unix\.so.*sha512' "$_f" 2>/dev/null || _ok=0
done
if [ "${_ok:-0}" -eq 1 ]; then
    sec_audit_report_pass 971 "SHA-512 password hashing in PAM"
else
    sec_audit_report_fail 971 "pam_unix sha512 not set in PAM stacks"
fi

# RULE212:
_max=$(awk '/^PASS_MAX_DAYS/{print $2; exit}' /etc/login.defs)
[ -z "$_max" ] && _max=99999
if [ "$_max" -le 365 ] 2>/dev/null; then
    sec_audit_report_pass 98 "PASS_MAX_DAYS=${_max} (<=365)"
else
    sec_audit_report_fail 98 "PASS_MAX_DAYS=${_max} (expected <=365)"
fi

# RULE107:
_min=$(awk '/^PASS_MIN_DAYS/{print $2; exit}' /etc/login.defs)
[ -z "$_min" ] && _min=0
if [ "$_min" -ge 7 ] 2>/dev/null; then
    sec_audit_report_pass 99 "PASS_MIN_DAYS=${_min}"
else
    sec_audit_report_fail 99 "PASS_MIN_DAYS=${_min} (expected >=7)"
fi

# RULE108:
_w=$(awk '/^PASS_WARN_AGE/{print $2; exit}' /etc/login.defs)
[ -z "$_w" ] && _w=7
if [ "$_w" -ge 7 ] 2>/dev/null; then
    sec_audit_report_pass 100 "PASS_WARN_AGE=${_w}"
else
    sec_audit_report_fail 100 "PASS_WARN_AGE=${_w} (expected >=7)"
fi

# RULE213:
_inact=$(grep -i INACTIVE /etc/default/useradd 2>/dev/null | tail -1 | awk -F= '{print $2}' | tr -d ' ')
[ -z "$_inact" ] && _inact=$(useradd -D 2>/dev/null | grep INACTIVE | awk '{print $3}')
[ -z "$_inact" ] && _inact=-1
if [ "$_inact" != "-1" ] && [ "$_inact" -le 30 ] 2>/dev/null; then
    sec_audit_report_pass 101 "inactive password lock ${_inact} days"
else
    sec_audit_report_fail 101 "INACTIVE not <=30 days"
fi

# RULE110:
_gid=$(awk -F: '$1=="root"{print $4}' /etc/passwd)
if [ "${_gid:-1}" = "0" ]; then
    sec_audit_report_pass 103 "root default group GID 0"
else
    sec_audit_report_fail 103 "root GID is ${_gid} (expected 0)"
fi

# RULE111:
_bad=$(grep -rEv '^[[:space:]]*#|umask' /etc/profile /etc/bashrc /etc/profile.d/*.sh 2>/dev/null | grep -i umask | awk '{print $2}' | while read -r _u; do
    _o=$(printf '%o' $((8#${_u:-022} & 8#777)) 2>/dev/null)
    [ -n "$_o" ] && [ "$_o" -le 27 ] 2>/dev/null || echo bad
    done | grep -c bad)
if [ "${_bad:-0}" -eq 0 ]; then
    sec_audit_report_pass 1042 "default umask 027 or more restrictive"
else
    sec_audit_report_fail 1042 "umask not restrictive enough in profile"
fi

# RULE112:
_ok=0
for _f in /etc/bashrc /etc/profile /etc/profile.d/*.sh; do
    [ -f "$_f" ] || continue
    grep -qE 'TMOUT=([1-9]|[1-8][0-9]{1,2}|900)' "$_f" 2>/dev/null && grep -qE 'readonly[[:space:]]+TMOUT|export[[:space:]]+TMOUT' "$_f" 2>/dev/null && _ok=1
done
if [ "${_ok:-0}" -eq 1 ]; then
    sec_audit_report_pass 1051 "TMOUT configured (1-900) with readonly/export"
else
    sec_audit_report_fail 1051 "TMOUT not configured in shell profiles"
fi

# RULE1:
if sec_audit_kmod_is_blocked cramfs; then
    sec_audit_report_pass 1061 "mounting of cramfs filesystems is disabled"
else
    sec_audit_report_fail 1061 "cramfs module loaded or not disabled via modprobe"
fi

# RULE115:
if sec_audit_assert_path_access /etc/shadow 000 root root; then
    sec_audit_report_pass 107 "/etc/shadow mode 000 root:root"
else
    sec_audit_report_fail 107 "/etc/shadow permissions (expected 000 root:root, got $(sec_audit_path_mode_octal /etc/shadow 2>/dev/null))"
fi

# RULE1:
if sec_audit_kmod_is_blocked cramfs; then
    sec_audit_report_pass 1071 "mounting of cramfs filesystems is disabled"
else
    sec_audit_report_fail 1071 "cramfs module loaded or not disabled via modprobe"
fi

# RULE1:
if sec_audit_kmod_is_blocked cramfs; then
    sec_audit_report_pass 1081 "mounting of cramfs filesystems is disabled"
else
    sec_audit_report_fail 1081 "cramfs module loaded or not disabled via modprobe"
fi

# RULE119:
if sec_audit_assert_path_access /etc/gshadow 000 root root; then
    sec_audit_report_pass 109 "/etc/gshadow mode 000 root:root"
else
    sec_audit_report_fail 109 "/etc/gshadow permissions (expected 000 root:root, got $(sec_audit_path_mode_octal /etc/gshadow 2>/dev/null))"
fi

# RULE1:
if sec_audit_kmod_is_blocked cramfs; then
    sec_audit_report_pass 1091 "mounting of cramfs filesystems is disabled"
else
    sec_audit_report_fail 1091 "cramfs module loaded or not disabled via modprobe"
fi

# RULE121:
if sec_audit_assert_path_access /etc/passwd- 644 root root; then
    sec_audit_report_pass 110 "/etc/passwd- mode 644 root:root"
else
    sec_audit_report_fail 110 "/etc/passwd- permissions (expected 644 root:root, got $(sec_audit_path_mode_octal /etc/passwd- 2>/dev/null))"
fi

# RULE1:
if sec_audit_kmod_is_blocked cramfs; then
    sec_audit_report_pass 1101 "mounting of cramfs filesystems is disabled"
else
    sec_audit_report_fail 1101 "cramfs module loaded or not disabled via modprobe"
fi

# RULE1:
if sec_audit_kmod_is_blocked cramfs; then
    sec_audit_report_pass 1111 "mounting of cramfs filesystems is disabled"
else
    sec_audit_report_fail 1111 "cramfs module loaded or not disabled via modprobe"
fi

# RULE125:
if sec_audit_assert_path_access /etc/group- 644 root root; then
    sec_audit_report_pass 112 "/etc/group- mode 644 root:root"
else
    sec_audit_report_fail 112 "/etc/group- permissions (expected 644 root:root, got $(sec_audit_path_mode_octal /etc/group- 2>/dev/null))"
fi

# RULE1:
if sec_audit_kmod_is_blocked cramfs; then
    sec_audit_report_pass 1121 "mounting of cramfs filesystems is disabled"
else
    sec_audit_report_fail 1121 "cramfs module loaded or not disabled via modprobe"
fi

# RULE1:
if sec_audit_kmod_is_blocked cramfs; then
    sec_audit_report_pass 1131 "mounting of cramfs filesystems is disabled"
else
    sec_audit_report_fail 1131 "cramfs module loaded or not disabled via modprobe"
fi

# RULE156:
_bad=""
for _k in /etc/ssh/ssh_host_*_key.pub; do
    [ -f "$_k" ] || continue
    _m=$(sec_audit_path_mode_octal "$_k")
    [ "$_m" != "644" ] && [ "$_m" != "600" ] && _bad="$_bad $_k"
done
if [ -z "$_bad" ]; then
    sec_audit_report_pass 212 "SSH public host keys permissions OK"
else
    sec_audit_report_fail 212 "SSH public keys wrong mode:$_bad"
fi

# RULE157:
if grep -qiE '^[[:space:]]*(AllowUsers|AllowGroups|DenyUsers|DenyGroups)[[:space:]]' /etc/ssh/sshd_config 2>/dev/null; then
    sec_audit_report_pass 213 "SSH access limited via Allow/Deny directives"
else
    sec_audit_report_fail 213 "SSH access not limited (no Allow/Deny users/groups)"
fi

# RULE158:
_line=$(sec_audit_sshd_config_active_line Ciphers)
if [ -n "$_line" ] && ! echo "$_line" | grep -qiE '3des-cbc|aes128-cbc|aes256-cbc|arcfour|blowfish-cbc'; then
    sec_audit_report_pass 214 "SSH Ciphers exclude weak algorithms"
elif [ -z "$_line" ]; then
    sec_audit_report_fail 214 "Ciphers not set (weak defaults may apply)"
else
    sec_audit_report_fail 214 "weak Ciphers in sshd_config"
fi

# RULE159:
_line=$(sec_audit_sshd_config_active_line KexAlgorithms)
if [ -n "$_line" ] && ! echo "$_line" | grep -qiE 'diffie-hellman-group1-sha1|group14-sha1|group-exchange-sha1'; then
    sec_audit_report_pass 216 "SSH KexAlgorithms exclude weak DH"
elif [ -z "$_line" ]; then
    sec_audit_report_fail 216 "KexAlgorithms not set"
else
    sec_audit_report_fail 216 "weak KexAlgorithms present"
fi

# RULE160:
if sec_audit_sshd_config_effective_yes UsePAM; then
    sec_audit_report_pass 217 "SSH UsePAM enabled"
else
    sec_audit_report_fail 217 "SSH UsePAM not enabled"
fi

# RULE5:
if ! sec_audit_mount_is_dedicated /tmp; then
    sec_audit_report_fail 1191 "/tmp not mounted; cannot verify nodev"
elif sec_audit_mount_has_option /tmp nodev; then
    sec_audit_report_pass 1191 "nodev option set on /tmp partition"
else
    sec_audit_report_fail 1191 "nodev option not set on /tmp partition"
fi

# RULE6:
if ! sec_audit_mount_is_dedicated /tmp; then
    sec_audit_report_fail 1192 "/tmp not mounted; cannot verify nosuid"
elif sec_audit_mount_has_option /tmp nosuid; then
    sec_audit_report_pass 1192 "nosuid option set on /tmp partition"
else
    sec_audit_report_fail 1192 "nosuid option not set on /tmp partition"
fi

# RULE7:
if ! sec_audit_mount_is_dedicated /tmp; then
    sec_audit_report_fail 1193 "/tmp not mounted; cannot verify noexec"
elif sec_audit_mount_has_option /tmp noexec; then
    sec_audit_report_pass 1193 "noexec option set on /tmp partition"
else
    sec_audit_report_fail 1193 "noexec option not set on /tmp partition"
fi

# RULE8:
if sec_audit_path_is_isolated_volume /var; then
    sec_audit_report_pass 120 "separate partition exists for /var"
else
    sec_audit_report_fail 120 "no separate partition for /var"
fi

# RULE8:
if sec_audit_path_is_isolated_volume /var; then
    sec_audit_report_pass 121 "separate partition exists for /var"
else
    sec_audit_report_fail 121 "no separate partition for /var"
fi

# RULE10:
if ! sec_audit_mount_is_dedicated /var/tmp; then
    sec_audit_report_fail 1211 "/var/tmp not mounted; cannot verify nodev"
elif sec_audit_mount_has_option /var/tmp nodev; then
    sec_audit_report_pass 1211 "nodev option set on /var/tmp partition"
else
    sec_audit_report_fail 1211 "nodev option not set on /var/tmp partition"
fi

# RULE11:
if ! sec_audit_mount_is_dedicated /var/tmp; then
    sec_audit_report_fail 1212 "/var/tmp not mounted; cannot verify nosuid"
elif sec_audit_mount_has_option /var/tmp nosuid; then
    sec_audit_report_pass 1212 "nosuid option set on /var/tmp partition"
else
    sec_audit_report_fail 1212 "nosuid option not set on /var/tmp partition"
fi

# RULE12:
if ! sec_audit_mount_is_dedicated /var/tmp; then
    sec_audit_report_fail 1213 "/var/tmp not mounted; cannot verify noexec"
elif sec_audit_mount_has_option /var/tmp noexec; then
    sec_audit_report_pass 1213 "noexec option set on /var/tmp partition"
else
    sec_audit_report_fail 1213 "noexec option not set on /var/tmp partition"
fi

# RULE8:
if sec_audit_path_is_isolated_volume /var; then
    sec_audit_report_pass 122 "separate partition exists for /var"
else
    sec_audit_report_fail 122 "no separate partition for /var"
fi

# RULE8:
if sec_audit_path_is_isolated_volume /var; then
    sec_audit_report_pass 123 "separate partition exists for /var"
else
    sec_audit_report_fail 123 "no separate partition for /var"
fi

# RULE8:
if sec_audit_path_is_isolated_volume /var; then
    sec_audit_report_pass 124 "separate partition exists for /var"
else
    sec_audit_report_fail 124 "no separate partition for /var"
fi

# RULE16:
if ! sec_audit_mount_is_dedicated /home; then
    sec_audit_report_fail 1241 "/home not mounted; cannot verify nodev"
elif sec_audit_mount_has_option /home nodev; then
    sec_audit_report_pass 1241 "nodev option set on /home partition"
else
    sec_audit_report_fail 1241 "nodev option not set on /home partition"
fi

# RULE17:
if ! sec_audit_mount_is_dedicated /dev/shm; then
    sec_audit_report_fail 1242 "/dev/shm not mounted; cannot verify nodev"
elif sec_audit_mount_has_option /dev/shm nodev; then
    sec_audit_report_pass 1242 "nodev option set on /dev/shm partition"
else
    sec_audit_report_fail 1242 "nodev option not set on /dev/shm partition"
fi

# RULE18:
if ! sec_audit_mount_is_dedicated /dev/shm; then
    sec_audit_report_fail 126 "/dev/shm not mounted; cannot verify nosuid"
elif sec_audit_mount_has_option /dev/shm nosuid; then
    sec_audit_report_pass 126 "nosuid option set on /dev/shm partition"
else
    sec_audit_report_fail 126 "nosuid option not set on /dev/shm partition"
fi

# RULE19:
if ! sec_audit_mount_is_dedicated /dev/shm; then
    sec_audit_report_fail 1261 "/dev/shm not mounted; cannot verify noexec"
elif sec_audit_mount_has_option /dev/shm noexec; then
    sec_audit_report_pass 1261 "noexec option set on /dev/shm partition"
else
    sec_audit_report_fail 1261 "noexec option not set on /dev/shm partition"
fi

# RULE24:
_g=$(sec_audit_grub_conf_path)
if [ -n "$_g" ] && [ "$(sec_audit_path_mode_octal "$_g")" = "600" ] && [ "$(sec_audit_stat_uid_name "$_g")" = "root" ]; then
    sec_audit_report_pass 11 "bootloader config ${_g} mode 600 root"
else
    sec_audit_report_fail 11 "bootloader config permissions (expected 600 root:root on grub.conf)"
fi

# RULE26:
_g=$(sec_audit_grub_conf_path)
if [ -n "$_g" ] && grep -qE '^[[:space:]]*password[[:space:]]' "$_g" 2>/dev/null && grep -qiE 'superuser' "$_g" 2>/dev/null; then
    sec_audit_report_pass 12 "grub superuser/password configured"
else
    sec_audit_report_fail 12 "grub superuser or password not configured"
fi

# RULE26:
_g=$(sec_audit_grub_conf_path)
if [ -n "$_g" ] && grep -qE '^[[:space:]]*password[[:space:]]' "$_g" 2>/dev/null && grep -qiE 'superuser' "$_g" 2>/dev/null; then
    sec_audit_report_pass 12111 "grub superuser/password configured"
else
    sec_audit_report_fail 12111 "grub superuser or password not configured"
fi

# RULE27:
_ok=1
grep -qE '^[[:space:]]*\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0' /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null || _ok=0
sec_audit_sysctl_runtime_equals fs.suid_dumpable 0 || _ok=0
if [ "${_ok:-0}" -eq 1 ]; then
    sec_audit_report_pass 14 "core dumps restricted (limits and fs.suid_dumpable=0)"
else
    sec_audit_report_fail 14 "core dump restrictions incomplete"
fi

# RULE28:
_nx=0
if grep -qE '(pae|nx)' /proc/cpuinfo 2>/dev/null; then _nx=1; fi
if grep -q 'noexec[0-9]*=off' /proc/cmdline 2>/dev/null; then _nx=0; fi
if [ "${_nx:-0}" -eq 1 ]; then
    sec_audit_report_pass 15 "XD/NX (PAE) support appears enabled"
else
    sec_audit_report_fail 15 "XD/NX support not detected or disabled in kernel cmdline"
fi

# RULE29:
if sec_audit_sysctl_runtime_equals kernel.randomize_va_space 2; then
    sec_audit_report_pass 16 "ASLR enabled (kernel.randomize_va_space=2)"
else
    sec_audit_report_fail 16 "kernel.randomize_va_space is not 2"
fi

# RULE30:
if sec_audit_pkg_is_absent prelink; then
    sec_audit_report_pass 17 "prelink is not installed"
else
    sec_audit_report_fail 17 "prelink package is installed"
fi

# RULE31:
if sec_audit_grub_kernel_lines | grep -qE '(selinux=0|enforcing=0)'; then
    sec_audit_report_fail 18 "SELinux disabled in bootloader kernel line"
else
    sec_audit_report_pass 18 "SELinux not disabled in bootloader configuration"
fi

# RULE219:
_m=$(getenforce 2>/dev/null)
case "$_m" in
Enforcing|Permissive)
    sec_audit_report_pass 19 "SELinux mode ${_m}"
    ;;
*)
    sec_audit_report_fail 19 "SELinux not enforcing/permissive (${_m:-Disabled})"
    ;;
esac

# RULE32:
_t=""
[ -f /etc/selinux/config ] && _t=$(grep -E '^[[:space:]]*SELINUXTYPE=' /etc/selinux/config | tail -1 | awk -F= '{print $2}' | tr -d ' ')
case "$_t" in targeted|mls)
    sec_audit_report_pass 20 "SELINUXTYPE=${_t}"
    ;;
*)
    sec_audit_report_fail 20 "SELINUXTYPE not targeted or mls (got: ${_t:-unset})"
    ;;
esac

# RULE33:
if sec_audit_pkg_is_absent setroubleshoot; then
    sec_audit_report_pass 21 "setroubleshoot is not installed"
else
    sec_audit_report_fail 21 "setroubleshoot package is installed"
fi

# RULE34:
if sec_audit_pkg_is_absent mcstrans; then
    sec_audit_report_pass 22 "mcstrans is not installed"
else
    sec_audit_report_fail 22 "mcstrans package is installed"
fi

# RULE35:
if sec_audit_pkg_is_installed libselinux; then
    sec_audit_report_pass 23 "libselinux is installed"
else
    sec_audit_report_fail 23 "libselinux is not installed"
fi

# RULE36:
if [ -s /etc/motd ] && ! sec_audit_banner_exposes_os /etc/motd; then
    sec_audit_report_pass 24 "motd banner configured without OS info tokens"
elif [ ! -s /etc/motd ]; then
    sec_audit_report_fail 24 "motd not configured"
else
    sec_audit_report_fail 24 "motd contains prohibited OS information tokens"
fi

# RULE37:
if [ -s /etc/issue ] && ! sec_audit_banner_exposes_os /etc/issue; then
    sec_audit_report_pass 25 "issue banner configured without OS info tokens"
elif [ ! -s /etc/issue ]; then
    sec_audit_report_fail 25 "issue not configured"
else
    sec_audit_report_fail 25 "issue contains prohibited OS information tokens"
fi

# RULE38:
if [ -s /etc/issue.net ] && ! sec_audit_banner_exposes_os /etc/issue.net; then
    sec_audit_report_pass 26 "issue.net banner configured without OS info tokens"
elif [ ! -s /etc/issue.net ]; then
    sec_audit_report_fail 26 "issue.net not configured"
else
    sec_audit_report_fail 26 "issue.net contains prohibited OS information tokens"
fi

# RULE39:
if sec_audit_assert_path_access /etc/motd 644 root root; then
    sec_audit_report_pass 27 "permissions on /etc/motd are 644 root:root"
else
    sec_audit_report_fail 27 "/etc/motd permissions/owner (expected 644 root:root, got mode $(sec_audit_path_mode_octal /etc/motd 2>/dev/null) owner $(sec_audit_stat_uid_name /etc/motd 2>/dev/null))"
fi

# RULE40:
if sec_audit_assert_path_access /etc/issue 644 root root; then
    sec_audit_report_pass 271 "permissions on /etc/issue are 644 root:root"
else
    sec_audit_report_fail 271 "/etc/issue permissions/owner (expected 644 root:root, got mode $(sec_audit_path_mode_octal /etc/issue 2>/dev/null) owner $(sec_audit_stat_uid_name /etc/issue 2>/dev/null))"
fi

# RULE41:
if sec_audit_assert_path_access /etc/issue.net 644 root root; then
    sec_audit_report_pass 272 "permissions on /etc/issue.net are 644 root:root"
else
    sec_audit_report_fail 272 "/etc/issue.net permissions/owner (expected 644 root:root, got mode $(sec_audit_path_mode_octal /etc/issue.net 2>/dev/null) owner $(sec_audit_stat_uid_name /etc/issue.net 2>/dev/null))"
fi

# RULE43:
if sec_audit_pkg_is_absent xinetd; then
    sec_audit_report_pass 28 "xinetd is not installed"
else
    sec_audit_report_fail 28 "xinetd package is installed"
fi

# RULE51:
if sec_audit_pkg_is_absent nfs-utils; then
    sec_audit_report_pass 36 "nfs-utils not installed"
elif sec_audit_systemctl_is_masked nfs; then
    sec_audit_report_pass 36 "nfs-utils present but nfs service disabled"
else
    sec_audit_report_fail 36 "nfs service enabled"
fi

# RULE195:
if sec_audit_pkg_is_absent vsftpd; then
    sec_audit_report_pass 37 "vsftpd not installed"
else
    sec_audit_report_fail 37 "vsftpd package installed"
fi

# RULE196:
if sec_audit_pkg_is_absent httpd; then
    sec_audit_report_pass 38 "httpd not installed"
else
    sec_audit_report_fail 38 "httpd package installed"
fi

# RULE197:
if sec_audit_pkg_is_absent dovecot; then
    sec_audit_report_pass 39 "dovecot not installed"
else
    sec_audit_report_fail 39 "dovecot package installed"
fi

# RULE198:
if sec_audit_pkg_is_absent samba; then
    sec_audit_report_pass 40 "samba not installed"
else
    sec_audit_report_fail 40 "samba package installed"
fi

# RULE199:
if sec_audit_pkg_is_absent squid; then
    sec_audit_report_pass 41 "squid not installed"
else
    sec_audit_report_fail 41 "squid package installed"
fi

# RULE52:
if sec_audit_pkg_is_absent net-snmp; then
    sec_audit_report_pass 42 "net-snmp not installed"
else
    sec_audit_report_fail 42 "net-snmp package installed"
fi

# RULE53:
_bad=""
if sec_audit_have_bin ss; then
    _bad=$(ss -lntu 2>/dev/null | grep -E ':25[[:space:]]' | grep -Ev '127\.0\.0\.1:25|::1:25' | head -3 | xargs)
elif sec_audit_have_bin netstat; then
    _bad=$(netstat -lntu 2>/dev/null | grep -E ':25[[:space:]]' | grep -Ev '127\.0\.0\.1:25' | head -3)
fi
if [ -z "$_bad" ]; then
    sec_audit_report_pass 43 "MTA not listening on non-loopback port 25"
else
    sec_audit_report_fail 43 "MTA listening externally: $_bad"
fi

# RULE200:
if sec_audit_pkg_is_absent ypserv; then
    sec_audit_report_pass 44 "ypserv not installed"
else
    sec_audit_report_fail 44 "ypserv package installed"
fi

# RULE54:
if sec_audit_pkg_is_absent telnet-server; then
    sec_audit_report_pass 45 "telnet-server not installed"
else
    sec_audit_report_fail 45 "telnet-server package installed"
fi

# RULE56:
if sec_audit_sysctl_files_have net.ipv4.ip_forward 0; then
    echo "RULE52.1= PASS: net.ipv4.ip_forward=0 in sysctl config"
else
    echo "RULE52.1= FAIL: net.ipv4.ip_forward not set to 0 on disk"
fi

# RULE62:
sec_audit_assert_sysctl_equals 62 net.ipv4.icmp_echo_ignore_broadcasts 1 "broadcast ICMP ignored"

# RULE63:
sec_audit_assert_sysctl_equals 63 net.ipv4.icmp_ignore_bogus_error_responses 1 "bogus ICMP responses ignored"

# RULE65:
sec_audit_assert_sysctl_equals 65 net.ipv4.tcp_syncookies 1 "TCP SYN cookies enabled"

# RULE67:
if sec_audit_kmod_is_blocked dccp; then
    sec_audit_report_pass 63 "DCCP module disabled"
else
    sec_audit_report_fail 63 "DCCP not disabled"
fi

# RULE68:
if sec_audit_kmod_is_blocked sctp; then
    sec_audit_report_pass 64 "SCTP module disabled"
else
    sec_audit_report_fail 64 "SCTP not disabled"
fi

# RULE74:
if grep -qiE '^[[:space:]]*admin_space_left_action[[:space:]]*=[[:space:]]*halt' /etc/audit/auditd.conf 2>/dev/null; then
    sec_audit_report_pass 67 "admin_space_left_action=halt"
else
    sec_audit_report_fail 67 "admin_space_left_action not halt"
fi

# RULE74:
if grep -qiE '^[[:space:]]*admin_space_left_action[[:space:]]*=[[:space:]]*halt' /etc/audit/auditd.conf 2>/dev/null; then
    sec_audit_report_pass 671 "admin_space_left_action=halt"
else
    sec_audit_report_fail 671 "admin_space_left_action not halt"
fi

# RULE90:
_v=$(sec_audit_sshd_config_value LogLevel | tr '[:upper:]' '[:lower:]')
case "$_v" in info|verbose|'')
    sec_audit_report_pass 84 "SSH LogLevel appropriate (${_v:-default})"
    ;;
*)
    sec_audit_report_fail 84 "SSH LogLevel is $_v (expected INFO or VERBOSE)"
    ;;
esac

# RULE91:
if sec_audit_sshd_config_effective_no X11Forwarding || sec_audit_sshd_config_value X11Forwarding | grep -qi '^no$'; then
    sec_audit_report_pass 85 "SSH X11Forwarding disabled"
else
    sec_audit_report_fail 85 "SSH X11Forwarding enabled"
fi

# RULE92:
_v=$(sec_audit_sshd_config_value MaxAuthTries)
[ -z "$_v" ] && _v=6
if [ "$_v" -le 4 ] 2>/dev/null; then
    sec_audit_report_pass 86 "MaxAuthTries=${_v}"
else
    sec_audit_report_fail 86 "MaxAuthTries=${_v} (expected 4 or less)"
fi

# RULE93:
if sec_audit_sshd_config_effective_yes IgnoreRhosts; then
    sec_audit_report_pass 87 "SSH IgnoreRhosts enabled"
else
    sec_audit_report_fail 87 "SSH IgnoreRhosts not yes"
fi

# RULE94:
if sec_audit_sshd_config_effective_no HostbasedAuthentication; then
    sec_audit_report_pass 88 "SSH HostbasedAuthentication disabled"
else
    sec_audit_report_fail 88 "SSH HostbasedAuthentication enabled"
fi

# RULE95:
if sec_audit_sshd_config_effective_no PermitRootLogin; then
    sec_audit_report_pass 89 "SSH root login disabled"
else
    sec_audit_report_fail 89 "SSH PermitRootLogin not disabled"
fi

# RULE96:
if sec_audit_sshd_config_effective_no PermitEmptyPasswords; then
    sec_audit_report_pass 90 "SSH PermitEmptyPasswords disabled"
else
    sec_audit_report_fail 90 "SSH PermitEmptyPasswords not disabled"
fi

# RULE97:
if sec_audit_sshd_config_effective_no PermitUserEnvironment; then
    sec_audit_report_pass 91 "SSH PermitUserEnvironment disabled"
else
    sec_audit_report_fail 91 "SSH PermitUserEnvironment not disabled"
fi

# RULE98:
_line=$(sec_audit_sshd_config_active_line MACs)
if [ -z "$_line" ]; then
    sec_audit_report_fail 92 "SSH MACs not set (weak defaults may apply)"
elif echo "$_line" | grep -qiE 'hmac-md5|hmac-sha1[^-]|umac-64@openssh'; then
    sec_audit_report_fail 92 "weak MAC algorithms in SSH config"
else
    sec_audit_report_pass 92 "SSH MACs exclude weak algorithms"
fi

# RULE100:
_v=$(sec_audit_sshd_config_value ClientAliveCountMax)
[ -z "$_v" ] && _v=3
if [ "$_v" -ge 1 ] && [ "$_v" -le 3 ] 2>/dev/null; then
    sec_audit_report_pass 931 "ClientAliveCountMax=${_v}"
else
    sec_audit_report_fail 931 "ClientAliveCountMax=${_v} (expected 1-3)"
fi

# RULE100:
_v=$(sec_audit_sshd_config_value ClientAliveCountMax)
[ -z "$_v" ] && _v=3
if [ "$_v" -ge 1 ] && [ "$_v" -le 3 ] 2>/dev/null; then
    sec_audit_report_pass 932 "ClientAliveCountMax=${_v}"
else
    sec_audit_report_fail 932 "ClientAliveCountMax=${_v} (expected 1-3)"
fi

# RULE101:
_v=$(sec_audit_sshd_config_value LoginGraceTime)
[ -z "$_v" ] && _v=120
if [ "$_v" -le 60 ] 2>/dev/null; then
    sec_audit_report_pass 94 "LoginGraceTime=${_v}"
else
    sec_audit_report_fail 94 "LoginGraceTime=${_v} (expected 60 or less)"
fi

# RULE102:
_v=$(sec_audit_sshd_config_value Banner)
if [ -n "$_v" ] && [ -f "$_v" ]; then
    sec_audit_report_pass 95 "SSH Banner configured (${_v})"
else
    sec_audit_report_fail 95 "SSH Banner not configured"
fi

# RULE103:
_ok=1
for _f in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
    [ -f "$_f" ] || continue
    grep -q pam_cracklib.so "$_f" 2>/dev/null || _ok=0
done
if [ "${_ok:-0}" -eq 1 ]; then
    echo "RULE96.1= PASS: pam_cracklib configured in PAM stacks"
else
    echo "RULE96.1= FAIL: pam_cracklib missing from system-auth/password-auth"
fi

# RULE103:
_ok=1
for _f in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
    [ -f "$_f" ] || continue
    grep -q pam_cracklib.so "$_f" 2>/dev/null || _ok=0
done
if [ "${_ok:-0}" -eq 1 ]; then
    echo "RULE96.2= PASS: pam_cracklib configured in PAM stacks"
else
    echo "RULE96.2= FAIL: pam_cracklib missing from system-auth/password-auth"
fi

# RULE105:
_ok=1
for _f in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
    [ -f "$_f" ] || continue
    grep -qE 'pam_unix\.so.*remember=' "$_f" 2>/dev/null || _ok=0
done
if [ "${_ok:-0}" -eq 1 ]; then
    echo "RULE96.4= PASS: password remember limit in PAM"
else
    echo "RULE96.4= FAIL: password reuse (remember) not configured in PAM"
fi

# RULE106:
_ok=1
for _f in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
    [ -f "$_f" ] || continue
    grep -qE 'pam_unix\.so.*sha512' "$_f" 2>/dev/null || _ok=0
done
if [ "${_ok:-0}" -eq 1 ]; then
    sec_audit_report_pass 971 "SHA-512 password hashing in PAM"
else
    sec_audit_report_fail 971 "pam_unix sha512 not set in PAM stacks"
fi

# RULE212:
_max=$(awk '/^PASS_MAX_DAYS/{print $2; exit}' /etc/login.defs)
[ -z "$_max" ] && _max=99999
if [ "$_max" -le 365 ] 2>/dev/null; then
    sec_audit_report_pass 98 "PASS_MAX_DAYS=${_max} (<=365)"
else
    sec_audit_report_fail 98 "PASS_MAX_DAYS=${_max} (expected <=365)"
fi

# RULE107:
_min=$(awk '/^PASS_MIN_DAYS/{print $2; exit}' /etc/login.defs)
[ -z "$_min" ] && _min=0
if [ "$_min" -ge 7 ] 2>/dev/null; then
    sec_audit_report_pass 99 "PASS_MIN_DAYS=${_min}"
else
    sec_audit_report_fail 99 "PASS_MIN_DAYS=${_min} (expected >=7)"
fi

# RULE108:
_w=$(awk '/^PASS_WARN_AGE/{print $2; exit}' /etc/login.defs)
[ -z "$_w" ] && _w=7
if [ "$_w" -ge 7 ] 2>/dev/null; then
    sec_audit_report_pass 100 "PASS_WARN_AGE=${_w}"
else
    sec_audit_report_fail 100 "PASS_WARN_AGE=${_w} (expected >=7)"
fi

# RULE213:
_inact=$(grep -i INACTIVE /etc/default/useradd 2>/dev/null | tail -1 | awk -F= '{print $2}' | tr -d ' ')
[ -z "$_inact" ] && _inact=$(useradd -D 2>/dev/null | grep INACTIVE | awk '{print $3}')
[ -z "$_inact" ] && _inact=-1
if [ "$_inact" != "-1" ] && [ "$_inact" -le 30 ] 2>/dev/null; then
    sec_audit_report_pass 101 "inactive password lock ${_inact} days"
else
    sec_audit_report_fail 101 "INACTIVE not <=30 days"
fi

# RULE110:
_gid=$(awk -F: '$1=="root"{print $4}' /etc/passwd)
if [ "${_gid:-1}" = "0" ]; then
    sec_audit_report_pass 103 "root default group GID 0"
else
    sec_audit_report_fail 103 "root GID is ${_gid} (expected 0)"
fi

# RULE111:
_bad=$(grep -rEv '^[[:space:]]*#|umask' /etc/profile /etc/bashrc /etc/profile.d/*.sh 2>/dev/null | grep -i umask | awk '{print $2}' | while read -r _u; do
    _o=$(printf '%o' $((8#${_u:-022} & 8#777)) 2>/dev/null)
    [ -n "$_o" ] && [ "$_o" -le 27 ] 2>/dev/null || echo bad
    done | grep -c bad)
if [ "${_bad:-0}" -eq 0 ]; then
    sec_audit_report_pass 1042 "default umask 027 or more restrictive"
else
    sec_audit_report_fail 1042 "umask not restrictive enough in profile"
fi

# RULE112:
_ok=0
for _f in /etc/bashrc /etc/profile /etc/profile.d/*.sh; do
    [ -f "$_f" ] || continue
    grep -qE 'TMOUT=([1-9]|[1-8][0-9]{1,2}|900)' "$_f" 2>/dev/null && grep -qE 'readonly[[:space:]]+TMOUT|export[[:space:]]+TMOUT' "$_f" 2>/dev/null && _ok=1
done
if [ "${_ok:-0}" -eq 1 ]; then
    sec_audit_report_pass 1051 "TMOUT configured (1-900) with readonly/export"
else
    sec_audit_report_fail 1051 "TMOUT not configured in shell profiles"
fi

# RULE1:
if sec_audit_kmod_is_blocked cramfs; then
    sec_audit_report_pass 1061 "mounting of cramfs filesystems is disabled"
else
    sec_audit_report_fail 1061 "cramfs module loaded or not disabled via modprobe"
fi

# RULE115:
if sec_audit_assert_path_access /etc/shadow 000 root root; then
    sec_audit_report_pass 107 "/etc/shadow mode 000 root:root"
else
    sec_audit_report_fail 107 "/etc/shadow permissions (expected 000 root:root, got $(sec_audit_path_mode_octal /etc/shadow 2>/dev/null))"
fi

# RULE1:
if sec_audit_kmod_is_blocked cramfs; then
    sec_audit_report_pass 1071 "mounting of cramfs filesystems is disabled"
else
    sec_audit_report_fail 1071 "cramfs module loaded or not disabled via modprobe"
fi

# RULE1:
if sec_audit_kmod_is_blocked cramfs; then
    sec_audit_report_pass 1081 "mounting of cramfs filesystems is disabled"
else
    sec_audit_report_fail 1081 "cramfs module loaded or not disabled via modprobe"
fi

# RULE119:
if sec_audit_assert_path_access /etc/gshadow 000 root root; then
    sec_audit_report_pass 109 "/etc/gshadow mode 000 root:root"
else
    sec_audit_report_fail 109 "/etc/gshadow permissions (expected 000 root:root, got $(sec_audit_path_mode_octal /etc/gshadow 2>/dev/null))"
fi

# RULE1:
if sec_audit_kmod_is_blocked cramfs; then
    sec_audit_report_pass 1091 "mounting of cramfs filesystems is disabled"
else
    sec_audit_report_fail 1091 "cramfs module loaded or not disabled via modprobe"
fi

# RULE121:
if sec_audit_assert_path_access /etc/passwd- 644 root root; then
    sec_audit_report_pass 110 "/etc/passwd- mode 644 root:root"
else
    sec_audit_report_fail 110 "/etc/passwd- permissions (expected 644 root:root, got $(sec_audit_path_mode_octal /etc/passwd- 2>/dev/null))"
fi

# RULE1:
if sec_audit_kmod_is_blocked cramfs; then
    sec_audit_report_pass 1101 "mounting of cramfs filesystems is disabled"
else
    sec_audit_report_fail 1101 "cramfs module loaded or not disabled via modprobe"
fi

# RULE1:
if sec_audit_kmod_is_blocked cramfs; then
    sec_audit_report_pass 1111 "mounting of cramfs filesystems is disabled"
else
    sec_audit_report_fail 1111 "cramfs module loaded or not disabled via modprobe"
fi

# RULE125:
if sec_audit_assert_path_access /etc/group- 644 root root; then
    sec_audit_report_pass 112 "/etc/group- mode 644 root:root"
else
    sec_audit_report_fail 112 "/etc/group- permissions (expected 644 root:root, got $(sec_audit_path_mode_octal /etc/group- 2>/dev/null))"
fi

# RULE1:
if sec_audit_kmod_is_blocked cramfs; then
    sec_audit_report_pass 1121 "mounting of cramfs filesystems is disabled"
else
    sec_audit_report_fail 1121 "cramfs module loaded or not disabled via modprobe"
fi

# RULE1:
if sec_audit_kmod_is_blocked cramfs; then
    sec_audit_report_pass 1131 "mounting of cramfs filesystems is disabled"
else
    sec_audit_report_fail 1131 "cramfs module loaded or not disabled via modprobe"
fi

# RULE156:
_bad=""
for _k in /etc/ssh/ssh_host_*_key.pub; do
    [ -f "$_k" ] || continue
    _m=$(sec_audit_path_mode_octal "$_k")
    [ "$_m" != "644" ] && [ "$_m" != "600" ] && _bad="$_bad $_k"
done
if [ -z "$_bad" ]; then
    sec_audit_report_pass 212 "SSH public host keys permissions OK"
else
    sec_audit_report_fail 212 "SSH public keys wrong mode:$_bad"
fi

# RULE157:
if grep -qiE '^[[:space:]]*(AllowUsers|AllowGroups|DenyUsers|DenyGroups)[[:space:]]' /etc/ssh/sshd_config 2>/dev/null; then
    sec_audit_report_pass 213 "SSH access limited via Allow/Deny directives"
else
    sec_audit_report_fail 213 "SSH access not limited (no Allow/Deny users/groups)"
fi

# RULE158:
_line=$(sec_audit_sshd_config_active_line Ciphers)
if [ -n "$_line" ] && ! echo "$_line" | grep -qiE '3des-cbc|aes128-cbc|aes256-cbc|arcfour|blowfish-cbc'; then
    sec_audit_report_pass 214 "SSH Ciphers exclude weak algorithms"
elif [ -z "$_line" ]; then
    sec_audit_report_fail 214 "Ciphers not set (weak defaults may apply)"
else
    sec_audit_report_fail 214 "weak Ciphers in sshd_config"
fi

# RULE159:
_line=$(sec_audit_sshd_config_active_line KexAlgorithms)
if [ -n "$_line" ] && ! echo "$_line" | grep -qiE 'diffie-hellman-group1-sha1|group14-sha1|group-exchange-sha1'; then
    sec_audit_report_pass 216 "SSH KexAlgorithms exclude weak DH"
elif [ -z "$_line" ]; then
    sec_audit_report_fail 216 "KexAlgorithms not set"
else
    sec_audit_report_fail 216 "weak KexAlgorithms present"
fi

# RULE160:
if sec_audit_sshd_config_effective_yes UsePAM; then
    sec_audit_report_pass 217 "SSH UsePAM enabled"
else
    sec_audit_report_fail 217 "SSH UsePAM not enabled"
fi

# RULE2:
if sec_audit_kmod_is_blocked squashfs; then
    sec_audit_report_pass 2 "mounting of squashfs filesystems is disabled"
else
    sec_audit_report_fail 2 "squashfs module loaded or not disabled via modprobe"
fi

# RULE3:
if sec_audit_kmod_is_blocked udf; then
    sec_audit_report_pass 3 "mounting of udf filesystems is disabled"
else
    sec_audit_report_fail 3 "udf module loaded or not disabled via modprobe"
fi

# RULE5:
_swc=$(sec_audit_find_sticky_world_writable_count)
if [ "${_swc:-0}" -eq 0 ]; then
    sec_audit_report_pass 5 "sticky bit set on all world-writable directories (count=0)"
else
    sec_audit_report_fail 5 "${_swc} world-writable directories without sticky bit"
fi

# RULE6:
if sec_audit_systemctl_is_masked autofs || ! systemctl list-unit-files 2>/dev/null | grep -q '^autofs.service'; then
    sec_audit_report_pass 6 "autofs disabled"
else
    sec_audit_report_fail 6 "autofs enabled ($(systemctl is-enabled autofs 2>/dev/null))"
fi

# RULE9:
if sec_audit_pkg_is_installed aide; then
    sec_audit_report_pass 9 "AIDE package is installed"
else
    sec_audit_report_fail 9 "AIDE package is not installed"
fi

# RULE4:
if sec_audit_kmod_is_blocked vfat; then
    sec_audit_report_pass 4 "vfat/fat/msdos mount modules disabled"
else
    sec_audit_report_fail 4 "vfat or related module not disabled"
fi

# RULE119-RULE126:
sec_audit_mp_out() { findmnt -kn -T "$1" -o TARGET,FSTYPE,OPTIONS --noheadings 2>/dev/null | head -1; }

for _sec_mp in /tmp /var /var/tmp /var/log /var/log/audit /home /dev/shm; do
    case "$_sec_mp" in
    /tmp) _rk=119 ;;
    /var) _rk=120 ;;
    /var/tmp) _rk=121 ;;
    /var/log) _rk=122 ;;
    /var/log/audit) _rk=123 ;;
    /home) _rk=124 ;;
    /dev/shm) _rk=126 ;;
    esac
    if sec_audit_path_is_isolated_volume "$_sec_mp" || { [ "$_sec_mp" = /tmp ] && sec_audit_tmp_is_isolated; } || { [ "$_sec_mp" = /dev/shm ] && sec_audit_shm_is_isolated; }; then
        _ml=$(sec_audit_mp_out "$_sec_mp")
 echo "RULE${_rk}= PASS: ${_sec_mp} is a separate mount or tmpfs (${_ml})"
    else
 echo "RULE${_rk}= FAIL: ${_sec_mp} is not a separate -compliant mount"
    fi
done

for _pair in "1191:/tmp:nodev" "1192:/tmp:nosuid" "1193:/tmp:noexec" "1211:/var/tmp:nodev" "1212:/var/tmp:nosuid" "1213:/var/tmp:noexec" "1241:/home:nodev" "1242:/dev/shm:nodev" "126:/dev/shm:nosuid" "1261:/dev/shm:noexec"; do
    IFS=: read -r _rn _mp _opt <<< "$_pair"
    if sec_audit_mount_has_option "$_mp" "$_opt"; then
        echo "RULE${_rn}= PASS: ${_opt} set on ${_mp}"
    else
        echo "RULE${_rn}= FAIL: ${_opt} not set on ${_mp} (OPTIONS=$(sec_audit_mount_options "$_mp"))"
    fi
done

if systemctl list-unit-files 2>/dev/null | grep -qE '^rhnsd\.service[[:space:]]+enabled'; then
    sec_audit_report_fail 7 "rhnsd service unit is enabled"
else
    sec_audit_report_pass 7 "rhnsd not enabled"
fi

if ! systemctl is-enabled rhnsd &>/dev/null; then
    sec_audit_report_pass 8 "rhnsd not exist"
else
    sec_audit_report_fail 8 "rhnsd enabled"
fi

if rpm -qa 'xorg-x11-server*' 2>/dev/null | grep -q .; then
    sec_audit_report_fail 311 "x11-server packages installed"
else
    sec_audit_report_pass 311 "x11-server not installed"
fi

if sec_audit_pkg_is_absent rsync || sec_audit_systemctl_is_masked rsyncd; then
    sec_audit_report_pass 46 "rsync not installed or rsyncd masked/disabled"
else
    sec_audit_report_fail 46 "rsync installed and rsyncd not masked"
fi

if sec_audit_pkg_is_installed iptables; then
    sec_audit_report_pass 65 "iptables package installed"
else
    sec_audit_report_fail 65 "iptables not installed"
fi

_ml=$(awk -F= '/^[[:space:]]*max_log_file[[:space:]]*=/ {gsub(/ /,"",$2); print $2; exit}' /etc/audit/auditd.conf 2>/dev/null)
if [ -n "$_ml" ] && [ "$_ml" -le 8 ] 2>/dev/null; then
    sec_audit_report_pass 661 "max_log_file=${_ml} (<=8 MB configured)"
else
    sec_audit_report_fail 661 "max_log_file not configured <=8 (got: ${_ml:-unset})"
fi

_fcm=$(grep -rhE '^\$FileCreateMode' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | tail -1)
if echo "$_fcm" | grep -qE '0?640'; then
    sec_audit_report_pass 691 "rsyslog FileCreateMode 640"
else
    sec_audit_report_fail 691 "rsyslog FileCreateMode not 640"
fi
if grep -rE '^\*\.[^@]*@@[^I]' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -qv '127.0.0.1'; then
    sec_audit_report_pass 692 "remote syslog forwarding configured"
else
    sec_audit_report_fail 692 "no remote rsyslog host configured"
fi
if grep -rE '^\$ModLoad\s+imtcp|^\$InputTCPServerRun' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 693 "imtcp listener configured (verify designated log host manually)"
else
    sec_audit_report_fail 693 "rsyslog imtcp not configured"
fi

for _p in /etc/cron.allow /etc/at.allow; do
    _rn=$([ "$_p" = /etc/cron.allow ] && echo 802 || echo 812)
    if [ -f "$_p" ] && sec_audit_assert_path_access "$_p" 600 root root; then
        echo "RULE${_rn}= PASS: ${_p} exists mode 600 root:root"
    elif [ -f "$_p" ]; then
        echo "RULE${_rn}= FAIL: ${_p} permissions incorrect"
    else
        echo "RULE${_rn}= FAIL: ${_p} missing"
    fi
done

if sshd -T 2>/dev/null | grep -qi '^protocol 2'; then
    sec_audit_report_pass 83 "SSH Protocol 2"
elif ! grep -qiE '^protocol' /etc/ssh/sshd_config 2>/dev/null; then
    sec_audit_report_pass 83 "Default SSH protocol v2 (OpenSSH 7+)"
else
    sec_audit_report_fail 83 "SSH Protocol not restricted to 2"
fi

_pam_ok=0
for _f in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
    [ -f "$_f" ] || continue
    if grep -q pam_faillock "$_f" 2>/dev/null && grep -E 'pam_faillock\.so' "$_f" | grep -q deny; then
        _pam_ok=1
    elif grep -E 'pam_tally2\.so' "$_f" | grep -q deny; then
        _pam_ok=1
    fi
done
if [ "${_pam_ok:-0}" -eq 1 ]; then
    sec_audit_report_pass 9631 "deny/unlock_time configured in pam faillock or tally2"
else
    sec_audit_report_fail 9631 "lockout deny/unlock_time not configured"
fi

_bad_umask=$(grep -Ev '^\s*umask\s+\s*(0[0-7][2-7]7|[0-7][27]7|u=(r?|w?|x?)(r?|w?|x?)(r?|w?|x?),g=(r?x?|x?r?),o=)\s*(\s*#.*)?$' /etc/profile /etc/profile.d/*.sh /etc/bashrc 2>/dev/null | grep -E '(^|^[^#]*)umask' || true)
if [ -z "$_bad_umask" ]; then
    echo "RULE104.1= PASS: umask configured in profile/bashrc"
else
    echo "RULE104.1= FAIL: non-compliant umask entries present"
fi

_u0=$(awk -F: '($3==0){print $1}' /etc/passwd)
if [ "$_u0" = root ]; then
    sec_audit_report_pass 1181 "root is the only UID 0 account"
else
    sec_audit_report_fail 1181 "extra UID 0 accounts: $_u0"
fi

if sec_audit_pkg_is_absent ossec-hids 2>/dev/null && ! rpm -q ossec &>/dev/null; then
    sec_audit_report_pass 128 "ossec not installed (custom check)"
else
    sec_audit_report_fail 128 "ossec package present"
fi

if ! crontab -u root -l 2>/dev/null | grep -q ossec; then
    sec_audit_report_pass 129 "no ossec root crontab entry"
else
    sec_audit_report_fail 129 "ossec crontab entry for root"
fi

_guid=$(awk '/^PASS_MAX_DAYS/{print $2; exit}' /etc/login.defs)
_bad130=$(awk -F: -v m="$_guid" '($2!="*" && $2!~/^!/) && $5>m {print $1" "$5}' /etc/shadow 2>/dev/null)
if [ -z "$_bad130" ]; then
    sec_audit_report_pass 130 "shadow PASS_MAX_DAYS compliant"
else
    sec_audit_report_fail 130 "users exceed PASS_MAX_DAYS: $_bad130"
fi

if sec_audit_pkg_is_absent rpcbind || { sec_audit_systemctl_is_masked rpcbind && sec_audit_systemctl_is_masked rpcbind.socket; }; then
    sec_audit_report_pass 161 "rpcbind not installed or masked"
else
    sec_audit_report_fail 161 "rpcbind installed and not masked"
fi

_fail162=""
for _mp in $(removable_mountpoints 2>/dev/null); do
    sec_audit_mount_has_option "$_mp" noexec || _fail162="$_fail162 $_mp"
done
if [ -z "$_fail162" ]; then
    sec_audit_report_pass 162 "removable media mount points have noexec"
else
    sec_audit_report_fail 162 "missing noexec on:$_fail162"
fi
_fail163=""
for _mp in $(removable_mountpoints 2>/dev/null); do
    sec_audit_mount_has_option "$_mp" nodev || _fail163="$_fail163 $_mp"
done
if [ -z "$_fail163" ]; then
    sec_audit_report_pass 163 "removable media mount points have nodev"
else
    sec_audit_report_fail 163 "missing nodev on:$_fail163"
fi
_fail164=""
for _mp in $(removable_mountpoints 2>/dev/null); do
    sec_audit_mount_has_option "$_mp" nosuid || _fail164="$_fail164 $_mp"
done
if [ -z "$_fail164" ]; then
    sec_audit_report_pass 164 "removable media mount points have nosuid"
else
    sec_audit_report_fail 164 "missing nosuid on:$_fail164"
fi
if sec_audit_kmod_is_blocked usb-storage; then
    sec_audit_report_pass 165 "usb-storage kernel module disabled"
else
    sec_audit_report_fail 165 "usb-storage not disabled"
fi

if sec_audit_yum_gpgcheck_global_ok && ! sec_audit_yum_repo_gpgcheck0_enabled; then
    sec_audit_report_pass 166 "yum gpgcheck enabled globally and repos"
else
    sec_audit_report_fail 166 "yum gpgcheck misconfigured"
fi

_uc=$(ps -eZ 2>/dev/null | grep unconfined_service_t | grep -v grep | wc -l)
if [ "${_uc:-0}" -eq 0 ]; then
    sec_audit_report_pass 174 "no unconfined_service_t processes"
else
    sec_audit_report_fail 174 "${_uc} unconfined_service_t processes"
fi

echo "RULE183= $(rpm -qa 'xorg-x11-server*' 2>/dev/null | head -3 | tr '\\n' ' ')"
if rpm -qa 'xorg-x11-server*' 2>/dev/null | grep -q .; then
    sec_audit_report_fail 183 "xorg-x11-server packages installed"
else
    sec_audit_report_pass 183 "xorg-x11-server not installed"
fi

if sec_audit_have_bin nmcli; then
    _wr=$(nmcli radio all 2>/dev/null | awk 'NR>1 && $3 ~ /yes|on/ {print $1}')
    if [ -z "$_wr" ]; then
        sec_audit_report_pass 190 "wireless interfaces disabled via nmcli"
    else
        sec_audit_report_fail 190 "wireless enabled: $_wr"
    fi
else
    sec_audit_report_pass 190 "nmcli not available (manual wireless check)"
fi

if sec_audit_systemd_is_enabled ip6tables || sec_audit_systemd_is_active ip6tables; then
    sec_audit_report_pass 194 "ip6tables enabled/active"
else
    sec_audit_report_fail 194 "ip6tables not enabled"
fi

if sec_audit_pkg_is_installed audit && sec_audit_pkg_is_installed audit-libs; then
    sec_audit_report_pass 195 "audit and audit-libs installed"
else
    sec_audit_report_fail 195 "audit packages missing"
fi

_gb=$(find /boot -maxdepth 2 -name grub.cfg 2>/dev/null | head -1)
_efilinux=""
[ -d /boot/efi/EFI ] && _efilinux=$(find /boot/efi/EFI -name grub.cfg 2>/dev/null | head -1)
_grubcfg="${_efilinux:-$_gb}"
if [ -n "$_grubcfg" ] && grep -E '^\s*linux' "$_grubcfg" 2>/dev/null | grep -q 'audit=1'; then
    sec_audit_report_pass 196 "audit=1 in grub kernel line"
else
    sec_audit_report_fail 196 "audit=1 missing in grub"
fi
if [ -n "$_grubcfg" ] && grep -E '^\s*linux' "$_grubcfg" 2>/dev/null | grep -qE 'audit_backlog_limit=[0-9]+'; then
    sec_audit_report_pass 197 "audit_backlog_limit set in grub"
else
    sec_audit_report_fail 197 "audit_backlog_limit missing in grub"
fi

for _tag in "198:time-change" "201:perm_mod" "203:scope" "204:actions" "205:modules"; do
    IFS=: read -r _rn _pat <<< "$_tag"
    if sec_audit_audit_rules_file_grep -q "$_pat"; then
        echo "RULE${_rn}= PASS: audit rules contain ${_pat}"
    else
        echo "RULE${_rn}= FAIL: audit rules missing ${_pat}"
    fi
done

if sec_audit_pkg_is_installed rsyslog; then
    sec_audit_report_pass 206 "rsyslog installed"
else
    sec_audit_report_fail 206 "rsyslog not installed"
fi

if sec_audit_pkg_is_installed sudo; then
    sec_audit_report_pass 208 "sudo installed"
else
    sec_audit_report_fail 208 "sudo not installed"
fi
if grep -rEi '^\s*Defaults\s+([^#]+,\s*)?use_pty\b' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -q .; then
    sec_audit_report_pass 209 "sudo use_pty configured"
else
    sec_audit_report_fail 209 "sudo use_pty not configured"
fi
if grep -rEi '^\s*Defaults\s+([^#;]+,\s*)?logfile\s*=' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -q .; then
    sec_audit_report_pass 210 "sudo logfile configured"
else
    sec_audit_report_fail 210 "sudo logfile not configured"
fi

# RULE211:
_ok211=1
for _hk in /etc/ssh/ssh_host_*_key; do
    [ -f "$_hk" ] || continue
    _m=$(sec_audit_path_mode_octal "$_hk")
    [ "$_m" = "600" ] || _ok211=0
done
if [ "${_ok211:-0}" -eq 1 ]; then
    sec_audit_report_pass 211 "SSH private host keys mode 600"
else
    sec_audit_report_fail 211 "one or more SSH private host keys not mode 600"
fi

_uidmin=$(awk '/^UID_MIN/{print $2; exit}' /etc/login.defs)
_bad223=""
while read -r _u; do
    [ -n "$_u" ] || continue
    _st=$(passwd -S "$_u" 2>/dev/null | awk '{print $2}')
    echo "$_st" | grep -qE 'L|LK' || _bad223="$_bad223 $_u"
done < <(awk -F: -v m="${_uidmin:-500}" '($1!="root" && $3<m && $3>=0){print $1}' /etc/passwd)
if [ -z "$_bad223" ]; then
    sec_audit_report_pass 223 "inactive/password-locked system accounts"
else
    sec_audit_report_fail 223 "active system accounts:$_bad223"
fi

if grep -rE '^[[:space:]]*auth[[:space:]]+(required|requisite)[[:space:]]+pam_wheel\.so' /etc/pam.d/su 2>/dev/null | grep -qE 'use_uid|group='; then
    sec_audit_report_pass 226 "pam_wheel restricts su"
else
    sec_audit_report_fail 226 "su not restricted via pam_wheel"
fi
_np=$(awk -F: '($2!="x"){print $1}' /etc/passwd)
if [ -z "$_np" ]; then
    sec_audit_report_pass 227 "all accounts use shadowed passwords"
else
    sec_audit_report_fail 227 "non-shadowed: $_np"
fi
_missg=""
for _g in $(cut -s -d: -f4 /etc/passwd | sort -u); do
    grep -q ":$_g:" /etc/group || _missg="$_missg $_g"
done
if [ -z "$_missg" ]; then
    sec_audit_report_pass 228 "all passwd GIDs exist in group"
else
    sec_audit_report_fail 228 "missing groups:$_missg"
fi
_sg=$(awk -F: '($1=="shadow"){print $3}' /etc/group)
_insh=$(awk -F: -v g="$_sg" '($4==g){print $1}' /etc/passwd)
if [ -z "$_insh" ]; then
    sec_audit_report_pass 229 "shadow group empty"
else
    sec_audit_report_fail 229 "users in shadow group: $_insh"
fi
_dupu=$(cut -d: -f1 /etc/passwd | sort | uniq -d)
if [ -z "$_dupu" ]; then
    sec_audit_report_pass 230 "no duplicate usernames"
else
    sec_audit_report_fail 230 "duplicate users: $_dupu"
fi
_dupg=$(cut -d: -f1 /etc/group | sort | uniq -d)
if [ -z "$_dupg" ]; then
    sec_audit_report_pass 231 "no duplicate group names"
else
    sec_audit_report_fail 231 "duplicate groups: $_dupg"
fi
_dupgid=$(cut -d: -f3 /etc/group | sort | uniq -d)
if [ -z "$_dupgid" ]; then
    sec_audit_report_pass 232 "no duplicate GIDs"
else
    sec_audit_report_fail 232 "duplicate GIDs: $_dupgid"
fi
_pathv=$(sudo -Hiu root env 2>/dev/null | awk -F= '/^PATH=/{print $2; exit}')
_pathbad=""
echo "$_pathv" | grep -q '::' && _pathbad="empty dir ::"
echo "$_pathv" | grep -q ':$' && _pathbad="$_pathbad trailing :"
if [ -z "$_pathbad" ]; then
    sec_audit_report_pass 233 "root PATH integrity"
else
    sec_audit_report_fail 233 "root PATH issues: $_pathbad"
fi
_dotbad=$(awk -F: '($1!~/(halt|sync|shutdown)/ && $7!~/nologin|false/){print $1" "$6}' /etc/passwd | while read -r _u _d; do
    [ -d "$_d" ] || continue
    find "$_d" -maxdepth 1 -name '.*' -type f ! -name '.' ! -name '..' 2>/dev/null | while read -r _f; do
        _pm=$(stat -L -c '%A' "$_f" 2>/dev/null)
        echo "$_pm" | grep -qE '.{5}w|.{8}w' && echo "$_u:$_f:$_pm"
    done
done)
if [ -z "$_dotbad" ]; then
    sec_audit_report_pass 234 "user dot files not group/world writable"
else
    sec_audit_report_fail 234 "weak dot file perms"
fi

if [ -f /etc/default/grub ] && grep -q 'audit=1' /etc/default/grub; then
    sec_audit_report_pass 238 "audit=1 in /etc/default/grub"
else
    sec_audit_report_fail 238 "audit=1 not in /etc/default/grub"
fi

if awk '/-w/ && /utmp|wtmp|btmp/ && /-p.*wa/ && /-k |key=/' /etc/audit/rules.d/*.rules 2>/dev/null | grep -q .; then
    sec_audit_report_pass 245 "login/logout audit watch rules"
else
    sec_audit_report_fail 245 "missing utmp/wtmp/btmp audit watches"
fi
if awk '/-w/ && /lastlog|faillock/ && /-p.*wa/' /etc/audit/rules.d/*.rules 2>/dev/null | grep -q .; then
    sec_audit_report_pass 246 "session audit watch rules"
else
    sec_audit_report_fail 246 "missing lastlog/faillock audit watches"
fi
_uidmin=$(awk '/^UID_MIN/{print $2; exit}' /etc/login.defs)
if [ -n "$_uidmin" ] && awk -v u="$_uidmin" '/-a always,exit/ && /unlink|rename|unlinkat|renameat/ && /auid>=/ && /key=|-k /' /etc/audit/rules.d/*.rules 2>/dev/null | grep -q .; then
    sec_audit_report_pass 247 "file deletion audit rules for non-privileged users"
else
    sec_audit_report_fail 247 "file deletion audit rules incomplete"
fi

echo -n "RULE1000= PASS: password change audit "
for _u in $(awk -F: '($3>=1000){print $1}' /etc/passwd); do
    _exp=$(chage -l "$_u" 2>/dev/null | awk -F: '/Password expires/{print $2}' | xargs)
    [ "$_exp" = "never" ] || echo -ne "${_u}\t"
done
echo

_rin=$(awk -F: '($1=="root"){print $7}' /etc/shadow 2>/dev/null)
if [ -n "$_rin" ] && [ "$_rin" -le 30 ] 2>/dev/null; then
    sec_audit_report_pass 10111 "root INACTIVE=${_rin}"
else
    sec_audit_report_fail 10111 "root INACTIVE not <=30"
fi

if systemctl list-unit-files 2>/dev/null | grep -q '^syslog.service'; then
    sec_audit_report_pass 6911 "syslog unit present"
else
    sec_audit_report_fail 6911 "syslog not installed"
fi
if systemctl list-unit-files 2>/dev/null | grep -q '^syslog-ng.service'; then
    sec_audit_report_pass 6921 "syslog-ng unit present"
else
    sec_audit_report_fail 6921 "syslog-ng not installed"
fi

# RULE13:
_ok13=1
for _sf in /usr/lib/systemd/system/rescue.service /usr/lib/systemd/system/emergency.service; do
    grep -qE '/sbin/sulogin|/usr/sbin/sulogin' "$_sf" 2>/dev/null || _ok13=0
done
if [ "${_ok13:-0}" -eq 1 ]; then
    sec_audit_report_pass 13 "sulogin configured for rescue and emergency"
else
    sec_audit_report_fail 13 "rescue/emergency service missing sulogin"
fi

# RULE58-61:
sec_audit_req_sysctl_runtime 58 net.ipv4.icmp_echo_ignore_broadcasts 1 "ICMP echo broadcast ignored"
sec_audit_req_sysctl_runtime 59 net.ipv4.icmp_ignore_bogus_error_responses 1 "bogus ICMP responses ignored"
sec_audit_assert_sysctl_equals 61 net.ipv4.tcp_syncookies 1 "TCP SYN cookies enabled"

# RULE68:
if sec_audit_systemd_is_active auditd; then
    sec_audit_report_pass 68 "auditd service is active"
else
    sec_audit_report_fail 68 "auditd not active ($(systemctl is-active auditd 2>/dev/null))"
fi

# RULE69:
if sec_audit_systemd_is_active rsyslog; then
    sec_audit_report_pass 69 "rsyslog service is active"
else
    sec_audit_report_fail 69 "rsyslog not active ($(systemctl is-active rsyslog 2>/dev/null))"
fi

exit 0

