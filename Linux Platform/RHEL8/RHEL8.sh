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

RHEL8_FIND_CAP="${RHEL8_FIND_CAP:-${CRE_FIND_CAP:-20}}"
CRE_FIND_CAP="${RHEL8_FIND_CAP}"
RHEL8_CMD_CAP="${RHEL8_CMD_CAP:-${CRE_CMD_CAP:-12}}"
CRE_CMD_CAP="${RHEL8_CMD_CAP}"
RHEL8_DNF_CAP="${RHEL8_DNF_CAP:-${CRE_DNF_CAP:-30}}"
CRE_DNF_CAP="${RHEL8_DNF_CAP}"
RHEL8_ALLOW_CONTAINER_KMOD="${RHEL8_ALLOW_CONTAINER_KMOD:-${CRE_ALLOW_CONTAINER_KMOD:-${LINUX_CRE_ALLOW_CONTAINER_MODULES:-${ALMA_CRE_ALLOW_CONTAINER_MODULES:-0}}}}"
CRE_ALLOW_CONTAINER_KMOD="${RHEL8_ALLOW_CONTAINER_KMOD}"
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
        sec_audit_report_pass "$num" "${label} (waived: RHEL8_ALLOW_CONTAINER_KMOD=1)"
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
sec_audit_assert_kmod_disabled 1 "cramfs kernel module" cramfs cramfs.ko* "cramfs"
# RULE2:
sec_audit_assert_kmod_disabled 2 "squashfs kernel module" squashfs squashfs.ko* "squashfs"
# RULE3:
sec_audit_assert_kmod_disabled 3 "udf kernel module" udf udf.ko* "udf"
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
if sec_audit_mount_has_option /tmp nodev; then
    sec_audit_report_pass 5 "nodev option set on /tmp partition"
else
    sec_audit_report_fail 5 "nodev is not set on /tmp (or path not resolvable / not an explicit mount per policy)"
fi

# RULE6:
if sec_audit_mount_has_option /tmp noexec; then
    sec_audit_report_pass 6 "noexec option set on /tmp partition"
else
    sec_audit_report_fail 6 "noexec is not set on /tmp (or path not resolvable / not an explicit mount per policy)"
fi

# RULE7:
if sec_audit_mount_has_option /tmp nosuid; then
    sec_audit_report_pass 7 "nosuid option set on /tmp partition"
else
    sec_audit_report_fail 7 "nosuid is not set on /tmp (or path not resolvable / not an explicit mount per policy)"
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
if sec_audit_mount_has_option /var nodev; then
    sec_audit_report_pass 9 "nodev option set on /var partition"
else
    sec_audit_report_fail 9 "nodev is not set on /var (or path not resolvable / not an explicit mount per policy)"
fi

# RULE10:
if sec_audit_mount_has_option /var noexec; then
    sec_audit_report_pass 10 "noexec option set on /var partition"
else
    sec_audit_report_fail 10 "noexec is not set on /var (or path not resolvable / not an explicit mount per policy)"
fi

# RULE11:
if sec_audit_mount_has_option /var nosuid; then
    sec_audit_report_pass 11 "nosuid option set on /var partition"
else
    sec_audit_report_fail 11 "nosuid is not set on /var (or path not resolvable / not an explicit mount per policy)"
fi

# RULE12:
if sec_audit_path_is_isolated_volume /var/tmp; then
    if sec_audit_mount_is_persisted /var/tmp; then
        sec_audit_report_pass 12 "separate partition exists for /var/tmp"
    else
        sec_audit_report_fail 12 "dedicated mount for /var/tmp is runtime-only (missing fstab or systemd .mount persistence)"
    fi
else
    sec_audit_report_fail 12 "no compliant dedicated mount for /var/tmp"
fi
# RULE13:
if sec_audit_mount_has_option /var/tmp noexec; then
    sec_audit_report_pass 13 "noexec option set on /var/tmp partition"
else
    sec_audit_report_fail 13 "noexec is not set on /var/tmp (or path not resolvable / not an explicit mount per policy)"
fi

# RULE14:
if sec_audit_mount_has_option /var/tmp nosuid; then
    sec_audit_report_pass 14 "nosuid option set on /var/tmp partition"
else
    sec_audit_report_fail 14 "nosuid is not set on /var/tmp (or path not resolvable / not an explicit mount per policy)"
fi

# RULE15:
if sec_audit_mount_has_option /var/tmp nodev; then
    sec_audit_report_pass 15 "nodev option set on /var/tmp partition"
else
    sec_audit_report_fail 15 "nodev is not set on /var/tmp (or path not resolvable / not an explicit mount per policy)"
fi

# RULE16:
if sec_audit_path_is_isolated_volume /var/log; then
    if sec_audit_mount_is_persisted /var/log; then
        sec_audit_report_pass 16 "separate partition exists for /var/log"
    else
        sec_audit_report_fail 16 "dedicated mount for /var/log is runtime-only (missing fstab or systemd .mount persistence)"
    fi
else
    sec_audit_report_fail 16 "no compliant dedicated mount for /var/log"
fi
# RULE17:
if sec_audit_mount_has_option /var/log nodev; then
    sec_audit_report_pass 17 "nodev option set on /var/log partition"
else
    sec_audit_report_fail 17 "nodev is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
fi

# RULE18:
if sec_audit_mount_has_option /var/log noexec; then
    sec_audit_report_pass 18 "noexec option set on /var/log partition"
else
    sec_audit_report_fail 18 "noexec is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
fi

# RULE19:
if sec_audit_mount_has_option /var/log nosuid; then
    sec_audit_report_pass 19 "nosuid option set on /var/log partition"
else
    sec_audit_report_fail 19 "nosuid is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
fi

# RULE20:
if sec_audit_path_is_isolated_volume /var/log/audit; then
    if sec_audit_mount_is_persisted /var/log/audit; then
        sec_audit_report_pass 20 "separate partition exists for /var/log/audit"
    else
        sec_audit_report_fail 20 "dedicated mount for /var/log/audit is runtime-only (missing fstab or systemd .mount persistence)"
    fi
else
    sec_audit_report_fail 20 "no compliant dedicated mount for /var/log/audit"
fi
# RULE21:
if sec_audit_mount_has_option /var/log/audit noexec; then
    sec_audit_report_pass 21 "noexec option set on /var/log/audit partition"
else
    sec_audit_report_fail 21 "noexec is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
fi

# RULE22:
if sec_audit_mount_has_option /var/log/audit nodev; then
    sec_audit_report_pass 22 "nodev option set on /var/log/audit partition"
else
    sec_audit_report_fail 22 "nodev is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
fi

# RULE23:
if sec_audit_mount_has_option /var/log/audit nosuid; then
    sec_audit_report_pass 23 "nosuid option set on /var/log/audit partition"
else
    sec_audit_report_fail 23 "nosuid is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
fi

# RULE24:
if sec_audit_path_is_isolated_volume /home; then
    if sec_audit_mount_is_persisted /home; then
        sec_audit_report_pass 24 "separate partition exists for /home"
    else
        sec_audit_report_fail 24 "dedicated mount for /home is runtime-only (missing fstab or systemd .mount persistence)"
    fi
else
    sec_audit_report_fail 24 "no compliant dedicated mount for /home"
fi
# RULE25:
if sec_audit_mount_has_option /home nodev; then
    sec_audit_report_pass 25 "nodev option set on /home partition"
else
    sec_audit_report_fail 25 "nodev is not set on /home (or path not resolvable / not an explicit mount per policy)"
fi

# RULE26:
if sec_audit_mount_has_option /home nosuid; then
    sec_audit_report_pass 26 "nosuid option set on /home partition"
else
    sec_audit_report_fail 26 "nosuid is not set on /home (or path not resolvable / not an explicit mount per policy)"
fi

# RULE27:
if sec_audit_mount_has_option /home usrquota; then
    sec_audit_report_pass 27 "usrquota option set on /home partition"
else
    sec_audit_report_fail 27 "usrquota is not set on /home (or path not resolvable / not an explicit mount per policy)"
fi

# RULE28:
if sec_audit_mount_has_option /home grpquota; then
    sec_audit_report_pass 28 "grpquota option set on /home partition"
else
    sec_audit_report_fail 28 "grpquota is not set on /home (or path not resolvable / not an explicit mount per policy)"
fi

# RULE29:
if sec_audit_shm_is_isolated; then
    if sec_audit_mount_is_persisted /dev/shm; then
        sec_audit_report_pass 29 "/dev/shm is tmpfs or a separate partition"
    else
        sec_audit_report_fail 29 "/dev/shm is tmpfs or a separate partition is runtime-only (missing fstab or systemd .mount persistence)"
    fi
else
    sec_audit_report_fail 29 "/dev/shm does not meet tmpfs or separate-partition requirement"
fi
# RULE30:
if sec_audit_mount_has_option /dev/shm noexec; then
    sec_audit_report_pass 30 "noexec option set on /dev/shm partition"
else
    sec_audit_report_fail 30 "noexec is not set on /dev/shm (or path not resolvable / not an explicit mount per policy)"
fi

# RULE31:
if sec_audit_mount_has_option /dev/shm nosuid; then
    sec_audit_report_pass 31 "nosuid option set on /dev/shm partition"
else
    sec_audit_report_fail 31 "nosuid is not set on /dev/shm (or path not resolvable / not an explicit mount per policy)"
fi

# RULE32:
if sec_audit_have_bin subscription-manager; then
    if subscription-manager identity &>/dev/null; then
        sec_audit_report_pass 32 "Red Hat Subscription Manager identity is available"
    else
        sec_audit_report_fail 32 "subscription-manager identity not available"
    fi
else
    # RULE32:
if sec_audit_have_bin subscription-manager; then
    if subscription-manager identity &>/dev/null; then
        sec_audit_report_pass 32 "Red Hat Subscription Manager identity is available"
    else
        sec_audit_report_fail 32 "subscription-manager identity not available"
    fi
else
    sec_audit_report_fail 32 "subscription-manager not installed (RHSM registration cannot be verified)"
fi

fi

# RULE33:
_rule37_k=$(sec_audit_rpm_gpg_pubkey_count)
_rule37_sample=""
if sec_audit_have_bin rpm && [ "${_rule37_k:-0}" -gt 0 ]; then
    _rule37_sample=$(
        rpm -qa 'gpg-pubkey*' --qf '%{VERSION}\n' 2>/dev/null | awk 'NF && NR <= 6 { s = (s ? s "," : s) $1 } END { print s }'
    )
fi
if ! sec_audit_have_bin rpm; then
    sec_audit_report_fail 33 "rpm not available; cannot verify gpg-pubkey packages in the RPM database"
elif [ "${_rule37_k:-0}" -eq 0 ]; then
    sec_audit_report_fail 33 "no gpg-pubkey packages in the RPM database (import distribution or repository signing keys)"
else
    sec_audit_report_pass 33 "${_rule37_k} gpg-pubkey package(s) in RPM DB (sample key VERSION ids: ${_rule37_sample:-n/a})"
fi

# RULE34:
_rule38_main=$(sec_audit_dnf_main_option gpgcheck)
_rule38_repo=$(sec_audit_yum_repo_list_explicit_gpgcheck0 | head -n1)
if sec_audit_truthy_false "$_rule38_main"; then
    sec_audit_report_fail 34 "merged [main] gpgcheck is disabled (effective value: ${_rule38_main})"
elif [ -n "$_rule38_repo" ]; then
    sec_audit_report_fail 34 "enabled repository section explicitly sets gpgcheck=0 (${_rule38_repo//|/ -> })"
else
    sec_audit_report_pass 34 "[main] gpgcheck is not false and no enabled .repo section forces gpgcheck=0"
fi

# RULE35:
_rule40_dnf_n=$(sec_audit_dnf_enabled_repo_count)
if [ ! -d /etc/yum.repos.d ]; then
    sec_audit_report_fail 35 "/etc/yum.repos.d is missing"
else
    _rule40_nrepo=0
    shopt -s nullglob
    for _rf in /etc/yum.repos.d/*.repo; do
        [ -f "$_rf" ] && _rule40_nrepo=$((_rule40_nrepo + 1))
    done
    shopt -u nullglob
    if [ "${_rule40_nrepo:-0}" -eq 0 ]; then
        sec_audit_report_fail 35 "no .repo files under /etc/yum.repos.d"
    elif ! sec_audit_yum_repo_any_enabled_has_uris; then
        sec_audit_report_fail 35 "no enabled repository section defines a non-empty baseurl, mirrorlist, or metalink"
    elif sec_audit_have_bin dnf && [ "${_rule40_dnf_n:-0}" -eq 0 ]; then
        sec_audit_report_fail 35 ".repo files define URIs but dnf repolist enabled reports 0 repos (metadata, plugin, or config error)"
    else
        if sec_audit_have_bin dnf && [ "${_rule40_dnf_n:-0}" -gt 0 ]; then
            sec_audit_report_pass 35 "${_rule40_nrepo} .repo file(s); dnf reports ${_rule40_dnf_n} enabled repo(s); enabled sections include package URIs"
        else
            sec_audit_report_pass 35 "${_rule40_nrepo} .repo file(s); enabled sections include baseurl/mirrorlist/metalink (dnf not used for count)"
        fi
    fi
fi

# RULE36:
if rpm -q aide &>/dev/null; then
    sec_audit_report_pass 36 "AIDE is installed"
else
    sec_audit_report_fail 36 "AIDE is not installed"
fi

# RULE37:
if grep -Ers '^([^#]+\s+)?(\/usr\/s?bin\/|^\s*)aide(\.wrapper)?\s(--?\S+\s)*(-(check|update)|\$AIDEARGS)\b' /etc/cron.* /etc/crontab /var/spool/cron/ /etc/cron.d 2>/dev/null; then
    sec_audit_report_pass 37 "filesystem integrity is regularly checked (cron/cron.d entry references aide)"
elif systemctl is-enabled aidecheck.timer 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active aidecheck.timer 2>/dev/null | grep -q 'active'; then
        _a208_n=$(systemctl show aidecheck.timer -p NextElapseUSRealtime 2>/dev/null | cut -d= -f2-)
        sec_audit_report_pass 37 "aidecheck.timer enabled and active (next: ${_a208_n:-unknown})"
    else
        sec_audit_report_fail 37 "aidecheck.timer enabled but not active"
    fi
else
    sec_audit_report_fail 37 "filesystem integrity is regularly checked"
fi

# RULE38:
if sec_audit_grub_cfg_matches '^[[:space:]]*set superusers' && sec_audit_grub_cfg_matches 'password_pbkdf2'; then
    sec_audit_report_pass 38 "bootloader password is set (grub.cfg under /boot/grub2 or EFI)"
else
    sec_audit_report_fail 38 "GRUB bootloader superuser/password_pbkdf2 is not configured as required in grub.cfg"
fi
# RULE39:
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
    sec_audit_report_pass 39 "access to bootloader config is configured"
else
    sec_audit_report_fail 39 "/boot/grub2/grub.cfg (or EFI grub.cfg) owner/mode is not root:root with mode 600"
fi
# RULE40:
if grep -Eq '/sbin/sulogin|/usr/sbin/sulogin' /usr/lib/systemd/system/rescue.service /usr/lib/systemd/system/emergency.service 2>/dev/null; then
    sec_audit_report_pass 40 "authentication required when booting into rescue/emergency mode"
else
    sec_audit_report_fail 40 "rescue/emergency service does not invoke sulogin"
fi

# RULE41:
if sec_audit_core_dumps_limited; then
    sec_audit_report_pass 41 "limits * hard core 0 present and systemd DefaultLimitCORE does not allow unlimited core dumps"
elif grep -Pqs '^\*\s+hard\s+core\s+0\b' /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null; then
    sec_audit_report_fail 41 "limits.conf sets hard core 0 but systemd DefaultLimitCORE contradicts (check system.conf / user.conf drop-ins)"
else
    sec_audit_report_fail 41 "core file size limits are not configured (limits * hard core 0 not found)"
fi

# RULE42:
sec_audit_assert_sysctl_equals 42 fs.protected_hardlinks 1
# RULE43:
sec_audit_assert_sysctl_equals 43 fs.protected_symlinks 1
# RULE44:
if rpm -q libselinux &>/dev/null; then
    sec_audit_report_pass 44 "SELinux is installed"
else
    sec_audit_report_fail 44 "SELinux stack (libselinux) is not installed"
fi

# RULE45:
if grep -P '(selinux|enforcing)=0\b' /proc/cmdline 2>/dev/null; then
    sec_audit_report_fail 45 "SELinux is disabled via kernel command line or bootloader configuration"
elif grep -Prs '^\h*([^#\n\r]+\h+)?kernelopts=([^#\n\r]+\h+)?(selinux|enforcing)=0\b' /boot/grub2 /boot/efi 2>/dev/null; then
    sec_audit_report_fail 45 "SELinux is disabled via kernel command line or bootloader configuration"
else
    sec_audit_report_pass 45 "SELinux is not disabled in bootloader configuration"
fi

# RULE46:
if grep -Pqs '^\h*SELINUXTYPE\h*=\h*(targeted|mls)\b' /etc/selinux/config 2>/dev/null; then
    sec_audit_report_pass 46 "SELinux policy is configured"
else
    sec_audit_report_fail 46 "SELinux policy type is not set to targeted or mls in /etc/selinux/config"
fi

# RULE47:
_ge45=$(getenforce 2>/dev/null || true)
if grep -Pi '^\h*SELINUX=disabled\b' /etc/selinux/config 2>/dev/null; then
    sec_audit_report_fail 47 "SELinux is disabled in /etc/selinux/config"
elif [[ "$_ge45" == "Disabled" ]]; then
    sec_audit_report_fail 47 "getenforce reports Disabled"
elif [[ "$_ge45" == "Permissive" ]]; then
    sec_audit_report_fail 47 "SELinux is permissive (CRE default requires enforcing; set waiver or fix before audit)"
elif grep -Pi '^\h*SELINUX=(enforcing|permissive)\b' /etc/selinux/config 2>/dev/null && [[ "$_ge45" == "Enforcing" ]]; then
    sec_audit_report_pass 47 "the SELinux mode is not disabled (enforcing)"
else
    sec_audit_report_fail 47 "SELinux mode is not in an acceptable state (config/getenforce mismatch or disabled)"
fi
# RULE48:
_ge46=$(getenforce 2>/dev/null || true)
_cfg46=$(grep -Pi '^\h*SELINUX=\K\w+' /etc/selinux/config 2>/dev/null | head -n1 || true)
if [[ "$_ge46" != "Enforcing" ]]; then
    sec_audit_report_fail 48 "getenforce is '${_ge46:-unknown}', expected Enforcing"
elif [[ "$_cfg46" != "enforcing" ]]; then
    sec_audit_report_fail 48 "runtime Enforcing but /etc/selinux/config SELINUX=${_cfg46:-unset} (will revert after reboot)"
else
    sec_audit_report_pass 48 "the SELinux mode is enforcing (runtime and config)"
fi
# RULE49:
if ps -eZ 2>/dev/null | grep -q unconfined_service_t; then
    sec_audit_report_fail 49 "Processes running with unconfined_service_t were detected"
else
    sec_audit_report_pass 49 "no unconfined services exist"
fi

# RULE50:
if rpm -q setroubleshoot &>/dev/null; then
    sec_audit_report_fail 50 "package setroubleshoot is installed"
else
    sec_audit_report_pass 50 "package setroubleshoot is not installed"
fi

# RULE51:
if rpm -q mcstrans &>/dev/null; then
    sec_audit_report_fail 51 "package mcstrans is installed"
else
    sec_audit_report_pass 51 "package mcstrans is not installed"
fi

# RULE52:
if grep -Pqs "(\\\v|\\\r|\\\m|\\\s|\b$(grep ^ID= /etc/os-release 2>/dev/null | cut -d= -f2 | sed -e 's/"//g')\b)" /etc/motd 2>/dev/null; then
    sec_audit_report_fail 52 "/etc/motd is missing or does not contain required banner content"
else
    sec_audit_report_pass 52 "/etc/motd is configured"
fi

# RULE53:
if grep -Pqs "(\\\v|\\\r|\\\m|\\\s|\b$(grep ^ID= /etc/os-release 2>/dev/null | cut -d= -f2 | sed -e 's/"//g')\b)" /etc/issue 2>/dev/null; then
    sec_audit_report_fail 53 "/etc/issue is missing or does not contain required local login banner"
else
    sec_audit_report_pass 53 "/etc/issue is configured"
fi

# RULE54:
if [ -f /etc/issue.net ]; then
    if grep -Pqs "(\\\v|\\\r|\\\m|\\\s|\b$(grep ^ID= /etc/os-release 2>/dev/null | cut -d= -f2 | sed -e 's/"//g')\b)" /etc/issue.net 2>/dev/null; then
        sec_audit_report_fail 54 "/etc/issue.net is missing or does not contain required remote login banner"
    else
        sec_audit_report_pass 54 "/etc/issue.net is configured"
    fi
else
    sec_audit_report_pass 54 "/etc/issue.net is configured"
fi

# RULE55:
if [ -e /etc/motd ]; then
    if stat -Lc '%a' /etc/motd 2>/dev/null | grep -qE '^[0-6]44$'; then
        if stat -Lc '%U:%G' /etc/motd 2>/dev/null | grep -q '^root:root$'; then
            sec_audit_report_pass 55 "access to /etc/motd is configured"
        else
            sec_audit_report_fail 55 "File /etc/motd permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 55 "File /etc/motd permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 55 "access to /etc/motd is configured (file not found)"
fi

# RULE56:
if stat -Lc '%a' /etc/issue 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' /etc/issue 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 56 "access to /etc/issue is configured"
    else
        sec_audit_report_fail 56 "File /etc/issue permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 56 "File /etc/issue permissions or ownership not correct"
fi

# RULE57:
if [ -e /etc/issue.net ]; then
    if stat -Lc '%a' /etc/issue.net 2>/dev/null | grep -qE '^[0-6]44$'; then
        if stat -Lc '%U:%G' /etc/issue.net 2>/dev/null | grep -q '^root:root$'; then
            sec_audit_report_pass 57 "access to /etc/issue.net is configured"
        else
            sec_audit_report_fail 57 "File /etc/issue.net permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 57 "File /etc/issue.net permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 57 "access to /etc/issue.net is configured (file not found)"
fi

# RULE58:
GDM_CONFIG="/etc/gdm/custom.conf"
if [ -f "$GDM_CONFIG" ]; then
    if grep -Pzo "\[org/gnome/login-screen\][^\[]*banner-message-enable=true" "$GDM_CONFIG" 2>/dev/null | grep -q .; then
        sec_audit_report_pass 58 "GDM login banner is configured"
    else
        sec_audit_report_fail 58 "GDM login banner is not configured in $GDM_CONFIG"
    fi
else
    sec_audit_report_fail 58 "GDM configuration file not found ($GDM_CONFIG)"
fi

# RULE59:
if rpm -q gdm &>/dev/null && grep -q "DisableUserList=true" /etc/gdm/custom.conf 2>/dev/null; then
    sec_audit_report_pass 59 "GDM disable-user-list is configured"
elif ! rpm -q gdm &>/dev/null; then
    sec_audit_report_pass 59 "GDM is not installed"
else
    sec_audit_report_fail 59 "GDM disable-user-list is not configured"
fi

# RULE60:
if grep -q "idle-delay=uint32" /etc/dconf/db/gdm.d/* 2>/dev/null || \
   grep -q "lock-delay=uint32" /etc/dconf/db/gdm.d/* 2>/dev/null; then
    sec_audit_report_pass 60 "GDM screen lock is configured"
else
    sec_audit_report_fail 60 "GDM screen lock is not configured"
fi

# RULE61:
if grep -q "automount=false" /etc/dconf/db/gdm.d/* 2>/dev/null || \
   grep -q "automount-open=false" /etc/dconf/db/gdm.d/* 2>/dev/null; then
    sec_audit_report_pass 61 "GDM automount is configured"
else
    sec_audit_report_fail 61 "GDM automount is not configured"
fi

# RULE62:
if sec_audit_kmod_autoload_listed removable; then
    sec_audit_report_fail 62 "removable kernel module is listed in modules-load.d (auto-load at boot)"
elif ! sec_audit_soft_find --timeout=20 /usr/lib/modules/ /lib/modules/ -xdev -ignore_readdir_race -type f -name "removable.ko*" 2>/dev/null | grep -q .; then
    sec_audit_report_pass 62 "removable kernel module is not available"
else
    if ! lsmod | grep -q removable && modprobe --showconfig 2>/dev/null | grep -Eq '^(blacklist|install)[[:space:]]+removable\b'; then
        sec_audit_report_pass 62 "removable kernel module is not available"
    else
        sec_audit_report_fail 62 "removable kernel module is available, loaded, or not effectively blocked (modprobe blacklist/install)"
    fi
fi

# RULE63:
if sec_audit_have_bin dnf; then
    if dnf check-update --security 2>/dev/null | grep -qiE '^(Last metadata|Security:.*nothing to do|No security updates)'; then
        sec_audit_report_pass 63 "no pending security updates reported by dnf check-update --security"
    elif dnf check-update --security 2>/dev/null | tail -n +2 | grep -qE '^[[:alnum:]]'; then
        sec_audit_report_fail 63 "security updates are available (dnf check-update --security lists packages)"
    else
        sec_audit_report_pass 63 "dnf security update check completed with no pending packages"
    fi
elif sec_audit_have_bin yum; then
    if yum check-update --security 2>/dev/null | grep -q 'No packages needed for security'; then
        sec_audit_report_pass 63 "no security updates pending"
    else
        sec_audit_report_fail 63 "security updates may be available (yum check-update --security)"
    fi
else
    sec_audit_report_fail 63 "no supported package manager (dnf/yum) for update verification"
fi

# RULE64:
if grep -Piqs '^\h*LEGACY\b' /etc/crypto-policies/config 2>/dev/null; then
    sec_audit_report_fail 64 "System-wide crypto policy is LEGACY in /etc/crypto-policies/config"
else
    sec_audit_report_pass 64 "system-wide crypto policy is not legacy"
fi

# RULE65:
if rpm -q chrony &>/dev/null; then
    if systemctl is-active chronyd.service &>/dev/null; then
        sec_audit_report_pass 65 "chrony is installed and chronyd.service is active"
    else
        sec_audit_report_fail 65 "chrony is installed but chronyd.service is not active"
    fi
else
    sec_audit_report_fail 65 "time synchronization is not in use (chrony not installed)"
fi

# RULE66:
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
    sec_audit_report_pass 66 "chrony has ${_ch101_src:-0} server/pool line(s) in conf or chrony.d${_ch101_track}"
else
    sec_audit_report_fail 66 "chrony is not configured with time sources (no server/pool in chrony.conf or chrony.d)"
fi

# RULE67:
if rpm -q xinetd &>/dev/null; then
    sec_audit_report_fail 67 "package xinetd is installed"
else
    sec_audit_report_pass 67 "package xinetd is not installed"
fi

# RULE68:
if rpm -q xorg-x11-server &>/dev/null; then
    sec_audit_report_fail 68 "package xorg-x11-server is installed"
else
    sec_audit_report_pass 68 "package xorg-x11-server is not installed"
fi

# RULE69:
sec_audit_assert_service_unused 69 avahi "avahi daemon services are not in use" "avahi daemon services are installed and enabled or actively running" "avahi-daemon.socket" "avahi-daemon.service"
# RULE70:
sec_audit_assert_service_unused 70 cups "print server services are not in use" "print server services are installed and enabled or actively running" "cups.socket" "cups.service"
# RULE71:
if rpm -q dhcp &>/dev/null; then
    sec_audit_report_fail 71 "package dhcp is installed"
else
    sec_audit_report_pass 71 "package dhcp is not installed"
fi

# RULE72:
sec_audit_assert_service_unused 72 dnsmasq "dnsmasq services are not in use" "dnsmasq services are installed and enabled or actively running" "dnsmasq.service"
# RULE73:
sec_audit_assert_service_unused 73 vsftpd "ftp server services are not in use" "ftp server services are installed and enabled or actively running" "vsftpd.service"
# RULE74:
if sec_audit_pkg_any_installed dovecot cyrus-imapd; then
    if sec_audit_systemd_unit_live dovecot.socket dovecot.service cyrus-imapd.service; then
        sec_audit_report_fail 74 "message access server services are installed and enabled or actively running"
    else
        sec_audit_report_pass 74 "message access server services are not in use (package present but units masked/disabled/inactive)"
    fi
else
    sec_audit_report_pass 74 "message access server services are not in use"
fi
# RULE75:
sec_audit_assert_service_unused 75 nfs-utils "network file system services are not in use" "network file system services are installed and enabled or actively running" "nfs-server.service"
# RULE76:
if rpm -q httpd &>/dev/null; then
    sec_audit_report_fail 76 "package httpd is installed"
else
    sec_audit_report_pass 76 "package httpd is not installed"
fi

# RULE77:
if rpm -q dovecot &>/dev/null; then
    sec_audit_report_fail 77 "package dovecot is installed"
else
    sec_audit_report_pass 77 "package dovecot is not installed"
fi

# RULE78:
sec_audit_assert_service_unused 78 samba "samba file server services are not in use" "samba file server services are installed and enabled or actively running" "smb.service"
# RULE79:
if rpm -q squid &>/dev/null; then
    sec_audit_report_fail 79 "package squid is installed"
else
    sec_audit_report_pass 79 "package squid is not installed"
fi

# RULE80:
sec_audit_assert_service_unused 80 net-snmp "snmp services are not in use" "snmp services are installed and enabled or actively running" "snmpd.service"
# RULE81:
sec_audit_assert_service_unused 81 telnet-server "telnet server services are not in use" "telnet server services are installed and enabled or actively running" "telnet.socket"
# RULE82:
if rpm -q telnet &>/dev/null; then
    sec_audit_report_fail 82 "package telnet is installed"
else
    sec_audit_report_pass 82 "package telnet is not installed"
fi

# RULE83:
sec_audit_assert_service_unused 83 squid "web proxy server services are not in use" "web proxy server services are installed and enabled or actively running" "squid.service"
# RULE84:
if rpm -q nfs-utils &>/dev/null; then
    sec_audit_report_fail 84 "package nfs-utils is installed"
else
    sec_audit_report_pass 84 "package nfs-utils is not installed"
fi

# RULE85:
sec_audit_assert_service_unused 85 bind "dns server services are not in use" "dns server services are installed and enabled or actively running" "named.service"
# RULE86:
if rpm -q rsync &>/dev/null; then
    sec_audit_report_fail 86 "package rsync is installed"
else
    sec_audit_report_pass 86 "package rsync is not installed"
fi

# RULE87:
if rpm -q chrony &>/dev/null; then
    if systemctl is-active chronyd.service &>/dev/null; then
        sec_audit_report_pass 87 "chrony is installed and chronyd.service is active"
    else
        sec_audit_report_fail 87 "chrony is installed but chronyd.service is not active"
    fi
else
    sec_audit_report_fail 87 "time synchronization is not in use (chrony not installed)"
fi

# RULE88:
if rpm -q rsh &>/dev/null; then
    sec_audit_report_fail 88 "package rsh is installed"
else
    sec_audit_report_pass 88 "package rsh is not installed"
fi

# RULE89:
if rpm -q talk &>/dev/null; then
    sec_audit_report_fail 89 "package talk is installed"
else
    sec_audit_report_pass 89 "package talk is not installed"
fi

# RULE90:
if rpm -q telnet &>/dev/null; then
    sec_audit_report_fail 90 "package telnet is installed"
else
    sec_audit_report_pass 90 "package telnet is not installed"
fi

# RULE91:
if rpm -q openldap-clients &>/dev/null; then
    sec_audit_report_fail 91 "package openldap-clients is installed"
else
    sec_audit_report_pass 91 "package openldap-clients is not installed"
fi

# RULE92:
if rpm -q tftp &>/dev/null; then
    sec_audit_report_fail 92 "package tftp is installed"
else
    sec_audit_report_pass 92 "package tftp is not installed"
fi

# RULE93:
_bad=0
for _u in telnet.socket rsh.socket rexec.socket; do
    _st=$(systemctl is-enabled "$_u" 2>/dev/null || true)
    case "$_st" in enabled|enabled-runtime) _bad=1 ;; esac
done
if [ ${_bad} -eq 0 ]; then
    sec_audit_report_pass 93 "nonessential inet services are masked or disabled"
else
    sec_audit_report_fail 93 "nonessential systemd socket services still enabled"
fi

# RULE94:
if compgen -G "/sys/class/net/*/wireless" >/dev/null; then
    sec_audit_report_fail 94 "Wireless interfaces are present under /sys/class/net"
else
    sec_audit_report_pass 94 "wireless interfaces are not available"
fi

# RULE95:
sec_audit_assert_service_unused 95 bluez "bluetooth services are not in use" "bluetooth services are installed and enabled or actively running" "bluetooth.service"
# RULE96:
if sec_audit_have_bin nmcli; then
    if nmcli radio wifi 2>/dev/null | grep -qE '^enabled'; then
        sec_audit_report_fail 96 "wireless (Wi-Fi) radio is enabled"
    else
        sec_audit_report_pass 96 "wireless interfaces are disabled"
    fi
else
    # RULE96:
if sec_audit_have_bin nmcli; then
    if nmcli radio wifi 2>/dev/null | grep -qE '^enabled'; then
        sec_audit_report_fail 96 "wireless (Wi-Fi) radio is enabled"
    else
        sec_audit_report_pass 96 "wireless interfaces are disabled"
    fi
elif compgen -G "/sys/class/net/*/wireless" >/dev/null; then
    sec_audit_report_fail 96 "wireless interfaces present and nmcli unavailable to verify radio state"
else
    sec_audit_report_pass 96 "no wireless interfaces detected"
fi

fi

# RULE97:
sec_audit_assert_kmod_disabled 97 "atm kernel module" atm atm.ko* "atm"
# RULE98:
sec_audit_assert_kmod_disabled 98 "can kernel module" can can.ko* "can"
# RULE99:
FAIL99=0
if ! sec_audit_sysctl_runtime_equals "net.ipv4.conf.all.accept_source_route" "0"; then FAIL99=1; fi
if ! sec_audit_sysctl_runtime_equals "net.ipv4.conf.default.accept_source_route" "0"; then FAIL99=1; fi
if [ $FAIL99 -eq 0 ]; then
    sec_audit_report_pass 99 "sysctl policy OK (net.ipv4.conf.all.accept_source_route, net.ipv4.conf.default.accept_source_route)"
else
    sec_audit_report_fail 99 "one or more sysctl values do not match policy (net.ipv4.conf.all.accept_source_route, net.ipv4.conf.default.accept_source_route)"
fi

# RULE100:
FAIL100=0
if ! sec_audit_sysctl_runtime_equals "net.ipv4.conf.all.accept_redirects" "0"; then FAIL100=1; fi
if ! sec_audit_sysctl_runtime_equals "net.ipv4.conf.default.accept_redirects" "0"; then FAIL100=1; fi
if [ $FAIL100 -eq 0 ]; then
    sec_audit_report_pass 100 "sysctl policy OK (net.ipv4.conf.all.accept_redirects, net.ipv4.conf.default.accept_redirects)"
else
    sec_audit_report_fail 100 "one or more sysctl values do not match policy (net.ipv4.conf.all.accept_redirects, net.ipv4.conf.default.accept_redirects)"
fi

# RULE101:
FAIL101=0
if ! sec_audit_sysctl_runtime_equals "net.ipv4.conf.all.secure_redirects" "0"; then FAIL101=1; fi
if ! sec_audit_sysctl_runtime_equals "net.ipv4.conf.default.secure_redirects" "0"; then FAIL101=1; fi
if [ $FAIL101 -eq 0 ]; then
    sec_audit_report_pass 101 "sysctl policy OK (net.ipv4.conf.all.secure_redirects, net.ipv4.conf.default.secure_redirects)"
else
    sec_audit_report_fail 101 "one or more sysctl values do not match policy (net.ipv4.conf.all.secure_redirects, net.ipv4.conf.default.secure_redirects)"
fi

# RULE102:
FAIL102=0
if ! sec_audit_sysctl_runtime_equals "net.ipv4.conf.all.log_martians" "1"; then FAIL102=1; fi
if ! sec_audit_sysctl_runtime_equals "net.ipv4.conf.default.log_martians" "1"; then FAIL102=1; fi
if [ $FAIL102 -eq 0 ]; then
    sec_audit_report_pass 102 "sysctl policy OK (net.ipv4.conf.all.log_martians, net.ipv4.conf.default.log_martians)"
else
    sec_audit_report_fail 102 "one or more sysctl values do not match policy (net.ipv4.conf.all.log_martians, net.ipv4.conf.default.log_martians)"
fi

# RULE103:
FAIL103=0
if ! sec_audit_sysctl_runtime_equals "net.ipv4.icmp_echo_ignore_broadcasts" "1"; then FAIL103=1; fi
if [ $FAIL103 -eq 0 ]; then
    sec_audit_report_pass 103 "sysctl policy OK (net.ipv4.icmp_echo_ignore_broadcasts)"
else
    sec_audit_report_fail 103 "one or more sysctl values do not match policy (net.ipv4.icmp_echo_ignore_broadcasts)"
fi

# RULE104:
FAIL104=0
if ! sec_audit_sysctl_runtime_equals "net.ipv4.icmp_ignore_bogus_error_responses" "1"; then FAIL104=1; fi
if [ $FAIL104 -eq 0 ]; then
    sec_audit_report_pass 104 "sysctl policy OK (net.ipv4.icmp_ignore_bogus_error_responses)"
else
    sec_audit_report_fail 104 "one or more sysctl values do not match policy (net.ipv4.icmp_ignore_bogus_error_responses)"
fi

# RULE105:
FAIL105=0
if ! sec_audit_sysctl_runtime_equals "net.ipv4.conf.all.rp_filter" "1"; then FAIL105=1; fi
if ! sec_audit_sysctl_runtime_equals "net.ipv4.conf.default.rp_filter" "1"; then FAIL105=1; fi
if [ $FAIL105 -eq 0 ]; then
    sec_audit_report_pass 105 "sysctl policy OK (net.ipv4.conf.all.rp_filter, net.ipv4.conf.default.rp_filter)"
else
    sec_audit_report_fail 105 "one or more sysctl values do not match policy (net.ipv4.conf.all.rp_filter, net.ipv4.conf.default.rp_filter)"
fi

# RULE106:
FAIL106=0
if ! sec_audit_sysctl_runtime_equals "net.ipv4.tcp_syncookies" "1"; then FAIL106=1; fi
if [ $FAIL106 -eq 0 ]; then
    sec_audit_report_pass 106 "sysctl policy OK (net.ipv4.tcp_syncookies)"
else
    sec_audit_report_fail 106 "one or more sysctl values do not match policy (net.ipv4.tcp_syncookies)"
fi

# RULE107:
FAIL107=0
if ! sec_audit_sysctl_runtime_equals "net.ipv6.conf.all.accept_ra" "0"; then FAIL107=1; fi
if ! sec_audit_sysctl_runtime_equals "net.ipv6.conf.default.accept_ra" "0"; then FAIL107=1; fi
if [ $FAIL107 -eq 0 ]; then
    sec_audit_report_pass 107 "sysctl policy OK (net.ipv6.conf.all.accept_ra, net.ipv6.conf.default.accept_ra)"
else
    sec_audit_report_fail 107 "one or more sysctl values do not match policy (net.ipv6.conf.all.accept_ra, net.ipv6.conf.default.accept_ra)"
fi

# RULE108:
if rpm -q iptables iptables-services &>/dev/null; then
    sec_audit_report_pass 108 "iptables packages are installed"
else
    sec_audit_report_fail 108 "iptables or iptables-services package is not installed"
fi

# RULE109:
if systemctl is-enabled iptables &>/dev/null | grep -qE 'enabled|static'; then
    if systemctl is-active iptables &>/dev/null | grep -q '^active'; then
        sec_audit_report_pass 109 "iptables is enabled and active"
    else
        sec_audit_report_fail 109 "iptables enabled but not active"
    fi
else
    sec_audit_report_fail 109 "iptables is not enabled"
fi

# RULE110:
if rpm -q audit audit-libs &>/dev/null; then
    sec_audit_report_pass 110 "auditd packages are installed"
else
    sec_audit_report_fail 110 "audit audit-libs packages are not installed"
fi

# RULE111:
if systemctl is-enabled auditd 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active auditd 2>/dev/null | grep -q 'active'; then
        sec_audit_report_pass 111 "auditd service is enabled and active"
    else
        sec_audit_report_fail 111 "auditd is not enabled or not active"
    fi
else
    sec_audit_report_fail 111 "auditd is not enabled or not active"
fi

# RULE112:
if grep -Piqs '^\h*GRUB_CMDLINE_LINUX=\"([^#\n\r]+\h+)?\baudit_backlog_limit=\d+\b' /etc/default/grub 2>/dev/null; then
    sec_audit_report_pass 112 "audit_backlog_limit is configured"
else
    sec_audit_report_fail 112 "audit_backlog_limit is not set appropriately in audit rules or sysctl"
fi

# RULE113:
if grep -Piqs '^\h*GRUB_CMDLINE_LINUX=\"([^#\n\r]+\h+)?\baudit_backlog_limit=\d+\b' /etc/default/grub 2>/dev/null; then
    sec_audit_report_pass 113 "audit_backlog_limit is configured"
else
    sec_audit_report_fail 113 "audit_backlog_limit is not set appropriately in audit rules or sysctl"
fi

# RULE114:
if grep -Pqs '^\h*max_log_file\h*=\h*\d+\b' /etc/audit/auditd.conf 2>/dev/null; then
    sec_audit_report_pass 114 "audit log storage size is configured"
else
    sec_audit_report_fail 114 "max_log_file or rotation policy in auditd.conf does not meet policy"
fi

# RULE115:
if grep -Piqs '^\h*max_log_file_action\h*=\h*keep_logs\b' /etc/audit/auditd.conf 2>/dev/null; then
    sec_audit_report_pass 115 "audit logs are not automatically deleted"
else
    sec_audit_report_fail 115 "max_log_file_action or keep_logs policy allows silent deletion"
fi

# RULE116:
if grep -P '^\h*disk_full_action\h*=\h*(halt|single)\b' /etc/audit/auditd.conf 2>/dev/null; then
    if grep -P '^\h*disk_error_action\h*=\h*(syslog|single|halt)\b' /etc/audit/auditd.conf 2>/dev/null; then
        sec_audit_report_pass 116 "system is disabled when audit logs are full"
    else
        sec_audit_report_fail 116 "disk_full_action / space_left_action in auditd.conf does not meet policy"
    fi
else
    sec_audit_report_fail 116 "disk_full_action / space_left_action in auditd.conf does not meet policy"
fi

# RULE117:
if sec_audit_audit_rule_on_disk_and_loaded -q "path=/etc/sudoers"; then
    if sec_audit_audit_rule_on_disk_and_loaded -q "dir=/etc/sudoers.d"; then
        sec_audit_report_pass 117 "sudoers and sudoers.d watch rules present in audit.rules and loaded in kernel"
    else
        sec_audit_report_fail 117 "/etc/sudoers.d directory watch missing on disk or not loaded"
    fi
else
    sec_audit_report_fail 117 "/etc/sudoers file watch missing on disk or not loaded"
fi

# RULE118:
if sec_audit_audit_rule_on_disk_and_loaded -q "execve"; then
    sec_audit_report_pass 118 "execve auditing present on disk and loaded"
else
    sec_audit_report_fail 118 "actions as another user are not always logged (execve audit rule missing or not loaded)"
fi

# RULE119:
if [ -f /var/log/sudo.log ]; then
    if sec_audit_audit_rule_on_disk_and_loaded -q "path=/var/log/sudo.log"; then
        sec_audit_report_pass 119 "audit rule for /var/log/sudo.log on disk and loaded"
    else
        sec_audit_report_fail 119 "events that modify the sudo log file are not collected (audit watch for /var/log/sudo.log missing or not loaded)"
    fi
else
    sec_audit_report_fail 119 "events that modify the sudo log file are not collected (/var/log/sudo.log not found)"
fi

# RULE120:
if sec_audit_audit_rule_on_disk_and_loaded -E -q 'adjtimex|settimeofday|clock_settime|stime'; then
    sec_audit_report_pass 120 "time-change events are collected (audit rules on disk and loaded)"
else
    sec_audit_report_fail 120 "events that modify date and time information are not collected"
fi

# RULE121:
if command -v auditctl &>/dev/null; then
    if sec_audit_audit_rule_on_disk_and_loaded -E -q 'path=/usr/bin/sudo|path=/usr/bin/su|path=/bin/su'; then
        sec_audit_report_pass 121 "privileged command execution (sudo/su) audited on disk and loaded"
    else
        sec_audit_report_fail 121 "use of privileged commands is not being collected"
    fi
else
    sec_audit_report_fail 121 "use of privileged commands is not being collected"
fi

# RULE122:
if sec_audit_audit_rule_on_disk_and_loaded -q "path=/etc/shadow"; then
    if sec_audit_audit_rule_on_disk_and_loaded -q "path=/etc/gshadow"; then
        sec_audit_report_pass 122 "shadow and gshadow watches on disk and loaded"
    else
        sec_audit_report_fail 122 "events that modify /etc/gshadow are not collected (watch missing on disk or not loaded)"
    fi
else
    sec_audit_report_fail 122 "events that modify /etc/shadow are not collected (watch missing on disk or not loaded)"
fi

# RULE123:
if sec_audit_audit_rule_on_disk_and_loaded -q "dir=/etc/NetworkManager/"; then
    sec_audit_report_pass 123 "NetworkManager directory watch on disk and loaded"
else
    sec_audit_report_fail 123 "events that modify /etc/NetworkManager directory are not collected"
fi

# RULE124:
if sec_audit_audit_rule_on_disk_and_loaded -E -q 'EACCES|EPERM'; then
    sec_audit_report_pass 124 "unsuccessful access (EACCES/EPERM) auditing on disk and loaded"
else
    sec_audit_report_fail 124 "unsuccessful file access attempts are not collected"
fi

# RULE125:
if sec_audit_audit_rule_on_disk_and_loaded -E -q 'lastlog|faillock'; then
    sec_audit_report_pass 125 "login/logout related auditing on disk and loaded"
else
    sec_audit_report_fail 125 "login and logout events are not collected"
fi

# RULE126:
if sec_audit_audit_rule_on_disk_and_loaded -q "unlink"; then
    sec_audit_report_pass 126 "unlink auditing on disk and loaded"
else
    sec_audit_report_fail 126 "unlink file deletion events by users are not collected"
fi

# RULE127:
if sec_audit_audit_rule_on_disk_and_loaded -q "/usr/bin/chcon"; then
    sec_audit_report_pass 127 "audit rules for chcon on disk and loaded"
else
    sec_audit_report_fail 127 "attempts to use chcon are not recorded (audit watch missing or not loaded)"
fi

# RULE128:
if sec_audit_audit_rule_on_disk_and_loaded -q "/usr/bin/setfacl"; then
    sec_audit_report_pass 128 "audit rules for setfacl on disk and loaded"
else
    sec_audit_report_fail 128 "attempts to use setfacl are not recorded (audit watch missing or not loaded)"
fi

# RULE129:
if sec_audit_audit_rule_on_disk_and_loaded -q "/usr/bin/chacl"; then
    sec_audit_report_pass 129 "audit rules for chacl on disk and loaded"
else
    sec_audit_report_fail 129 "attempts to use chacl are not recorded (audit watch missing or not loaded)"
fi

# RULE130:
if sec_audit_audit_rule_on_disk_and_loaded -q "/usr/bin/usermod"; then
    sec_audit_report_pass 130 "audit rules for usermod on disk and loaded"
else
    sec_audit_report_fail 130 "attempts to use usermod are not recorded (audit watch missing or not loaded)"
fi

# RULE131:
if sec_audit_audit_rule_on_disk_and_loaded -- '-e 2'; then
    sec_audit_report_pass 131 "the audit configuration is immutable (-e 2 loaded and on disk)"
elif sec_audit_audit_rules_file_grep -q -- '-e 2'; then
    sec_audit_report_fail 131 "Immutable rule (-e 2) is on disk but not loaded (auditctl -l)"
elif sec_audit_auditctl_list_grep -q -- '-e 2'; then
    sec_audit_report_fail 131 "Immutable rule (-e 2) is loaded but missing from on-disk audit rules"
else
    sec_audit_report_fail 131 "Immutable rule (-e 2) is missing from loaded and on-disk audit rules"
fi
# RULE132:
if augenrules --check 2>/dev/null | grep -q "No change"; then
    sec_audit_report_pass 132 "the running and on disk configuration is the same"
else
    sec_audit_report_fail 132 "Loaded audit rules differ from on-disk rules (augenrules --check)"
fi

# RULE133:
if rpm -q rsyslog &>/dev/null; then
    sec_audit_report_pass 133 "rsyslog is installed"
else
    sec_audit_report_fail 133 "rsyslog package is not installed"
fi

# RULE134:
if systemctl is-enabled rsyslog 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active rsyslog.service 2>/dev/null | grep -q 'active'; then
        sec_audit_report_pass 134 "rsyslog service is enabled and active"
    else
        sec_audit_report_fail 134 "rsyslog is not enabled or not active"
    fi
else
    sec_audit_report_fail 134 "rsyslog is not enabled or not active"
fi

# RULE135:
if grep -Pqs '^\h*\$FileCreateMode\h+0[0,2,4,6][0,2,4]0\b' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null; then
    sec_audit_report_pass 135 "rsyslog log file creation mode is configured"
else
    sec_audit_report_fail 135 "rsyslog $FileCreateMode (or equivalent) does not meet policy"
fi

# RULE136:
if command -v rsyslogd &>/dev/null; then
    if [ -f /etc/rsyslog.conf ] && grep -v "^#" /etc/rsyslog.conf 2>/dev/null | grep -q "^\*\.\*\|^auth\|^mail\|^cron"; then
        sec_audit_report_pass 136 "rsyslog logging is configured"
    else
        sec_audit_report_fail 136 "rsyslog logging is not properly configured"
    fi
else
    sec_audit_report_pass 136 "rsyslog is not installed"
fi

# RULE137:
if grep -rE '^[^#[:space:]].*@@[^@[:space:]]' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -qvE '@@127\.0\.0\.1|@@localhost'; then
    sec_audit_report_pass 137 "rsyslog forwards logs to a remote host (@@ target in rsyslog configuration)"
elif grep -rE '^[^#[:space:]].*[^@]@[^@[:space:]]' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -qvE '@127\.0\.0\.1|@localhost'; then
    sec_audit_report_pass 137 "rsyslog forwards logs to a remote host (@ target in rsyslog configuration)"
else
    sec_audit_report_fail 137 "rsyslog is not configured to send logs to a remote log host"
fi

# RULE138:
if rpm -q systemd-journal-remote &>/dev/null; then
    sec_audit_report_pass 138 "systemd-journal-remote is installed"
else
    sec_audit_report_fail 138 "systemd-journal-remote package is not installed (if required by policy)"
fi

# RULE139:
if [ -f /etc/systemd/journal-upload.conf ] && grep -qE '^URL=' /etc/systemd/journal-upload.conf 2>/dev/null; then
    sec_audit_report_pass 139 "systemd-journal-upload URL is configured"
elif rpm -q systemd-journal-remote &>/dev/null; then
    sec_audit_report_pass 139 "systemd-journal-remote package installed (remote logging stack available)"
else
    sec_audit_report_fail 139 "systemd-journal-remote/upload is not configured"
fi

# RULE140:
if systemctl is-enabled systemd-journal-upload.service 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active systemd-journal-upload.service 2>/dev/null | grep -q 'active'; then
        sec_audit_report_pass 140 "systemd-journal-upload is enabled and active"
    else
        sec_audit_report_fail 140 "systemd-journal-upload is not enabled or not active"
    fi
else
    sec_audit_report_fail 140 "systemd-journal-upload is not enabled or not active"
fi

# RULE141:
if systemctl is-enabled systemd-journal-remote.socket systemd-journal-remote.service 2>/dev/null | grep -q 'enabled'; then
    sec_audit_report_fail 141 "systemd-journal-remote socket/service is enabled or active but should be disabled"
elif systemctl is-active systemd-journal-remote.socket systemd-journal-remote.service 2>/dev/null | grep -q 'active'; then
    sec_audit_report_fail 141 "systemd-journal-remote socket/service is enabled or active but should be disabled"
else
    sec_audit_report_pass 141 "systemd-journal-remote service is not in use"
fi

# RULE142:
if systemctl is-enabled systemd-journald.service 2>/dev/null | grep -q 'static'; then
    if systemctl is-active systemd-journald.service 2>/dev/null | grep -q 'active'; then
        sec_audit_report_pass 142 "journald service is active"
    else
        sec_audit_report_fail 142 "systemd-journald is not active or not in expected state"
    fi
else
    sec_audit_report_fail 142 "systemd-journald is not active or not in expected state"
fi

# RULE143:
if grep -q "^SystemMaxUse\|^SystemMaxFileSize\|^MaxFileSec" /etc/systemd/journald.conf 2>/dev/null; then
    sec_audit_report_pass 143 "journald log file rotation is configured"
else
    sec_audit_report_fail 143 "journald log file rotation limits not configured"
fi

# RULE144:
if systemctl is-active --quiet rsyslog 2>/dev/null; then
    if systemctl is-active --quiet systemd-journald 2>/dev/null; then
        sec_audit_report_fail 144 "more than one logging system is in use (both rsyslog and journald are active)"
    else
        sec_audit_report_pass 144 "only one logging system is in use (rsyslog)"
    fi
elif systemctl is-active --quiet systemd-journald 2>/dev/null; then
    sec_audit_report_pass 144 "only one logging system is in use (journald)"
else
    sec_audit_report_fail 144 "no logging system is active (neither rsyslog nor journald)"
fi

# RULE145:
if systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -qE '^ForwardToSyslog=yes'; then
    sec_audit_report_fail 145 "journald ForwardToSyslog=yes (should be no for dedicated journald)"
else
    sec_audit_report_pass 145 "journald not forwarding to rsyslog"
fi

# RULE146:
if grep -q "^SystemMaxUse\|^SystemMaxFileSize\|^MaxFileSec" /etc/systemd/journald.conf 2>/dev/null; then
    sec_audit_report_pass 146 "journald log file rotation is configured"
else
    sec_audit_report_fail 146 "journald log file rotation limits not configured"
fi

# RULE147:
if [ -d /var/log/journal ]; then
    DIR_PERM=$(stat -c '%a' /var/log/journal 2>/dev/null)
    if [ "$DIR_PERM" = "755" ] || [ "$DIR_PERM" = "750" ]; then
        sec_audit_report_pass 147 "journald log file access is configured (directory mode: $DIR_PERM)"
    else
        sec_audit_report_fail 147 "journald log directory has insecure permissions: $DIR_PERM"
    fi
else
    sec_audit_report_pass 147 "journald log file access is configured (directory not found)"
fi

# RULE148:
if systemctl is-enabled crond.service 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active crond.service 2>/dev/null | grep -q 'active'; then
        sec_audit_report_pass 148 "cron daemon is enabled and active"
    else
        sec_audit_report_fail 148 "crond service is not enabled or not active"
    fi
else
    sec_audit_report_fail 148 "crond service is not enabled or not active"
fi

# RULE149:
if stat -Lc '%a' /etc/crontab 2>/dev/null | grep -q '^[0-6]00$'; then
    if stat -Lc '%U:%G' /etc/crontab 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 149 "access to /etc/crontab is configured"
    else
        sec_audit_report_fail 149 "File /etc/crontab permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 149 "File /etc/crontab permissions or ownership not correct"
fi

# RULE150:
if stat -Lc '%a' /etc/cron.hourly 2>/dev/null | grep -q '^700$'; then
    if stat -Lc '%U:%G' /etc/cron.hourly 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 150 "access to /etc/cron.hourly is configured"
    else
        sec_audit_report_fail 150 "File /etc/cron.hourly permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 150 "File /etc/cron.hourly permissions or ownership not correct"
fi

# RULE151:
if stat -Lc '%a' /etc/cron.daily 2>/dev/null | grep -q '^700$'; then
    if stat -Lc '%U:%G' /etc/cron.daily 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 151 "access to /etc/cron.daily is configured"
    else
        sec_audit_report_fail 151 "File /etc/cron.daily permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 151 "File /etc/cron.daily permissions or ownership not correct"
fi

# RULE152:
if stat -Lc '%a' /etc/cron.weekly 2>/dev/null | grep -q '^700$'; then
    if stat -Lc '%U:%G' /etc/cron.weekly 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 152 "access to /etc/cron.weekly is configured"
    else
        sec_audit_report_fail 152 "File /etc/cron.weekly permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 152 "File /etc/cron.weekly permissions or ownership not correct"
fi

# RULE153:
if stat -Lc '%a' /etc/cron.monthly 2>/dev/null | grep -q '^700$'; then
    if stat -Lc '%U:%G' /etc/cron.monthly 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 153 "access to /etc/cron.monthly is configured"
    else
        sec_audit_report_fail 153 "File /etc/cron.monthly permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 153 "File /etc/cron.monthly permissions or ownership not correct"
fi

# RULE154:
if stat -Lc '%a' /etc/cron.yearly 2>/dev/null | grep -q '^700$'; then
    if stat -Lc '%U:%G' /etc/cron.yearly 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 154 "access to /etc/cron.yearly is configured"
    else
        sec_audit_report_fail 154 "File /etc/cron.yearly permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 154 "File /etc/cron.yearly permissions or ownership not correct"
fi

# RULE155:
if stat -Lc '%a' /etc/cron.d 2>/dev/null | grep -q '^700$'; then
    if stat -Lc '%U:%G' /etc/cron.d 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 155 "access to /etc/cron.d is configured"
    else
        sec_audit_report_fail 155 "File /etc/cron.d permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 155 "File /etc/cron.d permissions or ownership not correct"
fi

# RULE156:
if [ -e /etc/cron.allow ]; then
    if stat -Lc '%a' /etc/cron.allow 2>/dev/null | grep -qE '^640$'; then
        if stat -Lc '%U' /etc/cron.allow 2>/dev/null | grep -q 'root'; then
            if stat -Lc '%G' /etc/cron.allow 2>/dev/null | grep -qE 'root|crontab'; then
                sec_audit_report_pass 156 "access to crontab is configured"
            else
                sec_audit_report_fail 156 "File crontab permissions or ownership not correct"
            fi
        else
            sec_audit_report_fail 156 "File crontab permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 156 "File crontab permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 156 "File crontab permissions or ownership not correct"
fi

# RULE157:
if stat -Lc '%a' /etc/ssh/sshd_config 2>/dev/null | grep -q '^600$'; then
    if stat -Lc '%U:%G' /etc/ssh/sshd_config 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 157 "access to /etc/ssh/sshd_config is configured"
    else
        sec_audit_report_fail 157 "File /etc/ssh/sshd_config permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 157 "File /etc/ssh/sshd_config permissions or ownership not correct"
fi

if ! sec_audit_sshd_effective_usable; then
    for _sshn in 158 159 160 161 162 163 164 165 166 167 168 169 170 171 172 173; do
        sec_audit_report_fail "$_sshn" "unable_to_evaluate: sshd -T produced no effective configuration"
    done
else
# RULE158:
PRIV_KEYS=$(sec_audit_sshd_effective_config | awk '$1=="hostkey" {print $2}')
FAIL158=0
for key in $PRIV_KEYS; do
    if [ -f "$key" ]; then
        if ! stat -Lc '%a' "$key" 2>/dev/null | grep -q '^600$'; then
            FAIL158=1
        fi
        if ! stat -Lc '%U:%G' "$key" 2>/dev/null | grep -q '^root:root$'; then
            FAIL158=1
        fi
    else
        FAIL158=1
    fi
done
if [ $FAIL158 -eq 0 ]; then
    sec_audit_report_pass 158 "access to SSH private host key files is configured"
else
    sec_audit_report_fail 158 "File SSH private host key files permissions or ownership not correct"
fi

# RULE159:
PUB_KEYS=$(sec_audit_sshd_effective_config | awk '$1=="hostkey" {print $2".pub"}')
FAIL159=0
for key in $PUB_KEYS; do
    if [ -f "$key" ]; then
        if ! stat -Lc '%a' "$key" 2>/dev/null | grep -qE '^[0-6]44$'; then
            FAIL159=1
        fi
        if ! stat -Lc '%U:%G' "$key" 2>/dev/null | grep -q '^root:root$'; then
            FAIL159=1
        fi
    else
        FAIL159=1
    fi
done
if [ $FAIL159 -eq 0 ]; then
    sec_audit_report_pass 159 "access to SSH public host key files is configured"
else
    sec_audit_report_fail 159 "File SSH public host key files permissions or ownership not correct"
fi

# RULE160:
if sec_audit_sshd_config_grep -Piqs '^\h*(allow|deny)(users|groups)\h+\H+'; then
    sec_audit_report_pass 160 "sshd access is configured"
else
    sec_audit_report_fail 160 "sshd access controls (AllowUsers/DenyUsers/AllowGroups/DenyGroups) are not set as required"
fi

# RULE161:
if sec_audit_sshd_config_grep -Piqs '^banner\h+\/\H+'; then
    sec_audit_report_pass 161 "sshd Banner is configured"
else
    sec_audit_report_fail 161 "sshd Banner does not meet the required policy (see sshd -T)"
fi

# RULE162:
if sec_audit_sshd_config_grep -Piqs '^ciphers\h+\"?([^#\n\r]+,)?((3des|blowfish|cast128|aes(128|192|256))-cbc|arcfour(128|256)?|rijndael-cbc@lysator\.liu\.se)\b'; then
    sec_audit_report_fail 162 "sshd Ciphers allow weak or legacy algorithms (see sshd -T)"
else
    sec_audit_report_pass 162 "sshd Ciphers are configured"
fi

# RULE163:
if sec_audit_sshd_config_grep -Piqs 'clientaliveinterval\s+([1-9]|[1-9][0-9]+)'; then
    if sec_audit_sshd_config_grep -Piqs 'clientalivecountmax\s+([1-9]|[1-9][0-9]+)'; then
        sec_audit_report_pass 163 "sshd ClientAliveInterval and ClientAliveCountMax are configured"
    else
        sec_audit_report_fail 163 "sshd ClientAliveInterval and ClientAliveCountMax are not configured as required (see sshd -T)"
    fi
else
    sec_audit_report_fail 163 "sshd ClientAliveInterval and ClientAliveCountMax are not configured as required (see sshd -T)"
fi

# RULE164:
if sec_audit_sshd_config_grep -iq 'disableforwarding yes'; then
    sec_audit_report_pass 164 "sshd DisableForwarding is enabled"
else
    sec_audit_report_fail 164 "sshd DisableForwarding is not enabled in effective sshd -T output"
fi

# RULE165:
if sec_audit_sshd_config_grep -iq 'gssapiauthentication no'; then
    sec_audit_report_pass 165 "sshd GSSAPIAuthentication is disabled"
else
    sec_audit_report_fail 165 "sshd GSSAPIAuthentication is not disabled in effective sshd -T output"
fi

# RULE166:
if sec_audit_sshd_config_grep -iq 'hostbasedauthentication no'; then
    sec_audit_report_pass 166 "sshd HostbasedAuthentication is disabled"
else
    sec_audit_report_fail 166 "sshd HostbasedAuthentication is not disabled in effective sshd -T output"
fi

# RULE167:
if sec_audit_sshd_config_grep -iq 'ignorerhosts yes'; then
    sec_audit_report_pass 167 "sshd IgnoreRhosts is enabled"
else
    sec_audit_report_fail 167 "sshd IgnoreRhosts is not enabled in effective sshd -T output"
fi

# RULE168:
if sec_audit_sshd_config_grep -Piqs 'kexalgorithms\h+([^#\n\r]+,)?(diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1)\b'; then
    sec_audit_report_fail 168 "sshd KexAlgorithms does not meet the required policy (see sshd -T)"
else
    sec_audit_report_pass 168 "sshd KexAlgorithms is configured"
fi

# RULE169:
if sec_audit_sshd_config_grep -iq 'loglevel VERBOSE\|loglevel INFO'; then
    sec_audit_report_pass 169 "sshd LogLevel is configured"
else
    sec_audit_report_fail 169 "sshd LogLevel does not meet the required policy (see sshd -T)"
fi

# RULE170:
if sec_audit_sshd_config_grep -Piqs 'macs\h+([^#\n\r]+,)?(hmac-md5|hmac-md5-96|hmac-ripemd160|hmac-sha1-96|umac-64@openssh\.com|hmac-md5-etm@openssh\.com|hmac-md5-96-etm@openssh\.com|hmac-ripemd160-etm@openssh\.com|hmac-sha1-96-etm@openssh\.com|umac-64-etm@openssh\.com|umac-128-etm@openssh\.com)\b'; then
    sec_audit_report_fail 170 "sshd MACs allow weak or legacy algorithms (see sshd -T)"
else
    sec_audit_report_pass 170 "sshd MACs are configured"
fi

# RULE171:
if sec_audit_sshd_config_grep -Piqs 'maxauthtries\s+[1-4]\b'; then
    sec_audit_report_pass 171 "sshd MaxAuthTries is configured"
else
    sec_audit_report_fail 171 "sshd MaxAuthTries does not meet the required policy (see sshd -T)"
fi

# RULE172:
if sec_audit_sshd_config_grep -iq 'permitemptypasswords no'; then
    sec_audit_report_pass 172 "sshd PermitEmptyPasswords is disabled"
else
    sec_audit_report_fail 172 "sshd PermitEmptyPasswords is not disabled in effective sshd -T output"
fi

# RULE173:
if sec_audit_sshd_config_grep -iq 'permitrootlogin no'; then
    sec_audit_report_pass 173 "sshd PermitRootLogin is disabled"
else
    sec_audit_report_fail 173 "sshd PermitRootLogin is not disabled in effective sshd -T output"
fi

fi

# RULE174:
if rpm -q sudo &>/dev/null; then
    sec_audit_report_pass 174 "sudo is installed"
else
    sec_audit_report_fail 174 "sudo package is not installed"
fi

# RULE175:
if grep -rPiq '^\h*Defaults\h+([^#\n\r]+,\h*)?use_pty\b' /etc/sudoers* 2>/dev/null; then
    if ! grep -rPiq '^\h*Defaults\h+([^#\n\r]+,\h*)?!use_pty\b' /etc/sudoers* 2>/dev/null; then
        sec_audit_report_pass 175 "sudo commands use pty"
    else
        sec_audit_report_fail 175 "sudo is not configured to require a pseudo-terminal (use_pty)"
    fi
else
    sec_audit_report_fail 175 "sudo is not configured to require a pseudo-terminal (use_pty)"
fi

# RULE176:
if grep -rPsi "^\h*Defaults\h+([^#]+,\h*)?logfile\h*=\h*(\"|\')?\H+(\"|\')?(,\h*\H+\h*)*\h*(#.*)?$" /etc/sudoers* 2>/dev/null; then
    sec_audit_report_pass 176 "sudo log file exists"
else
    sec_audit_report_fail 176 "sudo log file is missing or not configured"
fi

# RULE177:
if grep -r "^[^#].*NOPASSWD" /etc/sudoers* 2>/dev/null; then
    sec_audit_report_fail 177 "NOPASSWD or password-less sudo rules violate escalation policy"
else
    sec_audit_report_pass 177 "users must provide password for escalation"
fi

# RULE178:
if grep -rPiq '^\h*Defaults\h+([^#\n\r]+,\h*)?!authenticate\b' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -q .; then
    sec_audit_report_fail 178 "sudo !authenticate disables re-authentication globally"
else
    sec_audit_report_pass 178 "re-authentication for privilege escalation is not disabled globally"
fi

# RULE179:
TIMEOUT=$(sudo -V 2>/dev/null | grep "Authentication timestamp timeout:" | awk '{print $4}')
TIMEOUT_INT=${TIMEOUT%%.*}
if [ -n "$TIMEOUT_INT" ]; then
    if [ "$TIMEOUT_INT" -ge 0 ] && [ "$TIMEOUT_INT" -le 15 ]; then
        sec_audit_report_pass 179 "sudo timestamp_timeout is configured"
    else
        sec_audit_report_fail 179 "sudo timestamp_timeout is not set within the required range"
    fi
else
    sec_audit_report_pass 179 "sudo timestamp_timeout is configured"
fi

# RULE180:
if grep -Piqs '^\h*auth\h+(?:required|requisite)\h+pam_wheel\.so\h+(?:[^#\n\r]+\h+)?((?!\2)(use_uid\b|group=\H+\b))\h+(?:[^#\n\r]+\h+)?((?!\1)(use_uid\b|group=\H+\b))(\h+.*)?$' /etc/pam.d/su 2>/dev/null; then
    GROUP=$(grep -Pi '^\h*auth\h+(?:required|requisite)\h+pam_wheel\.so\h+(?:[^#\n\r]+\h+)?((?!\2)(use_uid\b|group=\H+\b))\h+(?:[^#\n\r]+\h+)?((?!\1)(use_uid\b|group=\H+\b))(\h+.*)?$' /etc/pam.d/su 2>/dev/null | grep -oP 'group=\K\H+')
    if [ -n "$GROUP" ]; then
        if ! grep "^$GROUP:" /etc/group 2>/dev/null | grep -q ":$GROUP:x:"; then
            sec_audit_report_pass 180 "access to the su command is restricted"
        else
            sec_audit_report_fail 180 "su is not restricted to the wheel group in PAM configuration"
        fi
    else
        sec_audit_report_pass 180 "access to the su command is restricted"
    fi
else
    sec_audit_report_fail 180 "su is not restricted to the wheel group in PAM configuration"
fi

# RULE181:
if sec_audit_have_bin authselect; then
    if authselect current 2>/dev/null | grep -q with-faillock; then
        sec_audit_report_pass 181 "authselect profile includes with-faillock"
    else
        sec_audit_report_fail 181 "authselect current profile does not include with-faillock"
    fi
else
    sec_audit_report_fail 181 "authselect command not found"
fi

# RULE182:
if grep -Pqs '^\h*minlen\h*=\h*(1[4-9]|[2-9][0-9]|[1-9][0-9]{2,})\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null; then
    sec_audit_report_pass 182 "password length is configured"
else
    sec_audit_report_fail 182 "pwquality minlen (or equivalent) is not set to at least 14"
fi

# RULE183:
if grep -Pqs 'deny\h*=\h*[1-5]\b' /etc/security/faillock.conf 2>/dev/null; then
    sec_audit_report_pass 183 "password failed attempts lockout is configured"
else
    sec_audit_report_fail 183 "faillock deny threshold is not configured in /etc/security/faillock.conf"
fi

# RULE184:
if grep -Psi 'remember\h*=\h*(2[4-9]|[3-9][0-9]|[1-9][0-9]{2,})\b' /etc/security/pwhistory.conf 2>/dev/null; then
    sec_audit_report_pass 184 "password history remember is configured"
elif sec_audit_pam_stacks_grep_Pi '^\h*password\h+([^#\n\r]+)\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?remember=[0-9]+'; then
    _r=$(sec_audit_pam_stack_paths_password_system | while IFS= read -r _p; do
        [[ -f "$_p" ]] || continue
        grep -Po 'remember=\K[0-9]+' "$_p" 2>/dev/null | head -n1 && break
    done)
    if [[ "${_r:-0}" -ge 24 ]]; then
        sec_audit_report_pass 184 "password history remember is configured (authselect/PAM stack)"
    else
        sec_audit_report_fail 184 "pwhistory remember value is below policy or not configured"
    fi
else
    sec_audit_report_fail 184 "pwhistory remember value is below policy or not configured"
fi
# RULE185:
if grep -Pqs '^\h*ENCRYPT_METHOD\h+(SHA512|YESCRYPT)\b' /etc/login.defs 2>/dev/null; then
    sec_audit_report_pass 185 "strong password hashing algorithm is configured"
else
    sec_audit_report_fail 185 "ENCRYPT_METHOD in /etc/login.defs does not use a strong hashing algorithm"
fi

# RULE186:
if grep -Pqs '^\h*PASS_MAX_DAYS\h+(36[0-5]|3[0-5][0-9]|[1-2][0-9][0-9]|[1-9][0-9]|[1-9])\b' /etc/login.defs 2>/dev/null; then
    if ! awk -F: '($2~/^\$.+\$/) {if($5 > 365 || $5 < 1)print}' /etc/shadow 2>/dev/null | grep -q '.'; then
        sec_audit_report_pass 186 "password expiration is configured"
    else
        sec_audit_report_fail 186 "PASS_MAX_DAYS or per-user shadow MAX exceeds policy or is unset"
    fi
else
    sec_audit_report_fail 186 "PASS_MAX_DAYS or per-user shadow MAX exceeds policy or is unset"
fi

# RULE187:
if grep -q "^PASS_MIN_DAYS" /etc/login.defs 2>/dev/null; then
    MIN_DAYS=$(grep "^PASS_MIN_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
    if [ "$MIN_DAYS" -ge 7 ] 2>/dev/null; then
        sec_audit_report_pass 187 "Minimum password days is configured"
    else
        sec_audit_report_fail 187 "Minimum password days is too low (recommended 7+)"
    fi
else
    sec_audit_report_fail 187 "Minimum password days is not configured"
fi

# RULE188:
if grep -Pqs '^\h*PASS_WARN_AGE\h+([7-9]|[1-9][0-9]+)\b' /etc/login.defs 2>/dev/null; then
    if ! awk -F: '($2~/^\$.+\$/) {if($6 < 7)print}' /etc/shadow 2>/dev/null | grep -q '.'; then
        sec_audit_report_pass 188 "password expiration warning days is configured"
    else
        sec_audit_report_fail 188 "PASS_WARN_AGE is not set within policy in /etc/login.defs"
    fi
else
    sec_audit_report_fail 188 "PASS_WARN_AGE is not set within policy in /etc/login.defs"
fi

# RULE189:
if useradd -D 2>/dev/null | grep INACTIVE | cut -d= -f2 | grep -qE '^([1-9]|[1-4][0-9]|45)$'; then
    if ! awk -F: '($2~/^\$.+\$/) {if($7 > 45 || $7 < 0)print}' /etc/shadow 2>/dev/null | grep -q '.'; then
        sec_audit_report_pass 189 "inactive password lock is configured"
    else
        sec_audit_report_fail 189 "useradd INACTIVE or inactive lock policy is not configured"
    fi
else
    sec_audit_report_fail 189 "useradd INACTIVE or inactive lock policy is not configured"
fi

# RULE190:
FAIL190=0
while IFS=: read -r user pass last_change rest; do
    if [ -n "$last_change" ] && [ "$last_change" -gt 0 ] 2>/dev/null; then
        current_date=$(date +%s)
        last_change_seconds=$((last_change * 86400))
        if [ "$last_change_seconds" -gt "$current_date" ]; then
            sec_audit_report_fail 190 "User $user has password change date in the future"
            FAIL190=1
        fi
    fi
done < /etc/shadow 2>/dev/null
if [ $FAIL190 -eq 0 ]; then
    sec_audit_report_pass 190 "All users last password change date is in the past"
fi

# RULE191:
VALID_SHELLS=$(awk -F\/ '$NF != "nologin" && $NF != "false" {print}' /etc/shells 2>/dev/null | sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' -)
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs 2>/dev/null)
if awk -v pat="^($VALID_SHELLS)$" -v uidmin="$UID_MIN" -F: '($1!~/^(root|halt|sync|shutdown|nfsnobody)$/ && ($3<uidmin || $3==65534) && $NF ~ pat) {print}' /etc/passwd 2>/dev/null | grep -q '.'; then
    sec_audit_report_fail 191 "System accounts still have an interactive login shell"
else
    sec_audit_report_pass 191 "system accounts do not have a valid login shell"
fi

# RULE192:
if grep -Pqs '^\h*([^#\n\r]+)?\/nologin\b' /etc/shells 2>/dev/null; then
    sec_audit_report_fail 192 "nologin appears in /etc/shells"
else
    sec_audit_report_pass 192 "nologin is not listed in /etc/shells"
fi

# RULE193:
if awk -F: '$3=="0"{print $1":"$3}' /etc/group 2>/dev/null | grep -q "root:0"; then
    if [ $(awk -F: '$3=="0"{print}' /etc/group 2>/dev/null | wc -l) -eq 1 ]; then
        sec_audit_report_pass 193 "group root is the only GID 0 group"
    else
        sec_audit_report_fail 193 "Multiple groups share GID 0"
    fi
else
    sec_audit_report_fail 193 "Multiple groups share GID 0"
fi

# RULE194:
if grep -Pqs '^\h*umask\h+0?(?:[0-7][2-7]7)\b' /etc/login.defs 2>/dev/null; then
    if grep -Pqs '^\h*umask\h+0?027\b' /etc/profile.d/*.sh 2>/dev/null; then
        sec_audit_report_pass 194 "default user umask is configured"
    else
        sec_audit_report_fail 194 "Default user umask 027 is not set in /etc/profile or profile.d"
    fi
else
    sec_audit_report_fail 194 "Default user umask 027 is not set in /etc/profile or profile.d"
fi

# RULE195:
if [ -e /etc/passwd- ]; then
    if stat -Lc '%a' /etc/passwd- 2>/dev/null | grep -qE '^[0-6]44$'; then
        if stat -Lc '%U:%G' /etc/passwd- 2>/dev/null | grep -q '^root:root$'; then
            sec_audit_report_pass 195 "access to /etc/passwd- is configured"
        else
            sec_audit_report_fail 195 "File /etc/passwd- permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 195 "File /etc/passwd- permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 195 "/etc/passwd- is absent (optional file; permission check skipped)"
fi

# RULE196:
if stat -Lc '%a' /etc/group 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' /etc/group 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 196 "access to /etc/group is configured"
    else
        sec_audit_report_fail 196 "File /etc/group permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 196 "File /etc/group permissions or ownership not correct"
fi

# RULE197:
if [ -e /etc/group- ]; then
    if stat -Lc '%a' /etc/group- 2>/dev/null | grep -qE '^[0-6]44$'; then
        if stat -Lc '%U:%G' /etc/group- 2>/dev/null | grep -q '^root:root$'; then
            sec_audit_report_pass 197 "access to /etc/group- is configured"
        else
            sec_audit_report_fail 197 "File /etc/group- permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 197 "File /etc/group- permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 197 "/etc/group- is absent (optional file; permission check skipped)"
fi

# RULE198:
if stat -Lc '%a' /etc/shadow 2>/dev/null | grep -qE '^[0-6]40$'; then
    if stat -Lc '%U' /etc/shadow 2>/dev/null | grep -q 'root'; then
        if stat -Lc '%G' /etc/shadow 2>/dev/null | grep -qE 'root|shadow'; then
            sec_audit_report_pass 198 "access to /etc/shadow is configured"
        else
            sec_audit_report_fail 198 "File /etc/shadow permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 198 "File /etc/shadow permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 198 "File /etc/shadow permissions or ownership not correct"
fi

# RULE199:
if [ -e /etc/shadow- ]; then
    if stat -Lc '%a' /etc/shadow- 2>/dev/null | grep -qE '^[0-6]40$'; then
        if stat -Lc '%U' /etc/shadow- 2>/dev/null | grep -q 'root'; then
            if stat -Lc '%G' /etc/shadow- 2>/dev/null | grep -qE 'root|shadow'; then
                sec_audit_report_pass 199 "access to /etc/shadow- is configured"
            else
                sec_audit_report_fail 199 "File /etc/shadow- permissions or ownership not correct"
            fi
        else
            sec_audit_report_fail 199 "File /etc/shadow- permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 199 "File /etc/shadow- permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 199 "/etc/shadow- is absent (optional file; permission check skipped)"
fi

# RULE200:
if [ -e /etc/gshadow ]; then
    if stat -Lc '%a' /etc/gshadow 2>/dev/null | grep -qE '^[0-6]40$'; then
        if stat -Lc '%U' /etc/gshadow 2>/dev/null | grep -q 'root'; then
            if stat -Lc '%G' /etc/gshadow 2>/dev/null | grep -qE 'root|shadow'; then
                sec_audit_report_pass 200 "access to /etc/gshadow is configured"
            else
                sec_audit_report_fail 200 "File /etc/gshadow permissions or ownership not correct"
            fi
        else
            sec_audit_report_fail 200 "File /etc/gshadow permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 200 "File /etc/gshadow permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 200 "/etc/gshadow is absent (optional file; permission check skipped)"
fi

# RULE201:
if [ -e /etc/gshadow- ]; then
    if stat -Lc '%a' /etc/gshadow- 2>/dev/null | grep -qE '^[0-6]40$'; then
        if stat -Lc '%U' /etc/gshadow- 2>/dev/null | grep -q 'root'; then
            if stat -Lc '%G' /etc/gshadow- 2>/dev/null | grep -qE 'root|shadow'; then
                sec_audit_report_pass 201 "access to /etc/gshadow- is configured"
            else
                sec_audit_report_fail 201 "File /etc/gshadow- permissions or ownership not correct"
            fi
        else
            sec_audit_report_fail 201 "File /etc/gshadow- permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 201 "File /etc/gshadow- permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 201 "/etc/gshadow- is absent (optional file; permission check skipped)"
fi

# RULE202:
if stat -Lc '%a' /etc/shells 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' /etc/shells 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 202 "access to /etc/shells is configured"
    else
        sec_audit_report_fail 202 "File /etc/shells permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 202 "File /etc/shells permissions or ownership not correct"
fi

# RULE203:
if [ -e /etc/security/opasswd ]; then
    if stat -Lc '%a' /etc/security/opasswd 2>/dev/null | grep -q '^600$'; then
        if stat -Lc '%U:%G' /etc/security/opasswd 2>/dev/null | grep -q '^root:root$'; then
            sec_audit_report_pass 203 "access to /etc/security/opasswd is configured"
        else
            sec_audit_report_fail 203 "File /etc/security/opasswd permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 203 "File /etc/security/opasswd permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 203 "/etc/security/opasswd is absent (optional file; permission check skipped)"
fi

# RULE204:
CRITICAL_PATHS="/bin /sbin /usr/bin /usr/sbin /etc /var /home"
if sec_audit_find_hit_timeout sec_audit_soft_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type f -perm -0002 -print; then
    sec_audit_report_fail 204 "incomplete_scan: world-writable file search timed out under critical paths"
elif sec_audit_find_hit_timeout sec_audit_soft_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type d -perm -0002 -print; then
    sec_audit_report_fail 204 "incomplete_scan: world-writable directory search timed out under critical paths"
else
    WW_FILES=$(sec_audit_soft_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type f -perm -0002 -print 2>/dev/null | wc -l)
    WW_DIRS=$(sec_audit_soft_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type d -perm -0002 -print 2>/dev/null | wc -l)
    if [ "${WW_FILES:-0}" -eq 0 ] && [ "${WW_DIRS:-0}" -eq 0 ]; then
        sec_audit_report_pass 204 "No critical world writable files or directories found"
    else
        sec_audit_report_fail 204 "Found potential world-writable items ($WW_FILES files, $WW_DIRS dirs)"
    fi
fi
# RULE205:
_unowned=$(sec_audit_soft_find --timeout=30 $(sec_audit_local_fs_roots | tr '\n' ' ') -xdev \( -nouser -o -nogroup \) 2>/dev/null | head -20)
if [ -z "$_unowned" ]; then
    sec_audit_report_pass 205 "no unowned files or directories exist (sample scan)"
else
    sec_audit_report_fail 205 "unowned or ungrouped objects found: $_unowned"
fi

# RULE206:
SPECIAL_COUNTS=$(
    while IFS= read -r mount_point; do
        [ -d "$mount_point" ] || continue
        sec_audit_soft_find --timeout=120 "$mount_point" -xdev -ignore_readdir_race -type f -perm /6000 -printf '%m\n' 2>/dev/null
    done <<< "$(sec_audit_local_fs_roots)" | awk '
        {
            special_digit = int(($1 % 10000) / 1000)
            if (special_digit == 4 || special_digit == 5 || special_digit == 6 || special_digit == 7) suid++
            if (special_digit == 2 || special_digit == 3 || special_digit == 6 || special_digit == 7) sgid++
        }
        END { print suid + 0, sgid + 0 }
    '
)
read -r SUID_FILES SGID_FILES <<< "$SPECIAL_COUNTS"
if [ "$SUID_FILES" -gt 0 ] || [ "$SGID_FILES" -gt 0 ]; then
    # RULE206:
n=$(_find_perm_summary "-type f -perm /6000" 2>/dev/null || echo 0)
if [ "${n:-0}" -eq 0 ]; then
    sec_audit_report_pass 206 "no SUID or SGID files found (sample scan)"
else
    sec_audit_report_fail 206 "found ${n} SUID/SGID files requiring review"
fi

else
    sec_audit_report_pass 206 "No SUID or SGID files found"
fi

# RULE207:
if awk -F: '($2 != "x" ) { print }' /etc/passwd 2>/dev/null | grep -q '.'; then
    sec_audit_report_fail 207 "Non-shadow password field found in /etc/passwd (second field not "x")"
else
    sec_audit_report_pass 207 "accounts in /etc/passwd use shadowed passwords"
fi

# RULE208:
FAIL208=0
while IFS=: read -r user pass uid gid rest; do
    if ! grep -q "^.*:.*:$gid:" /etc/group 2>/dev/null; then
        sec_audit_report_fail 208 "User $user has primary group GID $gid which does not exist in /etc/group"
        FAIL208=1
    fi
done < /etc/passwd 2>/dev/null
[ $FAIL208 -eq 0 ] && echo "RULE208= PASS: All groups in /etc/passwd exist in /etc/group"

# RULE209:
if cut -f3 -d":" /etc/passwd 2>/dev/null | sort -n | uniq -c | while read -r count uid; do [ "$count" -gt 1 ] && echo "found"; done | grep -q "found"; then
    sec_audit_report_fail 209 "Duplicate UID entries exist in /etc/passwd"
else
    sec_audit_report_pass 209 "no duplicate UIDs exist"
fi

# RULE210:
if cut -f3 -d":" /etc/group 2>/dev/null | sort -n | uniq -c | while read -r count gid; do [ "$count" -gt 1 ] && echo "found"; done | grep -q "found"; then
    sec_audit_report_fail 210 "Duplicate GID entries exist in /etc/group"
else
    sec_audit_report_pass 210 "no duplicate GIDs exist"
fi

# RULE211:
if cut -f1 -d":" /etc/passwd 2>/dev/null | sort -n | uniq -c | while read -r count user; do [ "$count" -gt 1 ] && echo "found"; done | grep -q "found"; then
    sec_audit_report_fail 211 "Duplicate user names exist in /etc/passwd"
else
    sec_audit_report_pass 211 "no duplicate user names exist"
fi

# RULE212:
FAIL212=0
ROOT_PATH=$(sudo -i echo "\$PATH" 2>/dev/null || echo "$PATH")
if echo "$ROOT_PATH" | grep -q "::"; then
    sec_audit_report_fail 212 "Root PATH contains empty directory (::)"
    FAIL212=1
fi
if echo "$ROOT_PATH" | grep -qE '(^|:)\.(:|$)'; then
    sec_audit_report_fail 212 "Root PATH contains current directory (.)"
    FAIL212=1
fi
[ $FAIL212 -eq 0 ] && echo "RULE212= PASS: root PATH integrity is maintained"

# RULE213:
if awk -F: '($3 == 0) { print $1 }' /etc/passwd 2>/dev/null | grep -qx "root"; then
    if [ $(awk -F: '($3 == 0) { print $1 }' /etc/passwd 2>/dev/null | wc -l) -eq 1 ]; then
        sec_audit_report_pass 213 "root is the only UID 0 account"
    else
        sec_audit_report_fail 213 "Multiple accounts with UID 0 exist in /etc/passwd"
    fi
else
    sec_audit_report_fail 213 "Multiple accounts with UID 0 exist in /etc/passwd"
fi

# RULE214:
FAIL214=0
while IFS=: read -r user _ uid gid _ home _; do
    [[ -z "$user" || "$uid" -ge 1000 ]] || continue
    [[ -d "$home" ]] || continue
    owner=$(stat -Lc '%U' "$home" 2>/dev/null) || { FAIL214=1; continue; }
    [[ "$owner" == "$user" ]] || FAIL214=1
done < /etc/passwd
if [ $FAIL214 -eq 0 ]; then
    sec_audit_report_pass 214 "users own their home directories"
else
    sec_audit_report_fail 214 "one or more local users do not own their home directory"
fi

# RULE215:
FAIL215=0
while IFS=: read -r user pass uid gid rest; do
    if [ "$uid" -ge 1000 ] 2>/dev/null && [ "$uid" -lt 65534 ]; then
        home=$(echo "$rest" | cut -d: -f1)
        for dotfile in "$home/.bashrc" "$home/.bash_profile" "$home/.profile" "$home/.bash_logout"; do
            if [ -f "$dotfile" ]; then
                perm=$(stat -c '%a' "$dotfile" 2>/dev/null)
                if [ "${perm:2:1}" -gt 0 ] 2>/dev/null || [ "${perm:1:1}" -gt 0 ] 2>/dev/null; then
                    sec_audit_report_fail 215 "User $user dot file $dotfile has world/group write permissions ($perm)"
                    FAIL215=1
                fi
            fi
        done
    fi
done < /etc/passwd 2>/dev/null
[ $FAIL215 -eq 0 ] && echo "RULE215= PASS: Local interactive user dot files access is configured"

exit 0

