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

DEB10_FIND_CAP="${DEB10_FIND_CAP:-${CRE_FIND_CAP:-20}}"
CRE_FIND_CAP="${DEB10_FIND_CAP}"
DEB10_CMD_CAP="${DEB10_CMD_CAP:-${CRE_CMD_CAP:-12}}"
CRE_CMD_CAP="${DEB10_CMD_CAP}"
DEB10_DNF_CAP="${DEB10_DNF_CAP:-${CRE_DNF_CAP:-30}}"
CRE_DNF_CAP="${DEB10_DNF_CAP}"
DEB10_ALLOW_CONTAINER_KMOD="${DEB10_ALLOW_CONTAINER_KMOD:-${CRE_ALLOW_CONTAINER_KMOD:-${LINUX_CRE_ALLOW_CONTAINER_MODULES:-${ALMA_CRE_ALLOW_CONTAINER_MODULES:-0}}}}"
CRE_ALLOW_CONTAINER_KMOD="${DEB10_ALLOW_CONTAINER_KMOD}"
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
        sec_audit_report_pass "$num" "${label} (waived: DEB10_ALLOW_CONTAINER_KMOD=1)"
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
        if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'install ok installed'; then
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

sec_audit_yum_conf_last_value() {
    local want="$1" val=""
    [[ -f /etc/yum.conf ]] || { builtin printf '%s\n' ""; return 0; }
    val=$(awk -v want="$1" '
        function trim(s) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", s); return s }
        function lc(s) { return tolower(s) }
        BEGIN { v = "" }
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*\[/ { next }
        {
            line = $0
            sub(/#.*/, "", line)
            if (line !~ /=/) next
            eq = index(line, "=")
            key = trim(substr(line, 1, eq - 1))
            if (lc(key) == lc(want)) v = trim(substr(line, eq + 1))
        }
        END { print v }
    ' /etc/yum.conf 2>/dev/null)
    builtin printf '%s' "$val"
}

sec_audit_yum_val_is_true() {
    case "$(builtin printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')" in
    1 | true | yes | on) return 0 ;;
    *) return 1 ;;
    esac
}

sec_audit_pam_common_password_file() {
    builtin printf '%s\n' /etc/pam.d/common-password
}

sec_audit_dpkg_is_installed() {
    dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'
}

sec_audit_debian_apt_https_repos_ok() {
    grep -rqE '^[[:space:]]*deb[[:space:]]+[^#]+https://' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null
}

sec_audit_modprobe_deny_detail() {
    local mod="$1"
    if sec_audit_have_bin modprobe; then
        modprobe -n -v "$mod" 2>&1
    else
        echo "modprobe not available"
    fi
}

sec_audit_sshd_effective_equals() {
    local key="$1" want="$2" got
    got=$(sec_audit_sshd_config_grep -iE "^[[:space:]]*${key}[[:space:]]+" 2>/dev/null | awk '{print $2}' | head -n1)
    [[ "${got,,}" == "${want,,}" ]]
}

sec_audit_sshd_effective_not_equals() {
    local key="$1" bad="$2" got
    got=$(sec_audit_sshd_config_grep -iE "^[[:space:]]*${key}[[:space:]]+" 2>/dev/null | awk '{print $2}' | head -n1)
    [[ "${got,,}" != "${bad,,}" ]]
}

sec_audit_assert_kmod_disabled 2 freevxfs "freevxfs.ko*"
sec_audit_assert_kmod_disabled 3 jffs2 "jffs2.ko*"
sec_audit_assert_kmod_disabled 4 hfs "hfs.ko*"
sec_audit_assert_kmod_disabled 5 hfsplus "hfsplus.ko*"
sec_audit_assert_kmod_disabled 6 squashfs "squashfs.ko*"
sec_audit_assert_kmod_disabled 7 udf "udf.ko*"
sec_audit_assert_kmod_disabled 85 dccp "dccp.ko*"
sec_audit_assert_kmod_disabled 86 sctp "sctp.ko*"
sec_audit_assert_kmod_disabled 87 rds "rds.ko*"
sec_audit_assert_kmod_disabled 88 tipc "tipc.ko*"
sec_audit_assert_kmod_disabled 216 usb_storage "usb-storage.ko*" usb_storage "usb-storage"

if sec_audit_tmp_is_isolated; then
    echo "RULE8= PASS: /tmp is tmpfs or a separate partition"
else
    echo "RULE8= FAIL: /tmp does not meet tmpfs or separate-partition requirement"
fi
if sec_audit_mount_resolves /tmp && sec_audit_mount_has_option /tmp nodev; then
    echo "RULE9= PASS: nodev option set on /tmp"
else
    echo "RULE9= FAIL: nodev is not set on /tmp"
fi
if sec_audit_mount_resolves /tmp && sec_audit_mount_has_option /tmp nosuid; then
    echo "RULE10= PASS: nosuid option set on /tmp"
else
    echo "RULE10= FAIL: nosuid is not set on /tmp"
fi
if sec_audit_mount_resolves /tmp && sec_audit_mount_has_option /tmp noexec; then
    echo "RULE11= PASS: noexec option set on /tmp"
else
    echo "RULE11= FAIL: noexec is not set on /tmp"
fi
if sec_audit_path_is_isolated_volume /var; then
    echo "RULE15= PASS: /var is a separate partition"
else
    echo "RULE15= FAIL: /var is not a separate partition"
fi
if sec_audit_path_is_isolated_volume /var/tmp; then
    echo "RULE16= PASS: /var/tmp is a separate partition"
else
    echo "RULE16= FAIL: /var/tmp is not a separate partition"
fi
if sec_audit_mount_resolves /var/tmp && sec_audit_mount_has_option /var/tmp nodev; then
    echo "RULE17= PASS: nodev set on /var/tmp"
else
    echo "RULE17= FAIL: nodev is not set on /var/tmp"
fi
if sec_audit_mount_resolves /var/tmp && sec_audit_mount_has_option /var/tmp nosuid; then
    echo "RULE18= PASS: nosuid set on /var/tmp"
else
    echo "RULE18= FAIL: nosuid is not set on /var/tmp"
fi
if sec_audit_mount_resolves /var/tmp && sec_audit_mount_has_option /var/tmp noexec; then
    echo "RULE19= PASS: noexec set on /var/tmp"
else
    echo "RULE19= FAIL: noexec is not set on /var/tmp"
fi
if sec_audit_path_is_isolated_volume /var/log; then
    echo "RULE20= PASS: /var/log is a separate partition"
else
    echo "RULE20= FAIL: /var/log is not a separate partition"
fi
if sec_audit_path_is_isolated_volume /var/log/audit; then
    echo "RULE21= PASS: /var/log/audit is a separate partition"
else
    echo "RULE21= FAIL: /var/log/audit is not a separate partition"
fi
if sec_audit_path_is_isolated_volume /home; then
    echo "RULE22= PASS: /home is a separate partition"
else
    echo "RULE22= FAIL: /home is not a separate partition"
fi
if sec_audit_mount_resolves /home && sec_audit_mount_has_option /home nodev; then
    echo "RULE23= PASS: nodev set on /home"
else
    echo "RULE23= FAIL: nodev is not set on /home"
fi
if sec_audit_mount_resolves /dev/shm && sec_audit_mount_has_option /dev/shm nodev; then
    echo "RULE13= PASS: nodev set on /dev/shm"
else
    echo "RULE13= FAIL: nodev is not set on /dev/shm"
fi
if sec_audit_mount_resolves /dev/shm && sec_audit_mount_has_option /dev/shm nosuid; then
    echo "RULE14= PASS: nosuid set on /dev/shm"
else
    echo "RULE14= FAIL: nosuid is not set on /dev/shm"
fi
if sec_audit_mount_resolves /dev/shm && sec_audit_mount_has_option /dev/shm noexec; then
    echo "RULE12= PASS: noexec set on /dev/shm"
else
    echo "RULE12= FAIL: noexec is not set on /dev/shm"
fi

bad_sticky=$(sec_audit_local_fs_roots | while read -r root; do
    sec_audit_soft_find --timeout=30 "$root" -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null
done | head -50)
sticky_cnt=$(sec_audit_local_fs_roots | while read -r root; do
    sec_audit_soft_find --timeout=30 "$root" -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null
done | wc -l)
if [ "${sticky_cnt:-0}" -eq 0 ]; then
    echo "RULE24= PASS: No world-writable directories without sticky bit"
else
    echo "RULE24= FAIL: Found ${sticky_cnt} world-writable directories without sticky bit: $(echo "$bad_sticky" | tr '\n' ' ')"
fi
if systemctl is-enabled autofs 2>/dev/null | grep -qE "enabled"; then
    echo "RULE25= FAIL: autofs is enabled"
else
    echo "RULE25= PASS: autofs is not enabled"
fi

if sec_audit_dpkg_is_installed aide; then
    echo "RULE27= PASS: aide package installed"
else
    echo "RULE27= FAIL: aide package not installed"
fi
if crontab -u root -l 2>/dev/null | grep -qE '[[:space:]]aide[[:space:]]'; then
    echo "RULE28= PASS: aide scheduled in root crontab"
else
    echo "RULE28= FAIL: no aide entry in root crontab"
fi
if systemctl is-enabled aidecheck.service &>/dev/null && systemctl is-enabled aidecheck.timer &>/dev/null; then
    echo "RULE29= PASS: aidecheck.service and aidecheck.timer enabled"
else
    echo "RULE29= FAIL: aidecheck.service/timer not both enabled"
fi
p=$(stat -c %a /boot/grub/grub.cfg 2>/dev/null)
if [ -n "$p" ] && [ "$p" -le 600 ]; then
    echo "RULE30= PASS: /boot/grub/grub.cfg permissions $p"
else
    echo "RULE30= FAIL: /boot/grub/grub.cfg permissions too permissive ($p)"
fi
if grep -qE '^[[:space:]]*set[[:space:]]+superusers' /boot/grub/grub.cfg 2>/dev/null; then
    echo "RULE31= PASS: grub superusers configured"
else
    echo "RULE31= FAIL: grub superusers not configured"
fi
if grep -qE '^[[:space:]]*password' /boot/grub/grub.cfg 2>/dev/null; then
    echo "RULE32= PASS: grub password configured"
else
    echo "RULE32= FAIL: grub password not configured"
fi
if journalctl 2>/dev/null | grep -q 'protection: active'; then
    echo "RULE33= PASS: NX protection active (journal)"
else
    echo "RULE33= FAIL: NX protection not confirmed in journal"
fi
if [[ -n $(grep -E 'noexec[0-9]*=off' /proc/cmdline 2>/dev/null) ]] || \
   { [ -z "$(grep -Ei ' (pae|nx) ' /proc/cpuinfo 2>/dev/null)" ] && \
     [ -z "$(dmesg 2>/dev/null | grep -E 'NX.*protection:' | grep -v active)" ]; }; then
    echo "RULE34= FAIL: NX protection may not be active"
else
    echo "RULE34= PASS: NX protection appears active"
fi

sec_audit_assert_sysctl_equals 35 kernel.randomize_va_space 2
if grep -Eq '^root:[*!]' /etc/shadow 2>/dev/null || ! grep -q '^root:' /etc/shadow 2>/dev/null; then
    sec_audit_report_pass 37 "root account locked or no password hash"
else
    sec_audit_report_fail 37 "root has password hash in /etc/shadow"
fi
if sec_audit_dpkg_is_installed prelink; then
    sec_audit_report_fail 38 "prelink package installed"
else
    sec_audit_report_pass 38 "prelink not installed"
fi
if sec_audit_core_dumps_limited && sec_audit_sysctl_runtime_equals fs.suid_dumpable 0; then
    sec_audit_report_pass 39 "core dumps restricted (limits and fs.suid_dumpable)"
    sec_audit_report_pass 391 "hard core 0 in limits"
else
    sec_audit_report_fail 39 "core dump restrictions incomplete"
    sec_audit_report_fail 391 "hard core 0 not set in limits"
fi
if systemctl is-active apparmor &>/dev/null | grep -q active; then
    sec_audit_report_pass 40 "AppArmor is active"
else
    sec_audit_report_fail 40 "AppArmor not active"
fi
if sec_audit_have_bin apparmor_status && apparmor_status 2>/dev/null | grep -q 'profiles are loaded'; then
    sec_audit_report_pass 41 "AppArmor profiles loaded"
else
    sec_audit_report_fail 41 "AppArmor profiles not loaded"
fi
if sec_audit_have_bin apparmor_status && apparmor_status 2>/dev/null | grep -q 'processes are in enforce mode'; then
    sec_audit_report_pass 42 "processes in AppArmor enforce mode"
else
    sec_audit_report_fail 42 "no processes in AppArmor enforce mode"
fi
sec_audit_os_release_id=$(grep '^ID=' /etc/os-release 2>/dev/null | cut -d= -f2 | sed 's/"//g')
for req in "43:/etc/motd" "44:/etc/issue" "45:/etc/issue.net"; do
    n=${req%%:*}; f=${req#*:}
    if grep -Eis "(\\\\v|\\\\r|\\\\m|\\\\s|${sec_audit_os_release_id})" "$f" 2>/dev/null | grep -q .; then
        echo "RULE${n}= PASS: warning banner configured in $f"
    else
        echo "RULE${n}= FAIL: warning banner missing or incomplete in $f"
    fi
done
for req in "46:/etc/motd:644" "47:/etc/issue:644" "48:/etc/issue.net:644"; do
    n=${req%%:*}; rest=${req#*:}; fp=${rest%%:*}; mx=${rest##*:}
    p=$(stat -c %a "$fp" 2>/dev/null)
    if [ -n "$p" ] && [ "$p" -le "$mx" ]; then
        echo "RULE${n}= PASS: $fp permissions $p"
    else
        echo "RULE${n}= FAIL: $fp permissions too permissive ($p)"
    fi
done
if sec_audit_dpkg_is_installed chrony; then
    sec_audit_report_pass 50 "chrony installed"
else
    sec_audit_report_fail 50 "chrony not installed"
fi
if sec_audit_dpkg_is_installed ntp; then
    sec_audit_report_pass 51 "ntp installed"
else
    sec_audit_report_fail 51 "ntp not installed"
fi
if grep -qE '^(server|pool)[[:space:]]' /etc/chrony/chrony.conf 2>/dev/null; then
    sec_audit_report_pass 52 "chrony server/pool configured"
else
    sec_audit_report_fail 52 "no chrony server/pool"
fi
if grep -q '^restrict' /etc/ntp.conf 2>/dev/null && grep -qE '^(server|pool)' /etc/ntp.conf 2>/dev/null; then
    sec_audit_report_pass 53 "ntp restrict and servers configured"
else
    sec_audit_report_fail 53 "ntp restrict or servers missing"
fi
if dpkg-query -W 'xserver-xorg*' 2>/dev/null | grep -q 'install ok installed'; then
    sec_audit_report_fail 54 "X11 server packages installed"
else
    sec_audit_report_pass 54 "X11 server packages not installed"
fi
sec_audit_assert_service_unused 55 avahi-daemon avahi-daemon "Avahi"
sec_audit_assert_service_unused 56 cups cups "CUPS"
sec_audit_assert_service_unused 57 isc-dhcp-server isc-dhcp-server "DHCP server"
sec_audit_assert_service_unused 58 slapd slapd "LDAP server"
sec_audit_assert_service_unused 59 nfs-kernel-server nfs-kernel-server "NFS server"
sec_audit_assert_service_unused 60 vsftpd vsftpd "vsftpd"
sec_audit_assert_service_unused 61 apache2 apache2 "Apache"
sec_audit_assert_service_unused 62 dovecot-imapd dovecot-imapd "Dovecot"
sec_audit_assert_service_unused 63 samba samba "Samba"
sec_audit_assert_service_unused 64 squid squid "Squid"
sec_audit_assert_service_unused 65 snmpd snmpd "SNMP"
if ss -lntu 2>/dev/null | grep -qE ':25[[:space:]]' && ss -lntu 2>/dev/null | grep -E ':25[[:space:]]' | grep -qvE '(127\.0\.0\.1|\[::1\]):25'; then
    sec_audit_report_fail 66 "MTA listening on non-loopback"
else
    sec_audit_report_pass 66 "no MTA on non-loopback (or not listening)"
fi
sec_audit_assert_service_unused 67 rsync rsync "rsync"
sec_audit_assert_service_unused 68 nis nis "NIS"
sec_audit_assert_service_unused 69 nis nis "NIS client"
sec_audit_assert_service_unused 70 rsh-client rsh-client "rsh-client"
sec_audit_assert_service_unused 71 talk talk "talk"
sec_audit_assert_service_unused 72 telnet telnet "telnet"
sec_audit_assert_service_unused 73 ldap-utils ldap-utils "ldap-utils"
sec_audit_assert_sysctl_equals 74 net.ipv4.ip_forward 0
sec_audit_assert_sysctl_equals 75 net.ipv4.conf.all.send_redirects 0
sec_audit_assert_sysctl_equals 76 net.ipv4.conf.all.accept_source_route 0
sec_audit_assert_sysctl_equals 77 net.ipv4.conf.all.accept_redirects 0
sec_audit_assert_sysctl_equals 78 net.ipv4.conf.all.secure_redirects 0
sec_audit_assert_sysctl_equals 79 net.ipv4.conf.all.log_martians 1
sec_audit_assert_sysctl_equals 80 net.ipv4.icmp_echo_ignore_broadcasts 1
sec_audit_assert_sysctl_equals 81 net.ipv4.icmp_ignore_bogus_error_responses 1
sec_audit_assert_sysctl_equals 82 net.ipv4.conf.all.rp_filter 1
sec_audit_assert_sysctl_equals 83 net.ipv4.tcp_syncookies 1
sec_audit_assert_sysctl_equals 84 net.ipv6.conf.all.accept_ra 0
if sec_audit_dpkg_is_installed iptables-persistent || sec_audit_dpkg_is_installed iptables; then
    sec_audit_report_pass 89 "iptables package present"
else
    sec_audit_report_fail 89 "iptables not installed"
fi
if systemctl is-enabled auditd &>/dev/null | grep -q enabled; then
    sec_audit_report_pass 90 "auditd enabled"
else
    sec_audit_report_fail 90 "auditd not enabled"
fi
if grep -qE '^[[:space:]]*max_log_file[[:space:]]*=' /etc/audit/auditd.conf 2>/dev/null; then
    sec_audit_report_pass 91 "max_log_file set in auditd.conf"
else
    sec_audit_report_fail 91 "max_log_file not set in auditd.conf"
fi
if grep -qE '^[[:space:]]*max_log_file_action[[:space:]]*=' /etc/audit/auditd.conf 2>/dev/null; then
    sec_audit_report_pass 92 "max_log_file_action set in auditd.conf"
else
    sec_audit_report_fail 92 "max_log_file_action not set in auditd.conf"
fi
if grep -qE '^[[:space:]]*space_left_action[[:space:]]*=' /etc/audit/auditd.conf 2>/dev/null; then
    sec_audit_report_pass 93 "space_left_action set in auditd.conf"
else
    sec_audit_report_fail 93 "space_left_action not set in auditd.conf"
fi
if grep -qE '^[[:space:]]*action_mail_acct[[:space:]]*=' /etc/audit/auditd.conf 2>/dev/null; then
    sec_audit_report_pass 94 "action_mail_acct set in auditd.conf"
else
    sec_audit_report_fail 94 "action_mail_acct not set in auditd.conf"
fi
if grep -qE '^[[:space:]]*admin_space_left_action[[:space:]]*=' /etc/audit/auditd.conf 2>/dev/null; then
    sec_audit_report_pass 95 "admin_space_left_action set in auditd.conf"
else
    sec_audit_report_fail 95 "admin_space_left_action not set in auditd.conf"
fi
if systemctl is-enabled rsyslog &>/dev/null | grep -q enabled; then
    sec_audit_report_pass 96 "rsyslog enabled"
else
    sec_audit_report_fail 96 "rsyslog not enabled"
fi
if grep -rE '^\$FileCreateMode' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 97 "rsyslog FileCreateMode configured"
else
    sec_audit_report_fail 97 "rsyslog FileCreateMode not configured"
fi
if grep -rE '^\*\.[^I][^I]*@' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -q .; then
    sec_audit_report_fail 98 "rsyslog forwards to remote host"
else
    sec_audit_report_pass 98 "rsyslog does not forward to remote host"
fi
if grep -rE '^\$ModLoad imtcp|^\$InputTCPServerRun' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -q .; then
    sec_audit_report_fail 99 "rsyslog listens for remote logs"
else
    sec_audit_report_pass 99 "rsyslog does not listen for remote logs"
fi

if systemctl is-enabled cron 2>/dev/null | grep -q enabled; then
    sec_audit_report_pass 100 "cron enabled"
else
    sec_audit_report_fail 100 "cron not enabled"
fi
p=$(stat -c %a "/etc/crontab" 2>/dev/null)
if [ -n "$p" ] && [ "$p" -le 600 ]; then
    sec_audit_report_pass 101 "/etc/crontab permissions $p"
else
    sec_audit_report_fail 101 "/etc/crontab permissions too permissive ($p)"
fi
p=$(stat -c %a "/etc/cron.hourly" 2>/dev/null)
if [ -n "$p" ] && [ "$p" -le 600 ]; then
    sec_audit_report_pass 102 "/etc/cron.hourly permissions $p"
else
    sec_audit_report_fail 102 "/etc/cron.hourly permissions too permissive ($p)"
fi
p=$(stat -c %a "/etc/cron.daily" 2>/dev/null)
if [ -n "$p" ] && [ "$p" -le 600 ]; then
    sec_audit_report_pass 103 "/etc/cron.daily permissions $p"
else
    sec_audit_report_fail 103 "/etc/cron.daily permissions too permissive ($p)"
fi
p=$(stat -c %a "/etc/cron.weekly" 2>/dev/null)
if [ -n "$p" ] && [ "$p" -le 600 ]; then
    sec_audit_report_pass 104 "/etc/cron.weekly permissions $p"
else
    sec_audit_report_fail 104 "/etc/cron.weekly permissions too permissive ($p)"
fi
p=$(stat -c %a "/etc/cron.monthly" 2>/dev/null)
if [ -n "$p" ] && [ "$p" -le 600 ]; then
    sec_audit_report_pass 105 "/etc/cron.monthly permissions $p"
else
    sec_audit_report_fail 105 "/etc/cron.monthly permissions too permissive ($p)"
fi
p=$(stat -c %a "/etc/cron.d" 2>/dev/null)
if [ -n "$p" ] && [ "$p" -le 600 ]; then
    sec_audit_report_pass 106 "/etc/cron.d permissions $p"
else
    sec_audit_report_fail 106 "/etc/cron.d permissions too permissive ($p)"
fi
ca_ok=1
for f in /etc/cron.allow /etc/at.allow; do
    [[ -f $f ]] || continue
    p=$(stat -c %a "$f" 2>/dev/null)
    [[ -n $p && $p -le 640 ]] || ca_ok=0
done
if [ $ca_ok -eq 1 ]; then
    sec_audit_report_pass 107 "cron/at allow files permissions OK"
else
    sec_audit_report_fail 107 "cron/at allow files too permissive"
fi
p=$(stat -c %a /etc/ssh/sshd_config 2>/dev/null)
if [ -n "$p" ] && [ "$p" -le 600 ]; then
    sec_audit_report_pass 108 "sshd_config permissions $p"
else
    sec_audit_report_fail 108 "sshd_config permissions too permissive"
fi
sec_audit_sshd_t_ensure

weak_macs='hmac-md5|hmac-md5-96|hmac-ripemd160|hmac-sha1|hmac-sha1-96|umac-64@openssh.com|hmac-md5-etm|hmac-sha1-etm'
if sec_audit_sshd_config_grep -i '^[[:space:]]*macs[[:space:]]' 2>/dev/null | grep -qiE "$weak_macs"; then
    sec_audit_report_fail 118 "sshd uses weak MAC algorithms"
else
    sec_audit_report_pass 118 "sshd MACs exclude weak algorithms"
fi
if sec_audit_sshd_effective_equals protocol 2; then
    sec_audit_report_pass 109 "sshd Protocol 2"
else
    sec_audit_report_fail 109 "sshd Protocol not 2"
fi
v=$(sec_audit_sshd_config_grep -i loglevel 2>/dev/null | awk "{print \$2}" | head -n1); case "${v,,}" in info|verbose) echo "RULE110= PASS: sshd LogLevel $v" ;; *) echo "RULE110= FAIL: sshd LogLevel not INFO/VERBOSE ($v)" ;; esac
if sec_audit_sshd_effective_equals x11forwarding no; then
    sec_audit_report_pass 111 "sshd X11Forwarding no"
else
    sec_audit_report_fail 111 "sshd X11Forwarding not no"
fi
v=$(sec_audit_sshd_config_grep -i maxauthtries 2>/dev/null | awk "{print \$2}" | head -n1)
if [[ "${v:-99}" -le 4 ]]; then
    sec_audit_report_pass 112 "sshd MaxAuthTries $v"
else
    sec_audit_report_fail 112 "sshd MaxAuthTries > 4 ($v)"
fi
if sec_audit_sshd_effective_equals ignorerhosts yes; then
    sec_audit_report_pass 113 "sshd IgnoreRhosts yes"
else
    sec_audit_report_fail 113 "sshd IgnoreRhosts not yes"
fi
if sec_audit_sshd_effective_equals hostbasedauthentication no; then
    sec_audit_report_pass 114 "sshd HostbasedAuthentication no"
else
    sec_audit_report_fail 114 "sshd HostbasedAuthentication not no"
fi
if sec_audit_sshd_effective_equals permitrootlogin no; then
    sec_audit_report_pass 115 "sshd PermitRootLogin no"
else
    sec_audit_report_fail 115 "sshd PermitRootLogin not no"
fi
if sec_audit_sshd_effective_equals permitemptypasswords no; then
    sec_audit_report_pass 116 "sshd PermitEmptyPasswords no"
else
    sec_audit_report_fail 116 "sshd PermitEmptyPasswords not no"
fi
if sec_audit_sshd_effective_equals permituserenvironment no; then
    sec_audit_report_pass 117 "sshd PermitUserEnvironment no"
else
    sec_audit_report_fail 117 "sshd PermitUserEnvironment not no"
fi
ci=$(sec_audit_sshd_config_grep -i clientaliveinterval 2>/dev/null | awk '{print $2}' | head -n1)
cc=$(sec_audit_sshd_config_grep -i clientalivecountmax 2>/dev/null | awk '{print $2}' | head -n1)
if [[ -n $ci && $ci -le 900 && -n $cc && ( $cc -eq 0 || $cc -le 3 ) ]]; then
    sec_audit_report_pass 119 "sshd ClientAlive configured"
else
    sec_audit_report_fail 119 "sshd ClientAlive not configured (interval=$ci count=$cc)"
fi
v=$(sec_audit_sshd_config_grep -i logingracetime 2>/dev/null | awk "{print \$2}" | head -n1)
if [[ -n $v && $v -le 60 ]]; then
    sec_audit_report_pass 120 "sshd LoginGraceTime $v"
else
    sec_audit_report_fail 120 "sshd LoginGraceTime > 60 ($v)"
fi
if sec_audit_sshd_config_grep -i banner 2>/dev/null | awk "{print \$2}" | grep -q .; then
    sec_audit_report_pass 121 "sshd Banner configured"
else
    sec_audit_report_fail 121 "sshd Banner not configured"
fi
pm=$(grep -E '^PASS_MAX_DAYS[[:space:]]+[0-9]+' /etc/login.defs | grep -v '^#' | awk '{print $2}' | head -n1)
if [[ -n $pm && $pm -le 365 ]]; then
    sec_audit_report_pass 127 "PASS_MAX_DAYS $pm"
else
    sec_audit_report_fail 127 "PASS_MAX_DAYS not <= 365"
fi
pn=$(grep -E '^PASS_MIN_DAYS[[:space:]]+[0-9]+' /etc/login.defs | grep -v '^#' | awk '{print $2}' | head -n1)
if [[ -n $pn && $pn -ge 1 ]]; then
    sec_audit_report_pass 126 "PASS_MIN_DAYS $pn"
else
    sec_audit_report_fail 126 "PASS_MIN_DAYS < 1"
fi
pw=$(grep -E '^PASS_WARN_AGE[[:space:]]+[0-9]+' /etc/login.defs | grep -v '^#' | awk '{print $2}' | head -n1)
if [[ -n $pw && $pw -ge 7 ]]; then
    sec_audit_report_pass 128 "PASS_WARN_AGE $pw"
else
    sec_audit_report_fail 128 "PASS_WARN_AGE < 7"
fi
inactive=$(useradd -D 2>/dev/null | awk -F= '/^INACTIVE=/ {print $2}')
if [[ -n $inactive && $inactive -le 30 ]]; then
    sec_audit_report_pass 129 "INACTIVE $inactive"
else
    sec_audit_report_fail 129 "INACTIVE not <= 30"
fi
gid=$(grep "^root:" /etc/passwd | cut -d: -f4)
if [ "$gid" = "0" ]; then
    sec_audit_report_pass 131 "root GID is 0"
else
    sec_audit_report_fail 131 "root GID is $gid"
fi
RULE118_out=""
for u in $(awk -F: '($3==0 || $3>=1000){print $1}' /etc/passwd); do
    exp=$(chage -l "$u" 2>/dev/null | awk -F: '/Password expires/ {gsub(/^[[:space:]]+|[[:space:]]+$/,"",$2); print $2}')
    if [[ "$exp" == "never" || -z $exp ]]; then RULE118_out="${RULE118_out}${u}:never "
    else
        now=$(date +%s); ex=$(date -d "$exp" +%s 2>/dev/null || echo 0)
        if [ "$ex" -gt "$now" ]; then RULE118_out="${RULE118_out}${u}:active "; else RULE118_out="${RULE118_out}${u}:expired "; fi
    fi
done
if echo "$RULE118_out" | grep -q "expired"; then
    sec_audit_report_fail 130 "expired password state found: ${RULE118_out:-none}"
else
    sec_audit_report_pass 130 "password expiration state OK: ${RULE118_out:-none}"
fi

p=$(stat -c %a "/etc/passwd" 2>/dev/null)
if [ -n "$p" ] && [ "$p" -le 644 ]; then
    sec_audit_report_pass 134 "/etc/passwd $p"
else
    sec_audit_report_fail 134 "/etc/passwd too permissive ($p)"
fi
p=$(stat -c %a "/etc/shadow" 2>/dev/null)
if [ -n "$p" ] && [ "$p" -le 000 ]; then
    sec_audit_report_pass 138 "/etc/shadow $p"
else
    sec_audit_report_fail 138 "/etc/shadow too permissive ($p)"
fi
p=$(stat -c %a "/etc/group" 2>/dev/null)
if [ -n "$p" ] && [ "$p" -le 644 ]; then
    sec_audit_report_pass 136 "/etc/group $p"
else
    sec_audit_report_fail 136 "/etc/group too permissive ($p)"
fi
p=$(stat -c %a "/etc/gshadow" 2>/dev/null)
if [ -n "$p" ] && [ "$p" -le 000 ]; then
    sec_audit_report_pass 140 "/etc/gshadow $p"
else
    sec_audit_report_fail 140 "/etc/gshadow too permissive ($p)"
fi
p=$(stat -c %a "/etc/passwd-" 2>/dev/null)
if [ -n "$p" ] && [ "$p" -le 644 ]; then
    sec_audit_report_pass 135 "/etc/passwd- $p"
else
    sec_audit_report_fail 135 "/etc/passwd- too permissive ($p)"
fi
p=$(stat -c %a "/etc/shadow-" 2>/dev/null)
if [ -n "$p" ] && [ "$p" -le 000 ]; then
    sec_audit_report_pass 139 "/etc/shadow- $p"
else
    sec_audit_report_fail 139 "/etc/shadow- too permissive ($p)"
fi
p=$(stat -c %a "/etc/group-" 2>/dev/null)
if [ -n "$p" ] && [ "$p" -le 644 ]; then
    sec_audit_report_pass 137 "/etc/group- $p"
else
    sec_audit_report_fail 137 "/etc/group- too permissive ($p)"
fi
p=$(stat -c %a "/etc/gshadow-" 2>/dev/null)
if [ -n "$p" ] && [ "$p" -le 000 ]; then
    sec_audit_report_pass 141 "/etc/gshadow- $p"
else
    sec_audit_report_fail 141 "/etc/gshadow- too permissive ($p)"
fi
sec_audit_find_perm_summary() {
    local find_expr="$1"
    sec_audit_local_fs_roots | while read -r root; do
        sec_audit_soft_find --timeout=25 "$root" -xdev $find_expr 2>/dev/null
    done | wc -l
}
n=$(sec_audit_find_perm_summary "-type f -perm -0002")
if [ "${n:-0}" -eq 0 ]; then
    sec_audit_report_pass 142 "no world-writable files found"
else
    sec_audit_report_fail 142 "found ${n} world-writable files"
fi
n=$(sec_audit_find_perm_summary "-nouser")
if [ "${n:-0}" -eq 0 ]; then
    sec_audit_report_pass 143 "no unowned objects found"
else
    sec_audit_report_fail 143 "found ${n} unowned objects"
fi
n=$(sec_audit_find_perm_summary "-nogroup")
if [ "${n:-0}" -eq 0 ]; then
    sec_audit_report_pass 144 "no ungrouped objects found"
else
    sec_audit_report_fail 144 "found ${n} ungrouped objects"
fi
n=$(sec_audit_find_perm_summary "-type f -perm -4000")
if [ "${n:-0}" -eq 0 ]; then
    sec_audit_report_pass 145 "no SUID files found"
else
    sec_audit_report_fail 145 "found ${n} SUID files"
fi
n=$(sec_audit_find_perm_summary "-type f -perm -2000")
if [ "${n:-0}" -eq 0 ]; then
    sec_audit_report_pass 146 "no SGID files found"
else
    sec_audit_report_fail 146 "found ${n} SGID files"
fi
empty_pw=$(awk -F: '($2==""){print $1}' /etc/shadow)
if [ -z "$empty_pw" ]; then
    sec_audit_report_pass 147 "no empty password accounts"
else
    sec_audit_report_fail 147 "accounts without password: $empty_pw"
fi
uid0=$(awk -F: '($3==0 && $1!="root"){print $1}' /etc/passwd)
if [ -z "$uid0" ]; then
    sec_audit_report_pass 148 "only root has UID 0"
else
    sec_audit_report_fail 148 "non-root UID 0: $uid0"
fi

cc=$(sec_audit_sshd_config_grep -i clientalivecountmax 2>/dev/null | awk '{print $2}' | head -n1)
if [[ -n $cc && $cc -le 3 ]]; then
    sec_audit_report_pass 1191 "sshd ClientAliveCountMax $cc"
else
    sec_audit_report_fail 1191 "sshd ClientAliveCountMax not configured ($cc)"
fi
if sec_audit_sshd_effective_equals usepam yes; then
    sec_audit_report_pass 215 "sshd UsePAM yes"
else
    sec_audit_report_fail 215 "sshd UsePAM not yes"
fi

if grep -qE 'pam_pwquality\.so' /etc/pam.d/common-password 2>/dev/null; then
    if grep -Pq '^\h*password\h+(requisite|required)\h+pam_pwquality\.so' /etc/pam.d/common-password; then
        sec_audit_report_pass 123 "pam_pwquality in common-password"
    else
        sec_audit_report_fail 123 "pam_pwquality not properly configured"
    fi
else
    sec_audit_report_fail 123 "pam_pwquality missing"
fi
if grep -Pq 'pam_pwhistory\.so.*remember=([5-9]|[1-9][0-9]+)' /etc/pam.d/common-password 2>/dev/null; then
    sec_audit_report_pass 124 "password history (remember) configured"
else
    sec_audit_report_fail 124 "pam_pwhistory remember not configured"
fi
if grep -qE 'pam_unix\.so.*sha512' /etc/pam.d/common-password 2>/dev/null; then
    sec_audit_report_pass 125 "sha512 in pam_unix (common-password)"
else
    sec_audit_report_fail 125 "sha512 not in pam_unix"
fi
if grep -qE '^\s*minlen\s*=' /etc/security/pwquality.conf 2>/dev/null; then
    sec_audit_report_pass 122 "pwquality minlen configured"
else
    sec_audit_report_fail 122 "pwquality minlen not configured"
fi

for req in "1341:/etc/passwd" "1351:/etc/passwd-" "1361:/etc/group" "1371:/etc/group-" "1381:/etc/shadow" "1391:/etc/shadow-" "1401:/etc/gshadow" "1411:/etc/gshadow-"; do
    n=${req%%:*}; fp=${req#*:}
    o=$(stat -c %U "$fp" 2>/dev/null)
    if [ "$o" = "root" ]; then
        echo "RULE${n}= PASS: $fp owned by root"
    else
        echo "RULE${n}= FAIL: $fp owner is ${o:-missing}"
    fi
done

if apt-get -qq update >/dev/null 2>&1 && grep -rqE '^[[:space:]]*deb[[:space:]]+[^#]+https://' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null; then
  sec_audit_report_pass 228 "package repositories are configured and HTTPS sources are present"
else
  sec_audit_report_fail 228 "package repositories are not properly configured or HTTPS sources are missing"
fi

if [ ! -d /etc/apt/trusted.gpg.d/ ] || [ -z "$(ls -A /etc/apt/trusted.gpg.d/)" ]; then
  sec_audit_report_fail 229 "No GPG keys found in /etc/apt/trusted.gpg.d/"
fi
if ! apt-key list 2>/dev/null | grep -q "pub"; then
  sec_audit_report_fail 229 "No valid GPG keys configured"
else
  sec_audit_report_pass 229 "GPG keys are properly configured"
fi

PT_VALUE=$(sysctl -n kernel.yama.ptrace_scope)
if [ "$PT_VALUE" -ne 1 ] && [ "$PT_VALUE" -ne 2 ] && [ "$PT_VALUE" -ne 3 ]; then
  sec_audit_report_fail 230 "ptrace_scope is not restricted (current value: $PT_VALUE)"
else
  sec_audit_report_pass 230 "ptrace_scope is properly restricted (value: $PT_VALUE)"
fi

if systemctl is-active apport.service >/dev/null 2>&1 || \
   [[ "$(grep -c '^enabled=1$' /etc/default/apport 2>/dev/null)" -gt 0 ]]; then
  sec_audit_report_fail 231 "Automatic error reporting is enabled"
else
  sec_audit_report_pass 231 "Automatic error reporting is disabled"
fi

if dpkg -l | grep -q "gdm3"; then
  sec_audit_report_fail 232 "GDM is installed"
else
  sec_audit_report_pass 232 "GDM is not installed"
fi

if [ -f /etc/gdm3/greeter.dconf-defaults ]; then
  if grep -q "^disable-user-list=true" /etc/gdm3/greeter.dconf-defaults; then
    sec_audit_report_pass 233 "disable-user-list enabled in GDM"
  else
    sec_audit_report_fail 233 "disable-user-list not enabled in GDM"
  fi
else
  sec_audit_report_fail 233 "/etc/gdm3/greeter.dconf-defaults not found"
fi

if [ -f /etc/gdm3/greeter.dconf-defaults ]; then
  if ! grep -q "^idle-delay=uint32\s\+[1-9]" /etc/gdm3/greeter.dconf-defaults || \
     ! grep -q "^lock-delay=uint32\s\+[1-9]" /etc/gdm3/greeter.dconf-defaults; then
    sec_audit_report_fail 234 "Screen lock timeout is not properly configured"
  else
    sec_audit_report_pass 234 "Screen lock timeout is properly configured"
  fi
else
  sec_audit_report_fail 234 "/etc/gdm3/greeter.dconf-defaults not found"
fi

if [ -f /etc/dconf/db/gdm.d/locks/session ]; then
  if ! grep -q "^/org/gnome/desktop/screensaver/lock-enabled" /etc/dconf/db/gdm.d/locks/session || \
     ! grep -q "^/org/gnome/desktop/session/idle-delay" /etc/dconf/db/gdm.d/locks/session; then
    sec_audit_report_fail 235 "Screen lock settings can be overridden"
  else
    sec_audit_report_pass 235 "Screen lock settings cannot be overridden"
  fi
else
  sec_audit_report_fail 235 "/etc/dconf/db/gdm.d/locks/session not found"
fi

if [ -f /etc/gdm3/greeter.dconf-defaults ]; then
  if ! grep -q "^automount=false" /etc/gdm3/greeter.dconf-defaults || \
     ! grep -q "^automount-open=false" /etc/gdm3/greeter.dconf-defaults; then
    sec_audit_report_fail 236 "Automatic mounting of removable media is enabled"
  else
    sec_audit_report_pass 236 "Automatic mounting of removable media is disabled"
  fi
else
  sec_audit_report_fail 236 "/etc/gdm3/greeter.dconf-defaults not found"
fi

if [ -f /etc/dconf/db/gdm.d/locks/automount ]; then
  if ! grep -q "^/org/gnome/desktop/media-handling/automount" /etc/dconf/db/gdm.d/locks/automount || \
     ! grep -q "^/org/gnome/desktop/media-handling/automount-open" /etc/dconf/db/gdm.d/locks/automount; then
    sec_audit_report_fail 237 "Automount settings can be overridden"
  else
    sec_audit_report_pass 237 "Automount settings cannot be overridden"
  fi
else
  sec_audit_report_fail 237 "/etc/dconf/db/gdm.d/locks/automount not found"
fi

if [ -f /etc/gdm3/greeter.dconf-defaults ]; then
  if ! grep -q "^autorun-never=true" /etc/gdm3/greeter.dconf-defaults; then
    sec_audit_report_fail 238 "autorun-never is not enabled"
  else
    sec_audit_report_pass 238 "autorun-never is enabled"
  fi
else
  sec_audit_report_fail 238 "/etc/gdm3/greeter.dconf-defaults not found"
fi

if [ -f /etc/dconf/db/gdm.d/locks/autorun ]; then
  if ! grep -q "^/org/gnome/desktop/media-handling/autorun-never" /etc/dconf/db/gdm.d/locks/autorun; then
    sec_audit_report_fail 239 "autorun-never setting can be overridden"
  else
    sec_audit_report_pass 239 "autorun-never setting cannot be overridden"
  fi
else
  sec_audit_report_fail 239 "/etc/dconf/db/gdm.d/locks/autorun not found"
fi

if grep -q "^Enable=true" /etc/gdm3/custom.conf 2>/dev/null; then
  sec_audit_report_fail 240 "XDCMP is enabled"
else
  sec_audit_report_pass 240 "XDCMP is not enabled"
fi

SERVICES=("chronyd" "ntpd" "systemd-timesyncd")
COUNT=0
for service in "${SERVICES[@]}"; do
  if systemctl is-enabled "$service" 2>/dev/null | grep -q "enabled"; then
    ((COUNT++))
    ACTIVE_SERVICE="$service"
  fi
done
if [ "$COUNT" -eq 0 ]; then
  sec_audit_report_fail 241 "No time synchronization service is enabled"
elif [ "$COUNT" -gt 1 ]; then
  sec_audit_report_fail 241 "Multiple time synchronization services enabled"
elif [ "$COUNT" -eq 1 ]; then
sec_audit_report_pass 241 "Only $ACTIVE_SERVICE is enabled for time synchronization"
fi

if grep "^server" /etc/chrony/chrony.conf | grep -qv "\.example\.net\|\.example\.com"; then
  sec_audit_report_pass 242 "chrony configured with authorized timeserver"
else
  sec_audit_report_fail 242 "chrony configured with example servers"
fi

if ps -ef | grep chronyd | grep -q "^_chrony"; then
  sec_audit_report_pass 243 "chrony running as _chrony user"
else
  sec_audit_report_fail 243 "chrony not running as _chrony user"
fi

if ! grep -q "^NTP=" /etc/systemd/timesyncd.conf; then
  sec_audit_report_fail 244 "No NTP servers configured in systemd-timesyncd"
else
  sec_audit_report_pass 244 "systemd-timesyncd configured with authorized timeserver"
fi

if grep -q "^restrict" /etc/ntp.conf; then
  sec_audit_report_pass 245 "ntp access control is configured"
else
  sec_audit_report_fail 245 "ntp access control not configured"
fi

if grep "^server" /etc/ntp.conf | grep -qv "\.example\.net\|\.example\.com"; then
  sec_audit_report_pass 246 "ntp configured with authorized timeserver"
else
  sec_audit_report_fail 246 "ntp configured with example servers"
fi

if ps -ef | grep ntpd | grep -q "^ntp"; then
  sec_audit_report_pass 247 "ntp running as ntp user"
else
  sec_audit_report_fail 247 "ntp not running as ntp user"
fi

if dpkg-query -W -f='${Status}' avahi-daemon 2>/dev/null | grep -q "installed"; then
  sec_audit_report_fail 248 "Avahi Server is installed"
else
  sec_audit_report_pass 248 "Avahi Server is not installed"
fi

if dpkg-query -W -f='${Status}' cups 2>/dev/null | grep -q "installed"; then
  sec_audit_report_fail 249 "CUPS is installed"
else
  sec_audit_report_pass 249 "CUPS is not installed"
fi

if dpkg-query -W -f='${Status}' isc-dhcp-server 2>/dev/null | grep -q "installed"; then
  sec_audit_report_fail 250 "DHCP Server is installed"
else
  sec_audit_report_pass 250 "DHCP Server is not installed"
fi

if dpkg-query -W -f='${Status}' slapd 2>/dev/null | grep -q "installed"; then
  sec_audit_report_fail 251 "LDAP server is installed"
else
  sec_audit_report_pass 251 "LDAP server is not installed"
fi

if dpkg-query -W -f='${Status}' nfs-kernel-server 2>/dev/null | grep -q "installed"; then
  sec_audit_report_fail 252 "NFS server is installed"
else
  sec_audit_report_pass 252 "NFS server is not installed"
fi

if dpkg-query -W -f='${Status}' dovecot-imapd dovecot-pop3d 2>/dev/null | grep -q "installed"; then
  sec_audit_report_fail 253 "IMAP/POP3 server is installed"
else
  sec_audit_report_pass 253 "IMAP/POP3 server is not installed"
fi

if dpkg-query -W -f='${Status}' dnsmasq 2>/dev/null | grep -q "installed"; then
  sec_audit_report_fail 254 "dnsmasq is installed"
else
  sec_audit_report_pass 254 "dnsmasq is not installed"
fi

if ! dpkg-query -W -f='${Status}' rsync 2>/dev/null | grep -q "installed"; then
  sec_audit_report_pass 255 "rsync is not installed"
else
  sec_audit_report_fail 255 "rsync is installed and not masked"
fi

if dpkg-query -W -f='${Status}' rpcbind 2>/dev/null | grep -q "installed"; then
  sec_audit_report_fail 256 "RPC is installed"
else
  sec_audit_report_pass 256 "RPC is not installed"
fi

NONESSENTIAL=("xinetd" "telnetd" "rsh-server" "ypbind" "tftpd" "atftp" "tftpd-hpa" "rlogin" "rsh-client")
FAILED=0
for service in "${NONESSENTIAL[@]}"; do
  if dpkg-query -W -f='${Status}' "$service" 2>/dev/null | grep -q "installed"; then
    sec_audit_report_fail 257 "$service is installed"
    FAILED=1
  fi
done
if [ $FAILED -eq 0 ]; then
  sec_audit_report_pass 257 "No nonessential services installed"
fi

if grep -qs "^\s*net\.ipv6\.conf\.all\.disable_ipv6\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf; then
    sec_audit_report_pass 258 "IPv6 is disabled in sysctl configuration"
elif grep -qs "^\s*net\.ipv6\.conf\.all\.disable_ipv6\s*=\s*0" /etc/sysctl.conf /etc/sysctl.d/*.conf; then
    sec_audit_report_fail 258 "IPv6 is enabled in sysctl configuration"
else
    sec_audit_report_fail 258 "IPv6 status is not explicitly configured in sysctl"
fi

if sec_audit_have_bin lsmod && lsmod 2>/dev/null | grep -q "bluetooth"; then
    sec_audit_report_fail 259 "Bluetooth module is loaded"
else
    sec_audit_report_pass 259 "Bluetooth module is not loaded"
fi

if dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' iptables-persistent 2>/dev/null | grep -q "installed"; then
    sec_audit_report_pass 260 "iptables-persistent is installed"
else
    sec_audit_report_fail 260 "iptables-persistent is not installed"
fi

if dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' ufw 2>/dev/null | grep -q "installed"; then
    sec_audit_report_fail 261 "ufw is installed"
else
    sec_audit_report_pass 261 "ufw is not installed"
fi

if dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' nftables 2>/dev/null | grep -q "installed"; then
    sec_audit_report_pass 262 "nftables is installed"
else
    sec_audit_report_fail 262 "nftables is not installed"
fi

if dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' ufw 2>/dev/null | grep -q "installed"; then
    sec_audit_report_fail 263 "ufw is installed"
else
    sec_audit_report_pass 263 "ufw is not installed"
fi

if grep -rq "^[^#].*NOPASSWD" /etc/sudoers* 2>/dev/null; then
    sec_audit_report_fail 264 "Found sudoers entries with NOPASSWD"
else
    sec_audit_report_pass 264 "No NOPASSWD entries found in sudoers files"
fi

if grep -r "^[^#].*timestamp_timeout=-1" /etc/sudoers*; then
    sec_audit_report_fail 265 "Found sudoers entries disabling re-authentication"
else
    sec_audit_report_pass 265 "No sudoers entries disable re-authentication"
fi

timeout=$(grep -roP "timestamp_timeout=\K[0-9]+" /etc/sudoers* | head -n 1)
if [[ -z "$timeout" ]]; then
    sec_audit_report_pass 266 "Default timeout (15 minutes) is in effect"
elif (( timeout > 15 )); then
    sec_audit_report_fail 266 "Sudo timeout is too high ($timeout minutes)"
else
    sec_audit_report_pass 266 "Sudo timeout is $timeout minutes (acceptable)"
fi

if awk -F: '($2 != "" && $2 !~ /^\$6\$/) {print $1}' /etc/shadow 1>/dev/null; then
    sec_audit_report_fail 267 "Some passwords do not use SHA-512 hashing"
else
    sec_audit_report_pass 267 "All passwords use SHA-512 hashing"
fi

if grep -Pq "^\h*password\h+(requisite|required)\h+pam_pwquality\.so\h+.*difok=[1-7]\b" /etc/pam.d/common-password; then
    sec_audit_report_fail 268 "Password change requires fewer than 8 new characters"
elif grep -Pq "^\h*password\h+(requisite|required)\h+pam_pwquality\.so\h+.*difok=[8-9]|[1-9][0-9]+\b" /etc/pam.d/common-password; then
    sec_audit_report_pass 268 "Password change requires sufficient new characters"
else
    sec_audit_report_fail 268 "No difok setting found in pam_pwquality"
fi

if grep -Pq "^\h*password\h+(requisite|required)\h+pam_pwquality\.so\h+.*dictcheck=1\b" /etc/pam.d/common-password; then
    sec_audit_report_pass 269 "Dictionary words are restricted in passwords"
else
    sec_audit_report_fail 269 "Dictionary words are not restricted in passwords"
fi

if grep -Fxq "/usr/sbin/nologin" /etc/shells || grep -Fxq "/sbin/nologin" /etc/shells; then
    sec_audit_report_fail 270 "nologin is listed in /etc/shells"
else
    sec_audit_report_pass 270 "nologin is not listed in /etc/shells"
fi

if grep -Pq "^\h*password\h+(requisite|required)\h+pam_pwquality\.so\h+.*maxrepeat=[0-2]\b" /etc/pam.d/common-password; then
    sec_audit_report_fail 271 "Allows too many consecutive characters"
elif grep -Pq "^\h*password\h+(requisite|required)\h+pam_pwquality\.so\h+.*maxrepeat=[3-9]|[1-9][0-9]+\b" /etc/pam.d/common-password; then
    sec_audit_report_pass 271 "Limits consecutive characters appropriately"
else
    sec_audit_report_fail 271 "No maxrepeat setting found in pam_pwquality"
fi

if dpkg-query -W -f='${db:Status-Status}' systemd-journal-remote 2>/dev/null | grep -q "installed"; then
    sec_audit_report_pass 272 "systemd-journal-remote is installed"
else
    sec_audit_report_fail 272 "systemd-journal-remote is not installed"
fi

if [ -f /etc/systemd/journal-upload.conf ] && grep -q "^URL=" /etc/systemd/journal-upload.conf; then
    sec_audit_report_pass 273 "systemd-journal-remote is configured (URL set)"
else
    sec_audit_report_fail 273 "systemd-journal-remote is not properly configured"
fi

if systemctl is-enabled systemd-journal-upload.service &>/dev/null; then
    sec_audit_report_pass 274 "systemd-journal-remote service is enabled"
else
    sec_audit_report_fail 274 "systemd-journal-remote service is not enabled"
fi

if grep -q "^ListenStream" /etc/systemd/journal-remote.conf 2>/dev/null; then
    sec_audit_report_fail 275 "journald is configured to receive remote logs"
else
    sec_audit_report_pass 275 "journald is not configured to receive remote logs"
fi

if grep -q "^ForwardToSyslog=yes" /etc/systemd/journald.conf; then
    sec_audit_report_fail 276 "journald is configured to forward logs to rsyslog"
else
    sec_audit_report_pass 276 "journald does not forward logs to rsyslog"
fi

if grep -q "^SystemMaxUse=" /etc/systemd/journald.conf; then
    sec_audit_report_pass 277 "journald log rotation is configured"
else
    sec_audit_report_fail 277 "journald log rotation is not configured"
fi

if grep -q "^Storage=persistent" /etc/systemd/journald.conf && grep -q "^SystemMaxUse=" /etc/systemd/journald.conf; then
    sec_audit_report_pass 278 "journald file permissions are configured"
else
    sec_audit_report_fail 278 "journald file permissions are not properly configured"
fi

if grep -q "^module(load=\"imtcp\")" /etc/rsyslog.conf || grep -q "^module(load=\"imudp\")" /etc/rsyslog.conf; then
    sec_audit_report_fail 279 "rsyslog is configured to receive remote logs"
else
    sec_audit_report_pass 279 "rsyslog is not configured to receive remote logs"
fi

if sec_audit_auditctl_list_grep -q "/usr/bin/chcon"; then
    sec_audit_report_pass 280 "Audit rule for chcon exists"
else
    sec_audit_report_fail 280 "No audit rule for chcon"
fi

if sec_audit_auditctl_list_grep -q "/usr/bin/setfacl"; then
    sec_audit_report_pass 281 "Audit rule for setfacl exists"
else
    sec_audit_report_fail 281 "No audit rule for setfacl"
fi

if sec_audit_auditctl_list_grep -q "/usr/bin/chacl"; then
    sec_audit_report_pass 282 "Audit rule for chacl exists"
else
    sec_audit_report_fail 282 "No audit rule for chacl"
fi

if sec_audit_auditctl_list_grep -q "/usr/sbin/usermod"; then
    sec_audit_report_pass 283 "Audit rule for usermod exists"
else
    sec_audit_report_fail 283 "No audit rule for usermod"
fi

sec_audit_auditctl_l_ensure
if diff <(builtin printf '%s\n' "$_auditctl_l_cache") <(augenrules --check 2>/dev/null) &>/dev/null; then
    sec_audit_report_pass 284 "Running and on-disk audit rules match"
else
    sec_audit_report_fail 284 "Running and on-disk audit rules differ"
fi

if [[ "$(stat -c %a /etc/audit/audit.rules)" -le 640 ]] && [[ "$(stat -c %a /etc/audit/rules.d/*)" -le 640 ]]; then
    sec_audit_report_pass 285 "Audit configuration files have correct permissions (640)"
else
    sec_audit_report_fail 285 "Audit configuration files have overly permissive permissions"
fi

if [ "$(stat -c %U /etc/audit/audit.rules)" = "root" ] && [ "$(stat -c %U /etc/audit/rules.d/*)" = "root" ]; then
    sec_audit_report_pass 286 "Audit configuration files are owned by root"
else
    sec_audit_report_fail 286 "Audit configuration files are not owned by root"
fi

if [ "$(stat -c %G /etc/audit/audit.rules)" = "root" ] && [ "$(stat -c %G /etc/audit/rules.d/*)" = "root" ]; then
    sec_audit_report_pass 287 "Audit configuration files belong to group root"
else
    sec_audit_report_fail 287 "Audit configuration files do not belong to group root"
fi

COUNT=0
for tool in /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules; do
    if [ -f "$tool" ] && [ "$(stat -c %a "$tool")" -gt 755 ]; then
      ((COUNT++))
    fi
done
if [ "$COUNT" -eq 0 ]; then
  sec_audit_report_pass 288 "All audit tools have correct permissions (755 or stricter)"
elif [ "$COUNT" -gt 0 ]; then
  sec_audit_report_fail 288 "audit tools has overly permissive permissions"
fi

COUNT=0
for tool in /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules; do
    if [ -f "$tool" ] && [ "$(stat -c %U "$tool")" != "root" ]; then
      ((COUNT++))
    fi
done
if [ "$COUNT" -eq 0 ]; then
  sec_audit_report_pass 289 "All audit tools are owned by root"
elif [ "$COUNT" -gt 0 ]; then
  sec_audit_report_fail 289 "$tool is not owned by root"
fi

COUNT=0
for tool in /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules; do
    if [ -f "$tool" ] && [ "$(stat -c %G "$tool")" != "root" ]; then
        ((COUNT++))
    fi
done
if [ "$COUNT" -eq 0 ]; then
  sec_audit_report_pass 290 "All audit tools belong to group root"
elif [ "$COUNT" -gt 0 ]; then
          sec_audit_report_fail 290 "$tool does not belong to group root"
fi

if sec_audit_have_bin aide && aide --check 2>/dev/null | grep -q "No changes"; then
    sec_audit_report_pass 291 "AIDE is installed and audit tools integrity is verified"
else
    sec_audit_report_fail 291 "AIDE detected changes in audit tools or AIDE is not installed (required for integrity checking)"
fi

permissions=$(stat -c %a /etc/shells)
owner=$(stat -c %U /etc/shells)
group=$(stat -c %G /etc/shells)
if [ "$permissions" -eq 644 ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
    sec_audit_report_pass 292 "/etc/shells has correct permissions (644), owner (root), and group (root)."
else
    sec_audit_report_fail 292 "/etc/shells has incorrect permissions ($permissions), owner ($owner), or group ($group). Expected: 644, root, root or /etc/shells does not exist."
fi

permissions=$(stat -c %a /etc/opasswd)
owner=$(stat -c %U /etc/opasswd)
group=$(stat -c %G /etc/opasswd)
if [[ "$permissions" -eq 600 ]] && [[ "$owner" = "root" ]] && [[ "$group" = "root" ]]; then
    sec_audit_report_pass 293 "/etc/opasswd has correct permissions (600), owner (root), and group (root)."
else
    sec_audit_report_fail 293 "/etc/opasswd has incorrect permissions ($permissions), owner ($owner), or group ($group). Expected: 600, root, root or /etc/opasswd does not exist (this may be acceptable depending on system configuration)."
fi

accounts_with_passwords=$(awk -F: '($2 != "x" && $2 != "") {print $1}' /etc/passwd)
if [ -z "$accounts_with_passwords" ]; then
    sec_audit_report_pass 294 "All accounts use shadowed passwords (no passwords found in /etc/passwd)."
else
    sec_audit_report_fail 294 "The accounts have passwords stored in /etc/passwd or Required files (/etc/passwd or /etc/shadow) are missing."
fi

home_dirs=$(awk -F: '($3 >= 1000 && $3 != 65534) {print $6}' /etc/passwd)
invalid_files=""
for dir in $home_dirs; do
    if [ -d "$dir" ]; then
        files=$(find "$dir" -maxdepth 1 -type f -name ".*")
        for file in $files; do
            permissions=$(stat -c %a "$file")
            owner=$(stat -c %U "$file")
            if [ "$owner" != "root" ] && [ "$permissions" -gt 740 ]; then
                invalid_files+="$file (permissions: $permissions, owner: $owner)\n"
            fi
        done
    fi
done
if [ -z "$invalid_files" ]; then
    sec_audit_report_pass 295 "All user dot files have correct permissions (<= 740) and ownership."
else
    sec_audit_report_fail 295 "The following dot files have excessive permissions or incorrect ownership: $invalid_files"
fi

exit 0

