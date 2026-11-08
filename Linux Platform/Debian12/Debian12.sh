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

DEB12_FIND_CAP="${DEB12_FIND_CAP:-${CRE_FIND_CAP:-20}}"
CRE_FIND_CAP="${DEB12_FIND_CAP}"
DEB12_CMD_CAP="${DEB12_CMD_CAP:-${CRE_CMD_CAP:-12}}"
CRE_CMD_CAP="${DEB12_CMD_CAP}"
DEB12_DNF_CAP="${DEB12_DNF_CAP:-${CRE_DNF_CAP:-30}}"
CRE_DNF_CAP="${DEB12_DNF_CAP}"
DEB12_ALLOW_CONTAINER_KMOD="${DEB12_ALLOW_CONTAINER_KMOD:-${CRE_ALLOW_CONTAINER_KMOD:-${LINUX_CRE_ALLOW_CONTAINER_MODULES:-${ALMA_CRE_ALLOW_CONTAINER_MODULES:-0}}}}"
CRE_ALLOW_CONTAINER_KMOD="${DEB12_ALLOW_CONTAINER_KMOD}"
# --- bootstrap / reporting ---
# Normalize leading-zero CIS ids (010 -> 10) so RULE* matches profile_rules.json.
sec_audit_report_pass() { printf 'RULE%d= PASS: %s\n' "$((10#$1))" "$2"; }
sec_audit_report_fail() { printf 'RULE%d= FAIL: %s\n' "$((10#$1))" "${3:-$2}"; }
sec_audit_report_skip() { printf 'RULE%d= SKIP: %s\n' "$((10#$1))" "$2"; }
sec_audit_report_error() { printf 'RULE%d= ERROR: %s\n' "$((10#$1))" "$2"; }

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
        sec_audit_report_pass "$num" "${label} (waived: DEB12_ALLOW_CONTAINER_KMOD=1)"
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
    [ "$_SSHD_T_READY" -eq 1 ] && return 0
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
    [ "$_AUDITCTL_L_READY" -eq 1 ] && return 0
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

sec_audit_debian12_sysctl_multi_rule() {
    local num=$((10#$1)) pass_msg="$2" fail_msg="$3" key want
    shift 3
    while [ $# -gt 0 ]; do
        key=$1
        want=$2
        shift 2
        if ! sec_audit_sysctl_runtime_equals "$key" "$want"; then
            echo "RULE${num}= FAIL: ${fail_msg}"
            return 0
        fi
    done
    echo "RULE${num}= PASS: ${pass_msg}"
}

_audit_rules_files_ready=0
_audit_rules_files_cache=""

sec_audit_audit_rules_files_ensure() {
    [ "$_audit_rules_files_ready" -eq 1 ] && return 0
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

sec_audit_sshd_d12_equals() {
    local num=$((10#$1)) key="$2" want="$3" pass_msg="$4" fail_msg="$5"
    if sec_audit_sshd_effective_equals "$key" "$want"; then
        echo "RULE${num}= PASS: ${pass_msg}"
    else
        echo "RULE${num}= FAIL: ${fail_msg}"
    fi
}
sec_audit_debian12_mount_opt_rule() {
    local num=$((10#$1)) mp="$2" opt="$3" msg="$4"
    if sec_audit_mount_has_option "$mp" "$opt"; then
        echo "RULE${num}= PASS: ${msg}"
    else
        echo "RULE${num}= FAIL: ${opt} option not set on ${mp}"
    fi
}

sec_audit_assert_kmod_disabled 1 cramfs "cramfs.ko*"
sec_audit_assert_kmod_disabled 2 freevxfs "freevxfs.ko*"
sec_audit_assert_kmod_disabled 3 hfs "hfs.ko*"
sec_audit_assert_kmod_disabled 4 hfsplus "hfsplus.ko*"
sec_audit_assert_kmod_disabled 5 jffs2 "jffs2.ko*"
sec_audit_assert_kmod_disabled 6 overlay "overlay.ko*" overlay overlayfs
sec_audit_assert_kmod_disabled 7 squashfs "squashfs.ko*"
sec_audit_assert_kmod_disabled 8 udf "udf.ko*"
sec_audit_assert_kmod_disabled 9 usb-storage "usb-storage.ko*" usb_storage "usb-storage"

if sec_audit_tmp_is_isolated; then
    sec_audit_report_pass 010 "/tmp is mounted on a separate partition"
else
    sec_audit_report_fail 010 "/tmp is not mounted on a separate partition (not tmpfs or separate source)"
fi
sec_audit_debian12_mount_opt_rule 11 /tmp nodev "nodev option set on /tmp partition"
sec_audit_debian12_mount_opt_rule 12 /tmp nosuid "nosuid option set on /tmp partition"
sec_audit_debian12_mount_opt_rule 13 /tmp noexec "noexec option set on /tmp partition"
if sec_audit_shm_is_isolated; then
    sec_audit_report_pass 014 "/dev/shm is mounted on a separate partition"
else
    sec_audit_report_fail 014 "/dev/shm is not mounted on a separate partition"
fi
sec_audit_debian12_mount_opt_rule 15 /dev/shm nodev "nodev option set on /dev/shm partition"
sec_audit_debian12_mount_opt_rule 16 /dev/shm nosuid "nosuid option set on /dev/shm partition"
sec_audit_debian12_mount_opt_rule 17 /dev/shm noexec "noexec option set on /dev/shm partition"
sec_audit_debian12_mount_opt_rule 18 /home nodev "nodev option set on /home partition"
sec_audit_debian12_mount_opt_rule 19 /home nosuid "nosuid option set on /home partition"
sec_audit_debian12_mount_opt_rule 20 /var nodev "nodev option set on /var partition"
sec_audit_debian12_mount_opt_rule 21 /var nosuid "nosuid option set on /var partition"
sec_audit_debian12_mount_opt_rule 22 /var/tmp nodev "nodev option set on /var/tmp partition"
sec_audit_debian12_mount_opt_rule 23 /var/tmp nosuid "nosuid option set on /var/tmp partition"
sec_audit_debian12_mount_opt_rule 24 /var/tmp noexec "noexec option set on /var/tmp partition"
sec_audit_debian12_mount_opt_rule 25 /var/log nodev "nodev option set on /var/log partition"
sec_audit_debian12_mount_opt_rule 26 /var/log nosuid "nosuid option set on /var/log partition"
sec_audit_debian12_mount_opt_rule 27 /var/log noexec "noexec option set on /var/log partition"
sec_audit_debian12_mount_opt_rule 28 /var/log/audit nodev "nodev option set on /var/log/audit partition"
sec_audit_debian12_mount_opt_rule 29 /var/log/audit nosuid "nosuid option set on /var/log/audit partition"
sec_audit_debian12_mount_opt_rule 30 /var/log/audit noexec "noexec option set on /var/log/audit partition"

if find /etc/apt/trusted.gpg.d/ -name '*.gpg' 2>/dev/null | grep -q . || \
   find /etc/apt/keyrings/ -type f 2>/dev/null | grep -q . || \
   gpg --list-keys --keyring /etc/apt/trusted.gpg 2>/dev/null | grep -q '^pub'; then
  sec_audit_report_pass 031 "GPG keys are configured for package repositories"
else
  sec_audit_report_fail 031 "requirement not met ()"
fi

if apt-cache policy 2>/dev/null | grep -q "http\|file"; then
  sec_audit_report_pass 032 "package manager repositories are configured"
else
  sec_audit_report_fail 032 "requirement not met ()"
fi

upgradable=$(apt-get -s upgrade 2>/dev/null | grep -c "^Inst " || true)
if [ "$upgradable" -eq 0 ]; then
  sec_audit_report_pass 033 "updates, patches, and security software are installed"
else
  sec_audit_report_fail 033 "requirement not met ()"
fi

if dpkg -s apparmor &>/dev/null 2>&1; then
  sec_audit_report_pass 034 "AppArmor package is installed"
else
  sec_audit_report_fail 034 "requirement not met ()"
fi

if grep -qP '^\s*GRUB_CMDLINE_LINUX\s*=.*\bapparmor=1\b' /etc/default/grub 2>/dev/null && \
   grep -qP '^\s*GRUB_CMDLINE_LINUX\s*=.*\bsecurity=apparmor\b' /etc/default/grub 2>/dev/null; then
  sec_audit_report_pass 035 "AppArmor enabled in bootloader configuration"
else
  sec_audit_report_fail 035 "requirement not met ()"
fi

if grep -qP '^\s*set\s+superusers=' /boot/grub/grub.cfg 2>/dev/null || \
   grep -qP '^\s*password' /boot/grub/grub.cfg 2>/dev/null; then
  sec_audit_report_pass 036 "bootloader password is set"
else
  sec_audit_report_fail 036 "requirement not met ()"
fi

_perm=$(stat -Lc "%a %u %g" /boot/grub/grub.cfg 2>/dev/null)
_mode=$(echo "$_perm" | awk '{print $1}')
_owner=$(echo "$_perm" | awk '{print $2}')
_group=$(echo "$_perm" | awk '{print $3}')
if [ "$_owner" = "0" ] && [ "$_group" = "0" ] && [[ "$_mode" =~ ^[0-6]00$ ]]; then
  sec_audit_report_pass 037 "bootloader config access restricted"
else
  sec_audit_report_fail 037 "requirement not met ()"
fi

if sec_audit_sysctl_runtime_equals kernel.randomize_va_space 2; then
  sec_audit_report_pass 038 "ASLR enabled"
else
  r=$(sec_audit_sysctl_runtime kernel.randomize_va_space)
  sec_audit_report_fail 038 "ASLR not enabled (kernel.randomize_va_space=${r:-?})"
fi

_ps=$(sec_audit_sysctl_runtime kernel.yama.ptrace_scope)
if [[ "${_ps:-}" =~ ^[123]$ ]]; then
  sec_audit_report_pass 039 "ptrace_scope restricted"
else
  sec_audit_report_fail 039 "ptrace_scope not restricted (value=${_ps:-unset})"
fi

if sec_audit_core_dumps_limited && sec_audit_sysctl_runtime_equals fs.suid_dumpable 0; then
  sec_audit_report_pass 040 "core dumps restricted"
else
  sec_audit_report_fail 040 "core dumps not fully restricted (limits/systemd/sysctl)"
fi

if [ -f /etc/motd ]; then
  if ! grep -qPi '(\\\v|\\\r|\\\m|\\\s|debian|ubuntu|linux)' /etc/motd 2>/dev/null; then
    sec_audit_report_pass 041 "/etc/motd configured"
  else
    sec_audit_report_fail 041 "requirement not met ()"
  fi
else
  sec_audit_report_pass 041 "/etc/motd configured"
fi

if [ -f /etc/issue ]; then
  if ! grep -qPi '(\\\v|\\\r|\\\m|\\\s)' /etc/issue 2>/dev/null; then
    sec_audit_report_pass 042 "local login banner configured"
  else
    sec_audit_report_fail 042 "requirement not met ()"
  fi
else
  sec_audit_report_fail 042 "requirement not met ()"
fi

if [ -f /etc/issue.net ]; then
  if ! grep -qPi '(\\\v|\\\r|\\\m|\\\s)' /etc/issue.net 2>/dev/null; then
    sec_audit_report_pass 043 "remote login banner configured"
  else
    sec_audit_report_fail 043 "requirement not met ()"
  fi
else
  sec_audit_report_fail 043 "requirement not met ()"
fi

_mp=$(stat -Lc "%a %u %g" /etc/motd 2>/dev/null)
if [ "$(echo "$_mp" | awk '{print $2}')" = "0" ] && [ "$(echo "$_mp" | awk '{print $3}')" = "0" ] && \
   [ "$(echo "$_mp" | awk '{print $1}')" = "644" ]; then
  sec_audit_report_pass 044 "/etc/motd access restricted"
else
  sec_audit_report_fail 044 "requirement not met ()"
fi

_ip=$(stat -Lc "%a %u %g" /etc/issue 2>/dev/null)
if [ "$(echo "$_ip" | awk '{print $2}')" = "0" ] && [ "$(echo "$_ip" | awk '{print $3}')" = "0" ] && \
   [ "$(echo "$_ip" | awk '{print $1}')" = "644" ]; then
  sec_audit_report_pass 045 "/etc/issue access restricted"
else
  sec_audit_report_fail 045 "requirement not met ()"
fi

_inp=$(stat -Lc "%a %u %g" /etc/issue.net 2>/dev/null)
if [ "$(echo "$_inp" | awk '{print $2}')" = "0" ] && [ "$(echo "$_inp" | awk '{print $3}')" = "0" ] && \
   [ "$(echo "$_inp" | awk '{print $1}')" = "644" ]; then
  sec_audit_report_pass 046 "/etc/issue.net access restricted"
else
  sec_audit_report_fail 046 "requirement not met ()"
fi

if ! dpkg -s gdm3 &>/dev/null 2>&1; then
  sec_audit_report_pass 047 "GDM package not installed"
else
  sec_audit_report_fail 047 "requirement not met ()"
fi

if grep -qP '^\s*banner-message-enable\s*=\s*true' /etc/gdm3/greeter.dconf-defaults 2>/dev/null || \
   find /etc/dconf/db/gdm.d/ -type f 2>/dev/null | xargs grep -lqP 'banner-message-enable\s*=\s*true' 2>/dev/null; then
  sec_audit_report_pass 048 "GDM login banner configured"
else
  if ! dpkg -s gdm3 &>/dev/null 2>&1; then
    sec_audit_report_pass 048 "GDM login banner configured"
  else
    sec_audit_report_fail 048 "requirement not met ()"
  fi
fi

if grep -qP '^\s*disable-user-list\s*=\s*true' /etc/gdm3/greeter.dconf-defaults 2>/dev/null || \
   find /etc/dconf/db/gdm.d/ -type f 2>/dev/null | xargs grep -lqP 'disable-user-list\s*=\s*true' 2>/dev/null; then
  sec_audit_report_pass 049 "disable-user-list enabled in GDM"
else
  if ! dpkg -s gdm3 &>/dev/null 2>&1; then
    sec_audit_report_pass 049 "disable-user-list enabled in GDM"
  else
    sec_audit_report_fail 049 "requirement not met ()"
  fi
fi

if ! dpkg -s gdm3 &>/dev/null 2>&1; then
  sec_audit_report_pass 050 "GDM configured to lock screen on idle"
elif find /etc/dconf/db/ -type f 2>/dev/null | xargs grep -lqP 'idle-delay' 2>/dev/null; then
  sec_audit_report_pass 050 "GDM configured to lock screen on idle"
else
  sec_audit_report_fail 050 "requirement not met ()"
fi

if ! dpkg -s gdm3 &>/dev/null 2>&1; then
  sec_audit_report_pass 051 "screen lock settings enforced"
elif find /etc/dconf/db/ -type f -name "locks*" 2>/dev/null | xargs grep -lq 'lock-delay\|idle-delay' 2>/dev/null; then
  sec_audit_report_pass 051 "screen lock settings enforced"
else
  sec_audit_report_fail 051 "requirement not met ()"
fi

if ! dpkg -s gdm3 &>/dev/null 2>&1; then
  sec_audit_report_pass 052 "GDM automatic mounting disabled"
elif find /etc/dconf/db/ -type f 2>/dev/null | xargs grep -lqP 'automount\s*=\s*false' 2>/dev/null; then
  sec_audit_report_pass 052 "GDM automatic mounting disabled"
else
  sec_audit_report_fail 052 "requirement not met ()"
fi

if ! dpkg -s gdm3 &>/dev/null 2>&1; then
  sec_audit_report_pass 053 "automount disable enforced"
elif find /etc/dconf/db/ -type f -name "locks*" 2>/dev/null | xargs grep -lq 'automount' 2>/dev/null; then
  sec_audit_report_pass 053 "automount disable enforced"
else
  sec_audit_report_fail 053 "requirement not met ()"
fi

if ! dpkg -s gdm3 &>/dev/null 2>&1; then
  sec_audit_report_pass 054 "autorun-never enabled in GDM"
elif find /etc/dconf/db/ -type f 2>/dev/null | xargs grep -lqP 'autorun-never\s*=\s*true' 2>/dev/null; then
  sec_audit_report_pass 054 "autorun-never enabled in GDM"
else
  sec_audit_report_fail 054 "requirement not met ()"
fi

if ! dpkg -s gdm3 &>/dev/null 2>&1; then
  sec_audit_report_pass 055 "autorun-never enforced"
elif find /etc/dconf/db/ -type f -name "locks*" 2>/dev/null | xargs grep -lq 'autorun-never' 2>/dev/null; then
  sec_audit_report_pass 055 "autorun-never enforced"
else
  sec_audit_report_fail 055 "requirement not met ()"
fi

if ! dpkg -s gdm3 &>/dev/null 2>&1; then
  sec_audit_report_pass 056 "XDMCP not enabled in GDM"
elif ! grep -qP '^\s*Enable\s*=\s*true' /etc/gdm3/custom.conf 2>/dev/null; then
  sec_audit_report_pass 056 "XDMCP not enabled in GDM"
else
  sec_audit_report_fail 056 "requirement not met ()"
fi

if ! dpkg -s chargen 2>/dev/null | grep -q "^Status.*installed" && \
   ! systemctl is-enabled chargen 2>/dev/null | grep -q enabled; then
  sec_audit_report_pass 057 "chargen services not enabled"
else
  sec_audit_report_fail 057 "requirement not met ()"
fi

if ! dpkg -s daytime 2>/dev/null | grep -q "^Status.*installed" && \
   ! systemctl is-enabled daytime 2>/dev/null | grep -q enabled; then
  sec_audit_report_pass 058 "daytime services not enabled"
else
  sec_audit_report_fail 058 "requirement not met ()"
fi

if ! dpkg -s discard 2>/dev/null | grep -q "^Status.*installed" && \
   ! systemctl is-enabled discard 2>/dev/null | grep -q enabled; then
  sec_audit_report_pass 059 "discard services not enabled"
else
  sec_audit_report_fail 059 "requirement not met ()"
fi

if ! dpkg -s echo 2>/dev/null | grep -q "^Status.*installed" && \
   ! systemctl is-enabled echo 2>/dev/null | grep -q "^enabled"; then
  sec_audit_report_pass 060 "echo services not enabled"
else
  sec_audit_report_fail 060 "requirement not met ()"
fi

if ! dpkg -s time 2>/dev/null | grep -q "^Status.*installed" && \
   ! systemctl is-enabled time-dgram.socket time-stream.socket 2>/dev/null | grep -q "^enabled"; then
  sec_audit_report_pass 061 "time services not enabled"
else
  sec_audit_report_fail 061 "requirement not met ()"
fi

if ! dpkg -s tftpd tftpd-hpa 2>/dev/null | grep -q "^Status.*installed" && \
   ! systemctl is-enabled tftpd.service tftp.socket tftpd-hpa 2>/dev/null | grep -q "^enabled"; then
  sec_audit_report_pass 062 "tftp server not enabled"
else
  sec_audit_report_fail 062 "requirement not met ()"
fi

if ! dpkg -s talkd 2>/dev/null | grep -q "^Status.*installed"; then
  sec_audit_report_pass 063 "talk server not enabled"
else
  sec_audit_report_fail 063 "requirement not met ()"
fi

if ! dpkg -s telnetd 2>/dev/null | grep -q "^Status.*installed" && \
   ! systemctl is-enabled telnet.socket 2>/dev/null | grep -q "^enabled"; then
  sec_audit_report_pass 064 "telnet server not enabled"
else
  sec_audit_report_fail 064 "requirement not met ()"
fi

if ! dpkg -s rsh-server 2>/dev/null | grep -q "^Status.*installed"; then
  sec_audit_report_pass 065 "rsh server not enabled"
else
  sec_audit_report_fail 065 "requirement not met ()"
fi

if ! systemctl is-enabled rsync 2>/dev/null | grep -q "^enabled"; then
  sec_audit_report_pass 066 "rsync service not enabled"
else
  sec_audit_report_fail 066 "requirement not met ()"
fi

if ! dpkg -s nis 2>/dev/null | grep -q "^Status.*installed" && \
   ! systemctl is-enabled ypserv 2>/dev/null | grep -q "^enabled"; then
  sec_audit_report_pass 067 "NIS server not enabled"
else
  sec_audit_report_fail 067 "requirement not met ()"
fi

if ! dpkg -s nis 2>/dev/null | grep -q "^Status.*installed"; then
  sec_audit_report_pass 068 "NIS client not installed"
else
  sec_audit_report_fail 068 "requirement not met ()"
fi

if ! dpkg -s rsh-client 2>/dev/null | grep -q "^Status.*installed"; then
  sec_audit_report_pass 069 "rsh client not installed"
else
  sec_audit_report_fail 069 "requirement not met ()"
fi

if ! dpkg -s talk 2>/dev/null | grep -q "^Status.*installed"; then
  sec_audit_report_pass 070 "talk client not installed"
else
  sec_audit_report_fail 070 "requirement not met ()"
fi

if ! dpkg -s telnet 2>/dev/null | grep -q "^Status.*installed"; then
  sec_audit_report_pass 071 "telnet client not installed"
else
  sec_audit_report_fail 071 "requirement not met ()"
fi

if ! dpkg -s ldap-utils 2>/dev/null | grep -q "^Status.*installed"; then
  sec_audit_report_pass 072 "LDAP client not installed"
else
  sec_audit_report_fail 072 "requirement not met ()"
fi

if systemctl is-active ntp &>/dev/null || systemctl is-active chrony &>/dev/null || \
   systemctl is-active systemd-timesyncd &>/dev/null; then
  sec_audit_report_pass 073 "NTP configured properly"
else
  sec_audit_report_fail 073 "requirement not met ()"
fi

if grep -qP '^\s*restrict\s+(-4\s+)?default\s+.*kod' /etc/ntp.conf 2>/dev/null || \
   [ -f /etc/chrony/chrony.conf ] || [ -f /etc/systemd/timesyncd.conf ]; then
  sec_audit_report_pass 074 "NTP restrict options configured"
else
  sec_audit_report_fail 074 "requirement not met ()"
fi

if ! dpkg -s xserver-xorg 2>/dev/null | grep -q "^Status.*installed" && \
   ! dpkg -l 'xserver-xorg*' 2>/dev/null | grep -q '^ii'; then
  sec_audit_report_pass 075 "X Window System not installed"
else
  sec_audit_report_fail 075 "requirement not met ()"
fi

sec_audit_debian12_sysctl_multi_rule 76 "packet redirect sending disabled" "packet redirect sending not disabled" \
    net.ipv4.conf.all.send_redirects 0 net.ipv4.conf.default.send_redirects 0

sec_audit_debian12_sysctl_multi_rule 77 "IP forwarding disabled" "IP forwarding enabled" \
    net.ipv4.ip_forward 0 net.ipv6.conf.all.forwarding 0

sec_audit_debian12_sysctl_multi_rule 78 "source routed packets rejected" "source routed packets accepted" \
    net.ipv4.conf.all.accept_source_route 0 net.ipv4.conf.default.accept_source_route 0 \
    net.ipv6.conf.all.accept_source_route 0 net.ipv6.conf.default.accept_source_route 0

sec_audit_debian12_sysctl_multi_rule 79 "ICMP redirects not accepted" "ICMP redirects accepted" \
    net.ipv4.conf.all.accept_redirects 0 net.ipv4.conf.default.accept_redirects 0 \
    net.ipv6.conf.all.accept_redirects 0 net.ipv6.conf.default.accept_redirects 0

sec_audit_debian12_sysctl_multi_rule 80 "secure ICMP redirects not accepted" "secure ICMP redirects accepted" \
    net.ipv4.conf.all.secure_redirects 0 net.ipv4.conf.default.secure_redirects 0

sec_audit_debian12_sysctl_multi_rule 81 "suspicious packets logged" "suspicious packets not logged" \
    net.ipv4.conf.all.log_martians 1 net.ipv4.conf.default.log_martians 1

sec_audit_debian12_sysctl_multi_rule 82 "broadcast ICMP requests ignored" "broadcast ICMP not ignored" \
    net.ipv4.icmp_echo_ignore_broadcasts 1

sec_audit_debian12_sysctl_multi_rule 83 "bogus ICMP responses ignored" "bogus ICMP not ignored" \
    net.ipv4.icmp_ignore_bogus_error_responses 1

sec_audit_debian12_sysctl_multi_rule 84 "Reverse Path Filtering enabled" "Reverse Path Filtering disabled" \
    net.ipv4.conf.all.rp_filter 1 net.ipv4.conf.default.rp_filter 1

sec_audit_debian12_sysctl_multi_rule 85 "TCP SYN Cookies enabled" "TCP SYN Cookies disabled" \
    net.ipv4.tcp_syncookies 1

sec_audit_debian12_sysctl_multi_rule 86 "IPv6 router advertisements not accepted" "IPv6 router advertisements accepted" \
    net.ipv6.conf.all.accept_ra 0 net.ipv6.conf.default.accept_ra 0

sec_audit_debian12_sysctl_multi_rule 87 "IPv6 redirects not accepted" "IPv6 redirects accepted" \
    net.ipv6.conf.all.accept_redirects 0 net.ipv6.conf.default.accept_redirects 0

if systemctl is-active auditd &>/dev/null; then
  sec_audit_report_pass 088 "auditd enabled and running"
else
  sec_audit_report_fail 088 "requirement not met ()"
fi

if systemctl is-enabled auditd 2>/dev/null | grep -q "^enabled"; then
  sec_audit_report_pass 089 "auditd service enabled"
else
  sec_audit_report_fail 089 "requirement not met ()"
fi

if grep -qP '\baudit=1\b' /proc/cmdline 2>/dev/null || \
   grep -qP '^\s*GRUB_CMDLINE_LINUX\s*=.*\baudit=1\b' /etc/default/grub 2>/dev/null; then
  sec_audit_report_pass 090 "auditing enabled at boot"
else
  sec_audit_report_fail 090 "requirement not met ()"
fi

_abl=$(grep -oP '\baudit_backlog_limit=\K[0-9]+' /proc/cmdline 2>/dev/null || \
       grep -oP '^\s*GRUB_CMDLINE_LINUX\s*=.*audit_backlog_limit=\K[0-9]+' /etc/default/grub 2>/dev/null | tail -1)
if [ -n "$_abl" ] && [ "$_abl" -ge 8192 ] 2>/dev/null; then
  sec_audit_report_pass 091 "audit_backlog_limit sufficient"
else
  sec_audit_report_fail 091 "requirement not met ()"
fi

if grep -qP '^\s*max_log_file\s*=' /etc/audit/auditd.conf 2>/dev/null; then
  sec_audit_report_pass 092 "audit log storage configured"
else
  sec_audit_report_fail 092 "requirement not met ()"
fi

_mla=$(grep -iP '^\s*max_log_file_action\s*=' /etc/audit/auditd.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
if echo "$_mla" | grep -qiP '^keep_logs$'; then
  sec_audit_report_pass 093 "audit logs retention configured"
else
  sec_audit_report_fail 093 "requirement not met ()"
fi

_sla=$(grep -iP '^\s*space_left_action\s*=' /etc/audit/auditd.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' | tr '[:upper:]' '[:lower:]')
_asla=$(grep -iP '^\s*admin_space_left_action\s*=' /etc/audit/auditd.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' | tr '[:upper:]' '[:lower:]')
if echo "$_asla" | grep -qP '^(halt|single)$'; then
  sec_audit_report_pass 094 "auditd configured to halt or single mode on full"
else
  sec_audit_report_fail 094 "requirement not met ()"
fi

_nl=$(grep -iP '^\s*num_logs\s*=' /etc/audit/auditd.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
if [ -n "$_nl" ] && [ "$_nl" -ge 5 ] 2>/dev/null; then
  sec_audit_report_pass 095 "audit logs rotation configured"
else
  sec_audit_report_fail 095 "requirement not met ()"
fi

if grep -qP '^\s*-e\s+2' /etc/audit/rules.d/*.rules /etc/audit/audit.rules 2>/dev/null; then
  sec_audit_report_pass 096 "audit rules immutable"
else
  sec_audit_report_fail 096 "requirement not met ()"
fi

if dpkg -s rsyslog &>/dev/null 2>&1; then
  sec_audit_report_pass 097 "rsyslog installed"
else
  sec_audit_report_fail 097 "requirement not met ()"
fi

if systemctl is-enabled rsyslog 2>/dev/null | grep -q "^enabled"; then
  sec_audit_report_pass 098 "rsyslog enabled"
else
  sec_audit_report_fail 098 "requirement not met ()"
fi

if grep -qP '^\s*ForwardToSyslog\s*=\s*yes' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null; then
  sec_audit_report_pass 099 "journald forwards to rsyslog"
else
  sec_audit_report_fail 099 "requirement not met ()"
fi

if grep -qP '^\s*Compress\s*=\s*yes' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null; then
  sec_audit_report_pass 100 "journald compression enabled"
else
  sec_audit_report_fail 100 "requirement not met ()"
fi

if grep -qP '^\s*Storage\s*=\s*persistent' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null; then
  sec_audit_report_pass 101 "journald persistent storage enabled"
else
  sec_audit_report_fail 101 "requirement not met ()"
fi

if [ -f /etc/logrotate.conf ] && find /etc/logrotate.d/ -type f 2>/dev/null | grep -q .; then
  sec_audit_report_pass 102 "logrotate configured"
else
  sec_audit_report_fail 102 "requirement not met ()"
fi

if systemctl is-enabled cron 2>/dev/null | grep -q "^enabled"; then
  sec_audit_report_pass 103 "cron service enabled"
else
  sec_audit_report_fail 103 "requirement not met ()"
fi

_cp=$(stat -Lc "%a %u %g" /etc/crontab 2>/dev/null)
if [ "$(echo "$_cp" | awk '{print $2}')" = "0" ] && [ "$(echo "$_cp" | awk '{print $3}')" = "0" ] && \
   [ "$(echo "$_cp" | awk '{print $1}')" = "600" ]; then
  sec_audit_report_pass 104 "/etc/crontab permissions configured"
else
  sec_audit_report_fail 104 "requirement not met ()"
fi

_chp=$(stat -Lc "%a %u %g" /etc/cron.hourly 2>/dev/null)
if [ "$(echo "$_chp" | awk '{print $2}')" = "0" ] && [ "$(echo "$_chp" | awk '{print $3}')" = "0" ] && \
   [ "$(echo "$_chp" | awk '{print $1}')" = "700" ]; then
  sec_audit_report_pass 105 "/etc/cron.hourly permissions configured"
else
  sec_audit_report_fail 105 "requirement not met ()"
fi

_cdp=$(stat -Lc "%a %u %g" /etc/cron.daily 2>/dev/null)
if [ "$(echo "$_cdp" | awk '{print $2}')" = "0" ] && [ "$(echo "$_cdp" | awk '{print $3}')" = "0" ] && \
   [ "$(echo "$_cdp" | awk '{print $1}')" = "700" ]; then
  sec_audit_report_pass 106 "/etc/cron.daily permissions configured"
else
  sec_audit_report_fail 106 "requirement not met ()"
fi

_cwp=$(stat -Lc "%a %u %g" /etc/cron.weekly 2>/dev/null)
if [ "$(echo "$_cwp" | awk '{print $2}')" = "0" ] && [ "$(echo "$_cwp" | awk '{print $3}')" = "0" ] && \
   [ "$(echo "$_cwp" | awk '{print $1}')" = "700" ]; then
  sec_audit_report_pass 107 "/etc/cron.weekly permissions configured"
else
  sec_audit_report_fail 107 "requirement not met ()"
fi

_cmp=$(stat -Lc "%a %u %g" /etc/cron.monthly 2>/dev/null)
if [ "$(echo "$_cmp" | awk '{print $2}')" = "0" ] && [ "$(echo "$_cmp" | awk '{print $3}')" = "0" ] && \
   [ "$(echo "$_cmp" | awk '{print $1}')" = "700" ]; then
  sec_audit_report_pass 108 "/etc/cron.monthly permissions configured"
else
  sec_audit_report_fail 108 "requirement not met ()"
fi

_cdirp=$(stat -Lc "%a %u %g" /etc/cron.d 2>/dev/null)
if [ "$(echo "$_cdirp" | awk '{print $2}')" = "0" ] && [ "$(echo "$_cdirp" | awk '{print $3}')" = "0" ] && \
   [ "$(echo "$_cdirp" | awk '{print $1}')" = "700" ]; then
  sec_audit_report_pass 109 "/etc/cron.d permissions configured"
else
  sec_audit_report_fail 109 "requirement not met ()"
fi

if [ -f /etc/cron.allow ] && [ ! -f /etc/cron.deny ] || \
   [ -f /etc/cron.allow ] && [ ! -s /etc/cron.deny ]; then
  sec_audit_report_pass 110 "cron and at access restricted"
else
  sec_audit_report_fail 110 "requirement not met ()"
fi

if dpkg -s libpam-pwquality &>/dev/null 2>&1 && \
   grep -qP 'pam_pwquality' /etc/pam.d/common-password 2>/dev/null; then
  sec_audit_report_pass 111 "password quality requirements configured"
else
  sec_audit_report_fail 111 "requirement not met ()"
fi

if grep -qP 'pam_faillock|pam_tally2' /etc/pam.d/common-auth /etc/pam.d/common-account 2>/dev/null; then
  sec_audit_report_pass 112 "faillock configured"
else
  sec_audit_report_fail 112 "requirement not met ()"
fi

if grep -qP 'sha512' /etc/pam.d/common-password 2>/dev/null || \
   grep -qP '^ENCRYPT_METHOD\s+SHA512' /etc/login.defs 2>/dev/null; then
  sec_audit_report_pass 113 "password hashing uses SHA-512"
else
  sec_audit_report_fail 113 "requirement not met ()"
fi

_csl=$(cat /etc/securetty 2>/dev/null | grep -cP '^\s*(console|tty[0-9]+)\s*$' || true)
if [ "$_csl" -gt 0 ] 2>/dev/null; then
  sec_audit_report_pass 114 "root login restricted to console"
else
  sec_audit_report_fail 114 "requirement not met ()"
fi

if grep -qP '^\s*auth\s+required\s+pam_wheel\.so' /etc/pam.d/su 2>/dev/null; then
  sec_audit_report_pass 115 "su access restricted to wheel group"
else
  sec_audit_report_fail 115 "requirement not met ()"
fi

if dpkg -s sudo &>/dev/null 2>&1; then
  sec_audit_report_pass 116 "sudo installed"
else
  sec_audit_report_fail 116 "requirement not met ()"
fi

if grep -qP '^\s*Defaults\s+.*requiretty' /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
  sec_audit_report_pass 117 "requiretty set for sudo"
else
  sec_audit_report_fail 117 "requirement not met ()"
fi

if grep -qP '^\s*Defaults\s+.*logfile\s*=' /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
  sec_audit_report_pass 118 "sudo log file configured"
else
  sec_audit_report_fail 118 "requirement not met ()"
fi

if grep -qP '^\s*[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
  sec_audit_report_fail 119 "requirement not met ()"
else
  sec_audit_report_pass 119 "sudo requires password"
fi

_tto=$(grep -oP 'timestamp_timeout\s*=\s*\K\-?[0-9]+' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | head -1)
if [ "$_tto" = "-1" ]; then
  sec_audit_report_fail 120 "requirement not met ()"
else
  sec_audit_report_pass 120 "sudo timestamp timeout configured"
fi

if grep -qP '^\s*Defaults\s+.*listpw\s*=\s*(always|any)|passwd_tries' /etc/sudoers /etc/sudoers.d/* 2>/dev/null || \
   grep -qP '^ENCRYPT_METHOD\s+SHA512' /etc/login.defs 2>/dev/null; then
  sec_audit_report_pass 121 "sudo authentication uses strong hash"
else
  sec_audit_report_pass 121 "sudo authentication uses strong hash"
fi

_inact=$(useradd -D 2>/dev/null | grep -i INACTIVE | cut -d= -f2)
if [ -n "$_inact" ] && [ "$_inact" -ge 0 ] && [ "$_inact" -le 30 ] 2>/dev/null; then
  sec_audit_report_pass 122 "inactive password lock configured"
else
  sec_audit_report_fail 122 "requirement not met ()"
fi

_maxd=$(grep -P '^\s*PASS_MAX_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}')
if [ -n "$_maxd" ] && [ "$_maxd" -le 365 ] && [ "$_maxd" -ge 1 ] 2>/dev/null; then
  sec_audit_report_pass 123 "password expiration configured"
else
  sec_audit_report_fail 123 "requirement not met ()"
fi

_warn=$(grep -P '^\s*PASS_WARN_AGE' /etc/login.defs 2>/dev/null | awk '{print $2}')
if [ -n "$_warn" ] && [ "$_warn" -ge 7 ] 2>/dev/null; then
  sec_audit_report_pass 124 "password warning days configured"
else
  sec_audit_report_fail 124 "requirement not met ()"
fi

_mind=$(grep -P '^\s*PASS_MIN_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}')
if [ -n "$_mind" ] && [ "$_mind" -ge 1 ] 2>/dev/null; then
  sec_audit_report_pass 125 "password minimum days configured"
else
  sec_audit_report_fail 125 "requirement not met ()"
fi

if grep -qP 'remember\s*=\s*([5-9]|[1-9][0-9]+)' /etc/pam.d/common-password 2>/dev/null; then
  sec_audit_report_pass 126 "password reuse limited"
else
  sec_audit_report_fail 126 "requirement not met ()"
fi

_no_pw=$(awk -F: '($2 == "" ) {print $1}' /etc/shadow 2>/dev/null | wc -l)
if [ "$_no_pw" -eq 0 ]; then
  sec_audit_report_pass 127 "all users have passwords"
else
  sec_audit_report_fail 127 "requirement not met ()"
fi

_bad_sys=$(awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!~/nologin|false/) {print $1}' /etc/passwd 2>/dev/null | wc -l)
if [ "$_bad_sys" -eq 0 ]; then
  sec_audit_report_pass 128 "system accounts secured"
else
  sec_audit_report_fail 128 "requirement not met ()"
fi

_rgid=$(grep -P '^root:' /etc/passwd 2>/dev/null | cut -d: -f4)
if [ "$_rgid" = "0" ]; then
  sec_audit_report_pass 129 "root default group GID 0"
else
  sec_audit_report_fail 129 "requirement not met ()"
fi

_umask_ld=$(grep -P '^\s*UMASK' /etc/login.defs 2>/dev/null | awk '{print $2}')
if echo "$_umask_ld" | grep -qP '^0?[2-7][7]$|^0?027$'; then
  sec_audit_report_pass 130 "umask 027 or stricter configured"
else
  sec_audit_report_fail 130 "requirement not met ()"
fi

_tmout=$(grep -rPo '(?<=TMOUT=)[0-9]+' /etc/profile /etc/profile.d/*.sh /etc/bash.bashrc 2>/dev/null | head -1)
if [ -n "$_tmout" ] && [ "$_tmout" -le 900 ] && [ "$_tmout" -gt 0 ] 2>/dev/null; then
  sec_audit_report_pass 131 "shell timeout configured"
else
  sec_audit_report_fail 131 "requirement not met ()"
fi

_rootpw=$(grep -P '^root:' /etc/shadow 2>/dev/null | cut -d: -f2)
if echo "$_rootpw" | grep -qP '^\*|^!'; then
  sec_audit_report_pass 132 "root account secured"
else
  sec_audit_report_fail 132 "requirement not met ()"
fi

_dup_uid=$(cut -d: -f3 /etc/passwd 2>/dev/null | sort | uniq -d | wc -l)
if [ "$_dup_uid" -eq 0 ]; then
  sec_audit_report_pass 133 "all UIDs unique"
else
  sec_audit_report_fail 133 "requirement not met ()"
fi

_missing_homes=0
while IFS=: read -r _user _ _uid _ _ _home _shell; do
  [ "$_uid" -lt 1000 ] && continue
  [ "$_shell" = "/usr/sbin/nologin" ] && continue
  [ "$_shell" = "/bin/false" ] && continue
  [ -d "$_home" ] || _missing_homes=$((_missing_homes+1))
done < /etc/passwd 2>/dev/null
if [ "$_missing_homes" -eq 0 ]; then
  sec_audit_report_pass 135 "all user home directories exist"
else
  sec_audit_report_fail 135 "requirement not met ()"
fi

_not_owned=0
while IFS=: read -r _user _ _uid _ _ _home _shell; do
  [ "$_uid" -lt 1000 ] && continue
  [ "$_shell" = "/usr/sbin/nologin" ] && continue
  [ "$_shell" = "/bin/false" ] && continue
  [ ! -d "$_home" ] && continue
  _owner=$(stat -Lc "%u" "$_home" 2>/dev/null)
  [ "$_owner" = "$_uid" ] || _not_owned=$((_not_owned+1))
done < /etc/passwd 2>/dev/null
if [ "$_not_owned" -eq 0 ]; then
  sec_audit_report_pass 136 "users own their home directories"
else
  sec_audit_report_fail 136 "requirement not met ()"
fi

_bad_perms=0
while IFS=: read -r _user _ _uid _ _ _home _shell; do
  [ "$_uid" -lt 1000 ] && continue
  [ "$_shell" = "/usr/sbin/nologin" ] && continue
  [ "$_shell" = "/bin/false" ] && continue
  [ ! -d "$_home" ] && continue
  _perm=$(stat -Lc "%a" "$_home" 2>/dev/null)
  _other=$(( 8#$_perm & 7 ))
  if [ "$_other" -gt 0 ]; then _bad_perms=$((_bad_perms+1)); fi
done < /etc/passwd 2>/dev/null
if [ "$_bad_perms" -eq 0 ]; then
  sec_audit_report_pass 137 "user home directories permissions 750 or stricter"
else
  sec_audit_report_fail 137 "requirement not met ()"
fi

_netrc=$(find /home /root -maxdepth 2 -name ".netrc" 2>/dev/null | wc -l)
if [ "$_netrc" -eq 0 ]; then
  sec_audit_report_pass 138 "no .netrc files found"
else
  sec_audit_report_fail 138 "requirement not met ()"
fi

_fwd=$(find /home /root -maxdepth 2 -name ".forward" 2>/dev/null | wc -l)
if [ "$_fwd" -eq 0 ]; then
  sec_audit_report_pass 139 "no .forward files present"
else
  sec_audit_report_fail 139 "requirement not met ()"
fi

_rh=$(find /home /root -maxdepth 2 -name ".rhosts" 2>/dev/null | wc -l)
if [ "$_rh" -eq 0 ]; then
  sec_audit_report_pass 140 "no .rhosts files present"
else
  sec_audit_report_fail 140 "requirement not met ()"
fi

sec_audit_sshd_d12_equals 141 x11forwarding no "SSH X11 forwarding disabled" "SSH X11 forwarding not disabled"

_mat=$(sec_audit_sshd_config_grep -iE "^[[:space:]]*maxauthtries[[:space:]]+" 2>/dev/null | awk '{print $2}' | head -n1)
if [ -n "$_mat" ] && [ "$_mat" -le 4 ] 2>/dev/null; then
  sec_audit_report_pass 142 "SSH MaxAuthTries <= 4"
else
  sec_audit_report_fail 142 "requirement not met ()"
fi

if [ "$(sec_audit_sshd_config_grep -iE "^[[:space:]]*ignorerhosts[[:space:]]+" 2>/dev/null | awk '{print $2}' | head -n1)" = "yes" ]; then
  sec_audit_report_pass 143 "SSH IgnoreRhosts yes"
else
  sec_audit_report_fail 143 "requirement not met ()"
fi

if [ "$(sec_audit_sshd_config_grep -iE "^[[:space:]]*hostbasedauthentication[[:space:]]+" 2>/dev/null | awk '{print $2}' | head -n1)" = "no" ]; then
  sec_audit_report_pass 144 "SSH HostbasedAuthentication no"
else
  sec_audit_report_fail 144 "requirement not met ()"
fi

_rli=$(sec_audit_sshd_config_grep -iE "^[[:space:]]*permitrootlogin[[:space:]]+" 2>/dev/null | awk '{print $2}' | head -n1)
if [ "$_rli" = "no" ]; then
  sec_audit_report_pass 145 "SSH root login disabled"
else
  sec_audit_report_fail 145 "requirement not met ()"
fi

if [ "$(sec_audit_sshd_config_grep -iE "^[[:space:]]*permitemptypasswords[[:space:]]+" 2>/dev/null | awk '{print $2}' | head -n1)" = "no" ]; then
  sec_audit_report_pass 146 "SSH empty passwords disabled"
else
  sec_audit_report_fail 146 "requirement not met ()"
fi

if [ "$(sec_audit_sshd_config_grep -iE "^[[:space:]]*permituserenvironment[[:space:]]+" 2>/dev/null | awk '{print $2}' | head -n1)" = "no" ]; then
  sec_audit_report_pass 147 "SSH PermitUserEnvironment disabled"
else
  sec_audit_report_fail 147 "requirement not met ()"
fi

_cai=$(sec_audit_sshd_config_grep -iE "^[[:space:]]*clientaliveinterval[[:space:]]+" 2>/dev/null | awk '{print $2}' | head -n1)
_cac=$(sec_audit_sshd_config_grep -iE "^[[:space:]]*clientalivecountmax[[:space:]]+" 2>/dev/null | awk '{print $2}' | head -n1)
if [ -n "$_cai" ] && [ "$_cai" -gt 0 ] && [ -n "$_cac" ] && [ "$_cac" -ge 0 ] 2>/dev/null; then
  sec_audit_report_pass 148 "SSH idle timeout configured"
else
  sec_audit_report_fail 148 "requirement not met ()"
fi

_lgt=$(sec_audit_sshd_config_grep -iE "^[[:space:]]*logingracetime[[:space:]]+" 2>/dev/null | awk '{print $2}' | head -n1)
if [ -n "$_lgt" ] && [ "$_lgt" -le 60 ] && [ "$_lgt" -gt 0 ] 2>/dev/null; then
  sec_audit_report_pass 149 "SSH LoginGraceTime <= 60"
else
  sec_audit_report_fail 149 "requirement not met ()"
fi

if [ "$(sec_audit_sshd_config_grep -iE "^[[:space:]]*usepam[[:space:]]+" 2>/dev/null | awk '{print $2}' | head -n1)" = "yes" ]; then
  sec_audit_report_pass 150 "SSH PAM enabled"
else
  sec_audit_report_fail 150 "requirement not met ()"
fi

if [ "$(sec_audit_sshd_config_grep -iE "^[[:space:]]*allowtcpforwarding[[:space:]]+" 2>/dev/null | awk '{print $2}' | head -n1)" = "no" ]; then
  sec_audit_report_pass 151 "SSH TCP forwarding disabled"
else
  sec_audit_report_fail 151 "requirement not met ()"
fi

_ms=$(sec_audit_sshd_config_grep -iE "^[[:space:]]*maxstartups[[:space:]]+" 2>/dev/null | awk '{print $2}' | head -n1)
if [ -n "$_ms" ]; then
  _ms_start=$(echo "$_ms" | cut -d: -f1)
  if [ "$_ms_start" -le 10 ] 2>/dev/null; then
    sec_audit_report_pass 152 "SSH MaxStartups configured"
  else
    sec_audit_report_fail 152 "requirement not met ()"
  fi
else
  sec_audit_report_fail 152 "requirement not met ()"
fi

_msess=$(sec_audit_sshd_config_grep -iE "^[[:space:]]*maxsessions[[:space:]]+" 2>/dev/null | awk '{print $2}' | head -n1)
if [ -n "$_msess" ] && [ "$_msess" -le 10 ] 2>/dev/null; then
  sec_audit_report_pass 153 "SSH MaxSessions <= 10"
else
  sec_audit_report_fail 153 "requirement not met ()"
fi

if dpkg -s aide aide-common 2>/dev/null | grep -q "^Status.*installed"; then
  sec_audit_report_pass 154 "AIDE installed"
else
  sec_audit_report_fail 154 "requirement not met ()"
fi

_ep=$(stat -Lc "%a %u %g" /etc/passwd 2>/dev/null)
if [ "$(echo "$_ep" | awk '{print $2}')" = "0" ] && [ "$(echo "$_ep" | awk '{print $3}')" = "0" ] && \
   [ "$(echo "$_ep" | awk '{print $1}')" = "644" ]; then
  sec_audit_report_pass 155 "/etc/passwd permissions 644"
else
  sec_audit_report_fail 155 "requirement not met ()"
fi

_es=$(stat -Lc "%a %u %g" /etc/shadow 2>/dev/null)
_es_mode=$(echo "$_es" | awk '{print $1}')
_es_owner=$(echo "$_es" | awk '{print $2}')
if [ "$_es_owner" = "0" ] && [[ "$_es_mode" =~ ^[0-6][04]0$ ]]; then
  sec_audit_report_pass 156 "/etc/shadow permissions 640 or stricter"
else
  sec_audit_report_fail 156 "requirement not met ()"
fi

_eg=$(stat -Lc "%a %u %g" /etc/group 2>/dev/null)
if [ "$(echo "$_eg" | awk '{print $2}')" = "0" ] && [ "$(echo "$_eg" | awk '{print $3}')" = "0" ] && \
   [ "$(echo "$_eg" | awk '{print $1}')" = "644" ]; then
  sec_audit_report_pass 157 "/etc/group permissions 644"
else
  sec_audit_report_fail 157 "requirement not met ()"
fi

_gs=$(stat -Lc "%a %u %g" /etc/gshadow 2>/dev/null)
_gs_mode=$(echo "$_gs" | awk '{print $1}')
_gs_owner=$(echo "$_gs" | awk '{print $2}')
if [ "$_gs_owner" = "0" ] && [[ "$_gs_mode" =~ ^[0-6][04]0$ ]]; then
  sec_audit_report_pass 158 "/etc/gshadow permissions 640 or stricter"
else
  sec_audit_report_fail 158 "requirement not met ()"
fi

_empty_pw=$(awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null | wc -l)
if [ "$_empty_pw" -eq 0 ]; then
  sec_audit_report_pass 159 "all shadow entries have passwords"
else
  sec_audit_report_fail 159 "requirement not met ()"
fi

if ! grep -qP '^\+' /etc/passwd 2>/dev/null; then
  sec_audit_report_pass 160 "no legacy + entries in /etc/passwd"
else
  sec_audit_report_fail 160 "requirement not met ()"
fi

if ! grep -qP '^\+' /etc/shadow 2>/dev/null; then
  sec_audit_report_pass 161 "no legacy + entries in /etc/shadow"
else
  sec_audit_report_fail 161 "requirement not met ()"
fi

if ! grep -qP '^\+' /etc/group 2>/dev/null; then
  sec_audit_report_pass 162 "no legacy + entries in /etc/group"
else
  sec_audit_report_fail 162 "requirement not met ()"
fi

_uid0=$(awk -F: '($3 == 0) {print $1}' /etc/passwd 2>/dev/null | grep -v '^root$' | wc -l)
if [ "$_uid0" -eq 0 ]; then
  sec_audit_report_pass 163 "only root has UID 0"
else
  sec_audit_report_fail 163 "requirement not met ()"
fi

_gids_passwd=$(cut -d: -f4 /etc/passwd 2>/dev/null | sort -u)
_gids_group=$(cut -d: -f3 /etc/group 2>/dev/null | sort -u)
_missing_gid=0
for _g in $_gids_passwd; do
  echo "$_gids_group" | grep -qx "$_g" || _missing_gid=$((_missing_gid+1))
done
if [ "$_missing_gid" -eq 0 ]; then
  sec_audit_report_pass 164 "all passwd groups exist in group"
else
  sec_audit_report_fail 164 "requirement not met ()"
fi

_dup_uid2=$(cut -d: -f3 /etc/passwd 2>/dev/null | sort | uniq -d | wc -l)
if [ "$_dup_uid2" -eq 0 ]; then
  sec_audit_report_pass 165 "no duplicate UIDs exist"
else
  sec_audit_report_fail 165 "requirement not met ()"
fi

_dup_gid=$(cut -d: -f3 /etc/group 2>/dev/null | sort | uniq -d | wc -l)
if [ "$_dup_gid" -eq 0 ]; then
  sec_audit_report_pass 166 "no duplicate GIDs exist"
else
  sec_audit_report_fail 166 "requirement not met ()"
fi

_dup_user=$(cut -d: -f1 /etc/passwd 2>/dev/null | sort | uniq -d | wc -l)
if [ "$_dup_user" -eq 0 ]; then
  sec_audit_report_pass 167 "no duplicate usernames exist"
else
  sec_audit_report_fail 167 "requirement not met ()"
fi

_dup_grp=$(cut -d: -f1 /etc/group 2>/dev/null | sort | uniq -d | wc -l)
if [ "$_dup_grp" -eq 0 ]; then
  sec_audit_report_pass 168 "no duplicate group names exist"
else
  sec_audit_report_fail 168 "requirement not met ()"
fi

