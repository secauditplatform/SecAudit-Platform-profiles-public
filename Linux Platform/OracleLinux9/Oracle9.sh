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

OL9_FIND_CAP="${OL9_FIND_CAP:-${CRE_FIND_CAP:-20}}"
CRE_FIND_CAP="${OL9_FIND_CAP}"
OL9_CMD_CAP="${OL9_CMD_CAP:-${CRE_CMD_CAP:-12}}"
CRE_CMD_CAP="${OL9_CMD_CAP}"
OL9_DNF_CAP="${OL9_DNF_CAP:-${CRE_DNF_CAP:-30}}"
CRE_DNF_CAP="${OL9_DNF_CAP}"
OL9_ALLOW_CONTAINER_KMOD="${OL9_ALLOW_CONTAINER_KMOD:-${CRE_ALLOW_CONTAINER_KMOD:-${LINUX_CRE_ALLOW_CONTAINER_MODULES:-${ALMA_CRE_ALLOW_CONTAINER_MODULES:-0}}}}"
CRE_ALLOW_CONTAINER_KMOD="${OL9_ALLOW_CONTAINER_KMOD}"
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
        sec_audit_report_pass "$num" "${label} (waived: OL9_ALLOW_CONTAINER_KMOD=1)"
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

sec_audit_sshd_t_ensure() {
    [ "${_SSHD_T_READY:-0}" -eq 1 ] && return 0
    _SSHD_T_READY=1
    if sec_audit_have_bin sshd; then
        _sshd_t_cache=$(sshd -T 2>/dev/null) || _sshd_t_cache=""
    else
        _sshd_t_cache=""
    fi
}

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
sec_audit_assert_kmod_disabled 2 "udf kernel module" udf udf.ko* "udf"
# RULE3:
if sec_audit_tmp_is_isolated; then
    if sec_audit_mount_is_persisted /tmp; then
        sec_audit_report_pass 3 "/tmp is tmpfs or a separate partition"
    else
        sec_audit_report_fail 3 "/tmp is tmpfs or a separate partition is runtime-only (missing fstab or systemd .mount persistence)"
    fi
else
    sec_audit_report_fail 3 "/tmp does not meet tmpfs or separate-partition requirement"
fi
# RULE4:
if sec_audit_mount_has_option /tmp nodev; then
    sec_audit_report_pass 4 "nodev option set on /tmp partition"
else
    sec_audit_report_fail 4 "nodev is not set on /tmp (or path not resolvable / not an explicit mount per policy)"
fi

# RULE5:
if sec_audit_mount_has_option /tmp nosuid; then
    sec_audit_report_pass 5 "nosuid option set on /tmp partition"
else
    sec_audit_report_fail 5 "nosuid is not set on /tmp (or path not resolvable / not an explicit mount per policy)"
fi

# RULE6:
if sec_audit_mount_has_option /tmp noexec; then
    sec_audit_report_pass 6 "noexec option set on /tmp partition"
else
    sec_audit_report_fail 6 "noexec is not set on /tmp (or path not resolvable / not an explicit mount per policy)"
fi

# RULE7:
if sec_audit_path_is_isolated_volume /var; then
    if sec_audit_mount_is_persisted /var; then
        sec_audit_report_pass 7 "separate partition exists for /var"
    else
        sec_audit_report_fail 7 "dedicated mount for /var is runtime-only (missing fstab or systemd .mount persistence)"
    fi
else
    sec_audit_report_fail 7 "no compliant dedicated mount for /var"
fi
# RULE8:
if sec_audit_path_is_isolated_volume /var/tmp; then
    if sec_audit_mount_is_persisted /var/tmp; then
        sec_audit_report_pass 8 "separate partition exists for /var/tmp"
    else
        sec_audit_report_fail 8 "dedicated mount for /var/tmp is runtime-only (missing fstab or systemd .mount persistence)"
    fi
else
    sec_audit_report_fail 8 "no compliant dedicated mount for /var/tmp"
fi
# RULE9:
if sec_audit_mount_has_option /var/tmp nodev; then
    sec_audit_report_pass 9 "nodev option set on /var/tmp partition"
else
    sec_audit_report_fail 9 "nodev is not set on /var/tmp (or path not resolvable / not an explicit mount per policy)"
fi

# RULE10:
if sec_audit_mount_has_option /var/tmp nosuid; then
    sec_audit_report_pass 10 "nosuid option set on /var/tmp partition"
else
    sec_audit_report_fail 10 "nosuid is not set on /var/tmp (or path not resolvable / not an explicit mount per policy)"
fi

# RULE11:
if sec_audit_mount_has_option /var/tmp noexec; then
    sec_audit_report_pass 11 "noexec option set on /var/tmp partition"
else
    sec_audit_report_fail 11 "noexec is not set on /var/tmp (or path not resolvable / not an explicit mount per policy)"
fi

# RULE12:
if sec_audit_path_is_isolated_volume /var/log; then
    if sec_audit_mount_is_persisted /var/log; then
        sec_audit_report_pass 12 "separate partition exists for /var/log"
    else
        sec_audit_report_fail 12 "dedicated mount for /var/log is runtime-only (missing fstab or systemd .mount persistence)"
    fi
else
    sec_audit_report_fail 12 "no compliant dedicated mount for /var/log"
fi
# RULE13:
if sec_audit_path_is_isolated_volume /var/log/audit; then
    if sec_audit_mount_is_persisted /var/log/audit; then
        sec_audit_report_pass 13 "separate partition exists for /var/log/audit"
    else
        sec_audit_report_fail 13 "dedicated mount for /var/log/audit is runtime-only (missing fstab or systemd .mount persistence)"
    fi
else
    sec_audit_report_fail 13 "no compliant dedicated mount for /var/log/audit"
fi
# RULE14:
if sec_audit_path_is_isolated_volume /home; then
    if sec_audit_mount_is_persisted /home; then
        sec_audit_report_pass 14 "separate partition exists for /home"
    else
        sec_audit_report_fail 14 "dedicated mount for /home is runtime-only (missing fstab or systemd .mount persistence)"
    fi
else
    sec_audit_report_fail 14 "no compliant dedicated mount for /home"
fi
# RULE15:
if sec_audit_mount_has_option /home nodev; then
    sec_audit_report_pass 15 "nodev option set on /home partition"
else
    sec_audit_report_fail 15 "nodev is not set on /home (or path not resolvable / not an explicit mount per policy)"
fi

# RULE16:
if sec_audit_shm_is_isolated; then
    if sec_audit_mount_is_persisted /dev/shm; then
        sec_audit_report_pass 16 "/dev/shm is tmpfs or a separate partition"
    else
        sec_audit_report_fail 16 "/dev/shm is tmpfs or a separate partition is runtime-only (missing fstab or systemd .mount persistence)"
    fi
else
    sec_audit_report_fail 16 "/dev/shm does not meet tmpfs or separate-partition requirement"
fi
# RULE17:
if sec_audit_mount_has_option /dev/shm nosuid; then
    sec_audit_report_pass 17 "nosuid option set on /dev/shm partition"
else
    sec_audit_report_fail 17 "nosuid is not set on /dev/shm (or path not resolvable / not an explicit mount per policy)"
fi

# RULE18:
if sec_audit_mount_has_option /dev/shm noexec; then
    sec_audit_report_pass 18 "noexec option set on /dev/shm partition"
else
    sec_audit_report_fail 18 "noexec is not set on /dev/shm (or path not resolvable / not an explicit mount per policy)"
fi

# RULE19:
if rpm -q autofs &>/dev/null && systemctl is-enabled autofs.service 2>/dev/null | grep -qE 'enabled|active'; then
    sec_audit_report_fail 19 "autofs is enabled or active"
else
    sec_audit_report_pass 19 "autofs is not enabled"
fi

# RULE20:
_rule37_k=$(sec_audit_rpm_gpg_pubkey_count)
_rule37_sample=""
if sec_audit_have_bin rpm && [ "${_rule37_k:-0}" -gt 0 ]; then
    _rule37_sample=$(
        rpm -qa 'gpg-pubkey*' --qf '%{VERSION}\n' 2>/dev/null | awk 'NF && NR <= 6 { s = (s ? s "," : s) $1 } END { print s }'
    )
fi
if ! sec_audit_have_bin rpm; then
    sec_audit_report_fail 20 "rpm not available; cannot verify gpg-pubkey packages in the RPM database"
elif [ "${_rule37_k:-0}" -eq 0 ]; then
    sec_audit_report_fail 20 "no gpg-pubkey packages in the RPM database (import distribution or repository signing keys)"
else
    sec_audit_report_pass 20 "${_rule37_k} gpg-pubkey package(s) in RPM DB (sample key VERSION ids: ${_rule37_sample:-n/a})"
fi

# RULE21:
if rpm -q aide &>/dev/null; then
    sec_audit_report_pass 21 "AIDE is installed"
else
    sec_audit_report_fail 21 "AIDE is not installed"
fi

# RULE22:
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
    sec_audit_report_pass 22 "access to bootloader config is configured"
else
    sec_audit_report_fail 22 "/boot/grub2/grub.cfg (or EFI grub.cfg) owner/mode is not root:root with mode 600"
fi
# RULE23:
if sec_audit_grub_cfg_matches '^[[:space:]]*set superusers' && sec_audit_grub_cfg_matches 'password_pbkdf2'; then
    sec_audit_report_pass 23 "bootloader password is set (grub.cfg under /boot/grub2 or EFI)"
else
    sec_audit_report_fail 23 "GRUB bootloader superuser/password_pbkdf2 is not configured as required in grub.cfg"
fi
# RULE24:
if grep "^\s*set superusers" /boot/grub2/grub.cfg 2>/dev/null | grep -q "set superusers"; then
    if grep "^\s*password" /boot/grub2/grub.cfg 2>/dev/null | grep -q "password_pbkdf2"; then
        sec_audit_report_pass 24 "bootloader password is set"
    else
        sec_audit_report_fail 24 "GRUB bootloader superuser/password_pbkdf2 is not configured as required in grub.cfg"
    fi
else
    sec_audit_report_fail 24 "GRUB bootloader superuser/password_pbkdf2 is not configured as required in grub.cfg"
fi

# RULE25:
sec_audit_assert_sysctl_equals 25 fs.protected_hardlinks 1
# RULE26:
sec_audit_assert_sysctl_equals 26 fs.protected_symlinks 1
# RULE27:
if grep -P '(selinux|enforcing)=0\b' /proc/cmdline 2>/dev/null; then
    sec_audit_report_fail 27 "SELinux is disabled via kernel command line or bootloader configuration"
elif grep -Prs '^\h*([^#\n\r]+\h+)?kernelopts=([^#\n\r]+\h+)?(selinux|enforcing)=0\b' /boot/grub2 /boot/efi 2>/dev/null; then
    sec_audit_report_fail 27 "SELinux is disabled via kernel command line or bootloader configuration"
else
    sec_audit_report_pass 27 "SELinux is not disabled in bootloader configuration"
fi

# RULE28:
_ge46=$(getenforce 2>/dev/null || true)
_cfg46=$(grep -Pi '^\h*SELINUX=\K\w+' /etc/selinux/config 2>/dev/null | head -n1 || true)
if [[ "$_ge46" != "Enforcing" ]]; then
    sec_audit_report_fail 28 "getenforce is '${_ge46:-unknown}', expected Enforcing"
elif [[ "$_cfg46" != "enforcing" ]]; then
    sec_audit_report_fail 28 "runtime Enforcing but /etc/selinux/config SELINUX=${_cfg46:-unset} (will revert after reboot)"
else
    sec_audit_report_pass 28 "the SELinux mode is enforcing (runtime and config)"
fi
# RULE29:
if grep -Psi '^\h*SELINUXTYPE\h*=\h*(targeted|mls)\b' /etc/selinux/config 2>/dev/null; then
    sec_audit_report_pass 29 "SELinux policy is configured"
else
    sec_audit_report_fail 29 "SELinux policy type is not set to targeted or mls in /etc/selinux/config"
fi

# RULE30:
if rpm -q setroubleshoot &>/dev/null; then
    sec_audit_report_fail 30 "package setroubleshoot is installed"
else
    sec_audit_report_pass 30 "package setroubleshoot is not installed"
fi

# RULE31:
if rpm -q mcstrans &>/dev/null; then
    sec_audit_report_fail 31 "package mcstrans is installed"
else
    sec_audit_report_pass 31 "package mcstrans is not installed"
fi

# RULE32:
if rpm -q libselinux &>/dev/null; then
    sec_audit_report_pass 32 "SELinux is installed"
else
    sec_audit_report_fail 32 "SELinux stack (libselinux) is not installed"
fi

# RULE33:
if grep -Psi "(\\\v|\\\r|\\\m|\\\s|\b$(grep ^ID= /etc/os-release 2>/dev/null | cut -d= -f2 | sed -e 's/"//g')\b)" /etc/motd 2>/dev/null; then
    sec_audit_report_fail 33 "/etc/motd is missing or does not contain required banner content"
else
    sec_audit_report_pass 33 "/etc/motd is configured"
fi

# RULE34:
if grep -Psi "(\\\v|\\\r|\\\m|\\\s|\b$(grep ^ID= /etc/os-release 2>/dev/null | cut -d= -f2 | sed -e 's/"//g')\b)" /etc/issue 2>/dev/null; then
    sec_audit_report_fail 34 "/etc/issue is missing or does not contain required local login banner"
else
    sec_audit_report_pass 34 "/etc/issue is configured"
fi

# RULE35:
if [ -f /etc/issue.net ]; then
    if grep -Psi "(\\\v|\\\r|\\\m|\\\s|\b$(grep ^ID= /etc/os-release 2>/dev/null | cut -d= -f2 | sed -e 's/"//g')\b)" /etc/issue.net 2>/dev/null; then
        sec_audit_report_fail 35 "/etc/issue.net is missing or does not contain required remote login banner"
    else
        sec_audit_report_pass 35 "/etc/issue.net is configured"
    fi
else
    sec_audit_report_pass 35 "/etc/issue.net is configured"
fi

# RULE36:
if [ -e /etc/motd ]; then
    if stat -Lc '%a' /etc/motd 2>/dev/null | grep -qE '^[0-6]44$'; then
        if stat -Lc '%U:%G' /etc/motd 2>/dev/null | grep -q '^root:root$'; then
            sec_audit_report_pass 36 "access to /etc/motd is configured"
        else
            sec_audit_report_fail 36 "File /etc/motd permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 36 "File /etc/motd permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 36 "access to /etc/motd is configured (file not found)"
fi

# RULE37:
if stat -Lc '%a' /etc/issue 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' /etc/issue 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 37 "access to /etc/issue is configured"
    else
        sec_audit_report_fail 37 "File /etc/issue permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 37 "File /etc/issue permissions or ownership not correct"
fi

# RULE38:
if [ -e /etc/issue.net ]; then
    if stat -Lc '%a' /etc/issue.net 2>/dev/null | grep -qE '^[0-6]44$'; then
        if stat -Lc '%U:%G' /etc/issue.net 2>/dev/null | grep -q '^root:root$'; then
            sec_audit_report_pass 38 "access to /etc/issue.net is configured"
        else
            sec_audit_report_fail 38 "File /etc/issue.net permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 38 "File /etc/issue.net permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 38 "access to /etc/issue.net is configured (file not found)"
fi

# RULE39:
echo "RULE39= MANUAL: check requires host review — 1.9 Ensure updates, patches, and additional security software are installed"

# RULE40:
if rpm -q xinetd &>/dev/null; then
    sec_audit_report_fail 40 "package xinetd is installed"
else
    sec_audit_report_pass 40 "package xinetd is not installed"
fi

# RULE41:
sec_audit_assert_service_unused 41 autofs "autofs services are not in use" "autofs services are installed and enabled or actively running" "autofs.service"
# RULE42:
sec_audit_assert_service_unused 42 avahi "avahi daemon services are not in use" "avahi daemon services are installed and enabled or actively running" "avahi-daemon.socket" "avahi-daemon.service"
# RULE43:
if rpm -q avahi &>/dev/null; then
    sec_audit_report_fail 43 "package avahi is installed"
else
    sec_audit_report_pass 43 "package avahi is not installed"
fi

# RULE44:
sec_audit_assert_service_unused 44 cups "print server services are not in use" "print server services are installed and enabled or actively running" "cups.socket" "cups.service"
# RULE45:
if rpm -q dhcp &>/dev/null; then
    sec_audit_report_fail 45 "package dhcp is installed"
else
    sec_audit_report_pass 45 "package dhcp is not installed"
fi

# RULE46:
sec_audit_assert_service_unused 46 nfs-utils "network file system services are not in use" "network file system services are installed and enabled or actively running" "nfs-server.service"
# RULE47:
sec_audit_assert_service_unused 47 dnsmasq "dnsmasq services are not in use" "dnsmasq services are installed and enabled or actively running" "dnsmasq.service"
# RULE48:
if rpm -q httpd &>/dev/null; then
    sec_audit_report_fail 48 "package httpd is installed"
else
    sec_audit_report_pass 48 "package httpd is not installed"
fi

# RULE49:
if rpm -q dovecot &>/dev/null; then
    sec_audit_report_fail 49 "package dovecot is installed"
else
    sec_audit_report_pass 49 "package dovecot is not installed"
fi

# RULE50:
sec_audit_assert_service_unused 50 samba "samba file server services are not in use" "samba file server services are installed and enabled or actively running" "smb.service"
# RULE51:
if rpm -q squid &>/dev/null; then
    sec_audit_report_fail 51 "package squid is installed"
else
    sec_audit_report_pass 51 "package squid is not installed"
fi

# RULE52:
sec_audit_assert_service_unused 52 net-snmp "snmp services are not in use" "snmp services are installed and enabled or actively running" "snmpd.service"
# RULE53:
sec_audit_assert_service_unused 53 telnet-server "telnet server services are not in use" "telnet server services are installed and enabled or actively running" "telnet.socket"
# RULE54:
if rpm -q telnet-server &>/dev/null; then
    if systemctl is-enabled telnet.socket 2>/dev/null | grep -q 'enabled'; then
        sec_audit_report_fail 54 "telnet server services are installed and enabled or actively running"
    elif systemctl is-active telnet.socket 2>/dev/null | grep -q '^active'; then
        sec_audit_report_fail 54 "telnet server services are installed and enabled or actively running"
    else
        sec_audit_report_pass 54 "telnet server services are not in use"
    fi
else
    sec_audit_report_pass 54 "telnet server services are not in use"
fi

# RULE55:
if rpm -q telnet &>/dev/null; then
    sec_audit_report_fail 55 "package telnet is installed"
else
    sec_audit_report_pass 55 "package telnet is not installed"
fi

# RULE56:
sec_audit_assert_service_unused 56 rsync-daemon "rsync services are not in use" "rsync services are installed and enabled or actively running" "rsyncd.socket" "rsyncd.service"
# RULE57:
if rpm -q telnet &>/dev/null; then
    sec_audit_report_fail 57 "package telnet is installed"
else
    sec_audit_report_pass 57 "package telnet is not installed"
fi

# RULE58:
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
    sec_audit_report_pass 58 "chrony has ${_ch101_src:-0} server/pool line(s) in conf or chrony.d${_ch101_track}"
else
    sec_audit_report_fail 58 "chrony is not configured with time sources (no server/pool in chrony.conf or chrony.d)"
fi

# RULE59:
sec_audit_assert_kmod_disabled 59 "atm kernel module" atm atm.ko* "atm"
# RULE60:
if sec_audit_kmod_autoload_listed atm; then
    sec_audit_report_fail 60 "atm kernel module is listed in modules-load.d (auto-load at boot)"
elif ! sec_audit_soft_find --timeout=20 /usr/lib/modules/ /lib/modules/ -xdev -ignore_readdir_race -type f -name "atm.ko*" 2>/dev/null | grep -q .; then
    sec_audit_report_pass 60 "atm kernel module is not available"
else
    if ! lsmod | grep -q atm && modprobe --showconfig | grep -Pq '^\h*(blacklist|install)\h+atm\b'; then
        sec_audit_report_pass 60 "atm kernel module is not available"
    else
        sec_audit_report_fail 60 "atm kernel module is available, loaded, or not effectively blocked (modprobe blacklist/install)"
    fi
fi

# RULE61:
sec_audit_assert_kmod_disabled 61 "can kernel module" can can.ko* "can"
# RULE62:
sec_audit_assert_sysctl_equals 62 net.ipv4.conf.all.send_redirects 0

# RULE63:
sec_audit_report_skip 63 "check requires host review — 3.3.2 Ensure ICMP redirects are not accepted"
# RULE64:
sec_audit_report_skip 64 "check requires host review — 3.3.3 Ensure secure ICMP redirects are not accepted"
# RULE65:
sec_audit_assert_sysctl_equals 65 net.ipv4.conf.all.accept_redirects 0

# RULE66:
sec_audit_report_skip 66 "check requires host review — 3.3.5 Ensure broadcast ICMP requests are ignored"
# RULE67:
sec_audit_assert_sysctl_equals 67 net.ipv4.conf.all.secure_redirects 0

# RULE68:
sec_audit_assert_sysctl_equals 68 net.ipv4.conf.all.rp_filter 1

# RULE69:
sec_audit_assert_sysctl_equals 69 net.ipv4.conf.default.rp_filter 1

# RULE70:
sec_audit_assert_sysctl_equals 70 net.ipv6.conf.all.accept_ra 0

# RULE71:
if grep -Pi '^\h*max_log_file_action\h*=\h*keep_logs\b' /etc/audit/auditd.conf 2>/dev/null; then
    sec_audit_report_pass 71 "audit logs are not automatically deleted"
else
    sec_audit_report_fail 71 "max_log_file_action or keep_logs policy allows silent deletion"
fi

# RULE72:
if grep -Po '^\h*max_log_file\h*=\h*\d+\b' /etc/audit/auditd.conf 2>/dev/null; then
    sec_audit_report_pass 72 "audit log storage size is configured"
else
    sec_audit_report_fail 72 "max_log_file or rotation policy in auditd.conf does not meet policy"
fi

# RULE73:
if grep -P '^\h*disk_full_action\h*=\h*(halt|single)\b' /etc/audit/auditd.conf 2>/dev/null; then
    if grep -P '^\h*disk_error_action\h*=\h*(syslog|single|halt)\b' /etc/audit/auditd.conf 2>/dev/null; then
        sec_audit_report_pass 73 "system is disabled when audit logs are full"
    else
        sec_audit_report_fail 73 "disk_full_action / space_left_action in auditd.conf does not meet policy"
    fi
else
    sec_audit_report_fail 73 "disk_full_action / space_left_action in auditd.conf does not meet policy"
fi

# RULE74:
if grep -P '^\h*disk_full_action\h*=\h*(halt|single)\b' /etc/audit/auditd.conf 2>/dev/null; then
    if grep -P '^\h*disk_error_action\h*=\h*(syslog|single|halt)\b' /etc/audit/auditd.conf 2>/dev/null; then
        sec_audit_report_pass 74 "system is disabled when audit logs are full"
    else
        sec_audit_report_fail 74 "disk_full_action / space_left_action in auditd.conf does not meet policy"
    fi
else
    sec_audit_report_fail 74 "disk_full_action / space_left_action in auditd.conf does not meet policy"
fi

# RULE75:
if grep -P '^\h*disk_full_action\h*=\h*(halt|single)\b' /etc/audit/auditd.conf 2>/dev/null; then
    if grep -P '^\h*disk_error_action\h*=\h*(syslog|single|halt)\b' /etc/audit/auditd.conf 2>/dev/null; then
        sec_audit_report_pass 75 "system is disabled when audit logs are full"
    else
        sec_audit_report_fail 75 "disk_full_action / space_left_action in auditd.conf does not meet policy"
    fi
else
    sec_audit_report_fail 75 "disk_full_action / space_left_action in auditd.conf does not meet policy"
fi

# RULE76:
if systemctl is-enabled auditd 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active auditd 2>/dev/null | grep -q 'active'; then
        sec_audit_report_pass 76 "auditd service is enabled and active"
    else
        sec_audit_report_fail 76 "auditd is not enabled or not active"
    fi
else
    sec_audit_report_fail 76 "auditd is not enabled or not active"
fi

# RULE77:
if systemctl is-enabled rsyslog 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active rsyslog.service 2>/dev/null | grep -q 'active'; then
        sec_audit_report_pass 77 "rsyslog service is enabled and active"
    else
        sec_audit_report_fail 77 "rsyslog is not enabled or not active"
    fi
else
    sec_audit_report_fail 77 "rsyslog is not enabled or not active"
fi

# RULE78:
if grep -Ps '^\h*\$FileCreateMode\h+0[0,2,4,6][0,2,4]0\b' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null; then
    sec_audit_report_pass 78 "rsyslog log file creation mode is configured"
else
    sec_audit_report_fail 78 "rsyslog $FileCreateMode (or equivalent) does not meet policy"
fi

# RULE79:
echo "RULE79= MANUAL: check requires host review — 4.2.1.6 Ensure rsyslog is configured to send logs to a remote log host"

# RULE80:
if stat -Lc '%a' /etc/ssh/sshd_config 2>/dev/null | grep -q '^600$'; then
    if stat -Lc '%U:%G' /etc/ssh/sshd_config 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 80 "access to /etc/ssh/sshd_config is configured"
    else
        sec_audit_report_fail 80 "File /etc/ssh/sshd_config permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 80 "File /etc/ssh/sshd_config permissions or ownership not correct"
fi

if ! sec_audit_sshd_effective_usable; then
    for _sshn in 81 82 83 84 85 86 87 88 89 90 91 92 93 94 95 96 97 98 99 100 155 156 157 158 200; do
        sec_audit_report_fail "$_sshn" "unable_to_evaluate: sshd -T produced no effective configuration"
    done
else
# RULE81:
PRIV_KEYS=$(sec_audit_sshd_effective_config | awk '$1=="hostkey" {print $2}')
FAIL81=0
for key in $PRIV_KEYS; do
    if [ -f "$key" ]; then
        if ! stat -Lc '%a' "$key" 2>/dev/null | grep -q '^600$'; then
            FAIL81=1
        fi
        if ! stat -Lc '%U:%G' "$key" 2>/dev/null | grep -q '^root:root$'; then
            FAIL81=1
        fi
    else
        FAIL81=1
    fi
done
if [ $FAIL81 -eq 0 ]; then
    sec_audit_report_pass 81 "access to SSH private host key files is configured"
else
    sec_audit_report_fail 81 "File SSH private host key files permissions or ownership not correct"
fi

# RULE82:
PUB_KEYS=$(sec_audit_sshd_effective_config | awk '$1=="hostkey" {print $2".pub"}')
FAIL82=0
for key in $PUB_KEYS; do
    if [ -f "$key" ]; then
        if ! stat -Lc '%a' "$key" 2>/dev/null | grep -qE '^[0-6]44$'; then
            FAIL82=1
        fi
        if ! stat -Lc '%U:%G' "$key" 2>/dev/null | grep -q '^root:root$'; then
            FAIL82=1
        fi
    else
        FAIL82=1
    fi
done
if [ $FAIL82 -eq 0 ]; then
    sec_audit_report_pass 82 "access to SSH public host key files is configured"
else
    sec_audit_report_fail 82 "File SSH public host key files permissions or ownership not correct"
fi

# RULE83:
if sec_audit_sshd_config_grep -Piq '^\h*(allow|deny)(users|groups)\h+\H+'; then
    sec_audit_report_pass 83 "sshd access is configured"
else
    sec_audit_report_fail 83 "sshd access controls (AllowUsers/DenyUsers/AllowGroups/DenyGroups) are not set as required"
fi

# RULE84:
if sec_audit_sshd_config_grep -Piq '^banner\h+\/\H+'; then
    sec_audit_report_pass 84 "sshd Banner is configured"
else
    sec_audit_report_fail 84 "sshd Banner does not meet the required policy (see sshd -T)"
fi

# RULE85:
if sec_audit_sshd_config_grep -Piq '^ciphers\h+\"?([^#\n\r]+,)?((3des|blowfish|cast128|aes(128|192|256))-cbc|arcfour(128|256)?|rijndael-cbc@lysator\.liu\.se)\b'; then
    sec_audit_report_fail 85 "sshd Ciphers allow weak or legacy algorithms (see sshd -T)"
else
    sec_audit_report_pass 85 "sshd Ciphers are configured"
fi

# RULE86:
if sec_audit_sshd_config_grep -Piq 'clientaliveinterval\s+([1-9]|[1-9][0-9]+)'; then
    if sec_audit_sshd_config_grep -Piq 'clientalivecountmax\s+([1-9]|[1-9][0-9]+)'; then
        sec_audit_report_pass 86 "sshd ClientAliveInterval and ClientAliveCountMax are configured"
    else
        sec_audit_report_fail 86 "sshd ClientAliveInterval and ClientAliveCountMax are not configured as required (see sshd -T)"
    fi
else
    sec_audit_report_fail 86 "sshd ClientAliveInterval and ClientAliveCountMax are not configured as required (see sshd -T)"
fi

# RULE87:
if sec_audit_sshd_config_grep -iq 'disableforwarding yes'; then
    sec_audit_report_pass 87 "sshd DisableForwarding is enabled"
else
    sec_audit_report_fail 87 "sshd DisableForwarding is not enabled in effective sshd -T output"
fi

# RULE88:
if sec_audit_sshd_config_grep -iq 'gssapiauthentication no'; then
    sec_audit_report_pass 88 "sshd GSSAPIAuthentication is disabled"
else
    sec_audit_report_fail 88 "sshd GSSAPIAuthentication is not disabled in effective sshd -T output"
fi

# RULE89:
if sec_audit_sshd_config_grep -Piq '^banner\h+\/\H+'; then
    sec_audit_report_pass 89 "sshd Banner is configured"
else
    sec_audit_report_fail 89 "sshd Banner does not meet the required policy (see sshd -T)"
fi

# RULE90:
if sec_audit_sshd_config_grep -Piq 'kexalgorithms\h+([^#\n\r]+,)?(diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1)\b'; then
    sec_audit_report_fail 90 "sshd KexAlgorithms does not meet the required policy (see sshd -T)"
else
    sec_audit_report_pass 90 "sshd KexAlgorithms is configured"
fi

# RULE91:
if sec_audit_sshd_config_grep -Piq 'maxauthtries\s+[1-4]\b'; then
    sec_audit_report_pass 91 "sshd MaxAuthTries is configured"
else
    sec_audit_report_fail 91 "sshd MaxAuthTries does not meet the required policy (see sshd -T)"
fi

# RULE92:
if sec_audit_sshd_config_grep -iq 'ignorerhosts yes'; then
    sec_audit_report_pass 92 "sshd IgnoreRhosts is enabled"
else
    sec_audit_report_fail 92 "sshd IgnoreRhosts is not enabled in effective sshd -T output"
fi

# RULE93:
if sec_audit_sshd_config_grep -iq 'disableforwarding yes'; then
    sec_audit_report_pass 93 "sshd DisableForwarding is enabled"
else
    sec_audit_report_fail 93 "sshd DisableForwarding is not enabled in effective sshd -T output"
fi

# RULE94:
if sec_audit_sshd_config_grep -Piq 'clientaliveinterval\s+([1-9]|[1-9][0-9]+)'; then
    if sec_audit_sshd_config_grep -Piq 'clientalivecountmax\s+([1-9]|[1-9][0-9]+)'; then
        sec_audit_report_pass 94 "sshd ClientAliveInterval and ClientAliveCountMax are configured"
    else
        sec_audit_report_fail 94 "sshd ClientAliveInterval and ClientAliveCountMax are not configured as required (see sshd -T)"
    fi
else
    sec_audit_report_fail 94 "sshd ClientAliveInterval and ClientAliveCountMax are not configured as required (see sshd -T)"
fi

# RULE95:
if sec_audit_sshd_config_grep -iq 'gssapiauthentication no'; then
    sec_audit_report_pass 95 "sshd GSSAPIAuthentication is disabled"
else
    sec_audit_report_fail 95 "sshd GSSAPIAuthentication is not disabled in effective sshd -T output"
fi

# RULE96:
if sec_audit_sshd_config_grep -iq 'hostbasedauthentication no'; then
    sec_audit_report_pass 96 "sshd HostbasedAuthentication is disabled"
else
    sec_audit_report_fail 96 "sshd HostbasedAuthentication is not disabled in effective sshd -T output"
fi

# RULE97:
if sec_audit_sshd_config_grep -iq 'permitrootlogin no'; then
    sec_audit_report_pass 97 "sshd PermitRootLogin is disabled"
else
    sec_audit_report_fail 97 "sshd PermitRootLogin is not disabled in effective sshd -T output"
fi

# RULE98:
if sec_audit_sshd_config_grep -iq 'permitrootlogin no'; then
    sec_audit_report_pass 98 "sshd PermitRootLogin is disabled"
else
    sec_audit_report_fail 98 "sshd PermitRootLogin is not disabled in effective sshd -T output"
fi

# RULE99:
if sec_audit_sshd_config_grep -iq 'permitemptypasswords no'; then
    sec_audit_report_pass 99 "sshd PermitEmptyPasswords is disabled"
else
    sec_audit_report_fail 99 "sshd PermitEmptyPasswords is not disabled in effective sshd -T output"
fi

# RULE100:
if sec_audit_sshd_config_grep -Piq 'macs\h+([^#\n\r]+,)?(hmac-md5|hmac-md5-96|hmac-ripemd160|hmac-sha1-96|umac-64@openssh\.com|hmac-md5-etm@openssh\.com|hmac-md5-96-etm@openssh\.com|hmac-ripemd160-etm@openssh\.com|hmac-sha1-96-etm@openssh\.com|umac-64-etm@openssh\.com|umac-128-etm@openssh\.com)\b'; then
    sec_audit_report_fail 100 "sshd MACs allow weak or legacy algorithms (see sshd -T)"
else
    sec_audit_report_pass 100 "sshd MACs are configured"
fi

fi

# RULE101:
sec_audit_report_skip 101 "check requires host review — 5.5.1 Ensure password creation requirements are configured"
# RULE102:
sec_audit_report_skip 102 "check requires host review — 5.5.1 Ensure password creation requirements are configured"
# RULE103:
sec_audit_report_skip 103 "check requires host review — 5.5.2 Ensure lockout for failed password attempts is configured"
# RULE104:
sec_audit_report_skip 104 "check requires host review — 5.5.3 Ensure password reuse is limited"
# RULE105:
sec_audit_report_skip 105 "check requires host review — 5.5.4 Ensure password hashing algorithm is SHA-512"
# RULE106:
sec_audit_report_skip 106 "check requires host review — 5.6.1.1 Ensure password expiration is 365 days or less"
# RULE107:
sec_audit_report_skip 107 "check requires host review — 5.6.1.3 Ensure password expiration warning days is 7 or more"
# RULE108:
sec_audit_report_skip 108 "check requires host review — 5.6.1.3 Ensure password expiration warning days is 7 or more"
# RULE109:
sec_audit_report_skip 109 "check requires host review — 5.6.1.4 Ensure inactive password lock is 30 days or less"
# RULE110:
sec_audit_report_skip 110 "check requires host review — 5.6.1.4 Ensure inactive password lock is 30 days or less"
# RULE111:
sec_audit_report_skip 111 "check requires host review — 5.6.1.5 Ensure all users last password change date is in the past"
# RULE112:
sec_audit_report_skip 112 "check requires host review — 5.6.4 Ensure default group for the root account is GID 0"
# RULE113:
sec_audit_report_skip 113 "check requires host review — 5.6.5 Ensure default user umask is 027 or more restrictive"
# RULE114:
sec_audit_report_skip 114 "check requires host review — 5.6.3 Ensure default user shell timeout is 900 seconds or less"
# RULE115:
if rpm -q aide &>/dev/null; then
    _a207_db=""
    if [ -f /var/lib/aide/aide.db.gz ] || [ -f /var/lib/aide/aide.db ]; then
        _a207_db="; AIDE database file present under /var/lib/aide"
    else
        _a207_db="; WARNING: no AIDE database under /var/lib/aide (initialize with aide --init)"
    fi
    sec_audit_report_pass 115 "AIDE package is installed${_a207_db}"
else
    sec_audit_report_fail 115 "AIDE package is not installed"
fi

# RULE116:
if stat -Lc '%a' /etc/passwd 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' /etc/passwd 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 116 "access to /etc/passwd is configured"
    else
        sec_audit_report_fail 116 "File /etc/passwd permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 116 "File /etc/passwd permissions or ownership not correct"
fi

# RULE117:
if stat -Lc '%a' /etc/shadow 2>/dev/null | grep -qE '^[0-6]40$'; then
    if stat -Lc '%U' /etc/shadow 2>/dev/null | grep -q 'root'; then
        if stat -Lc '%G' /etc/shadow 2>/dev/null | grep -qE 'root|shadow'; then
            sec_audit_report_pass 117 "access to /etc/shadow is configured"
        else
            sec_audit_report_fail 117 "File /etc/shadow permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 117 "File /etc/shadow permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 117 "File /etc/shadow permissions or ownership not correct"
fi

# RULE118:
sec_audit_report_skip 118 "check requires host review — "
# RULE119:
if stat -Lc '%a' /etc/group 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' /etc/group 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 119 "access to /etc/group is configured"
    else
        sec_audit_report_fail 119 "File /etc/group permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 119 "File /etc/group permissions or ownership not correct"
fi

# RULE120:
sec_audit_report_skip 120 "check requires host review — "
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
sec_audit_report_skip 122 "check requires host review — "
# RULE123:
if grep -Ers '^([^#]+\s+)?(\/usr\/s?bin\/|^\s*)aide(\.wrapper)?\s(--?\S+\s)*(-(check|update)|\$AIDEARGS)\b' /etc/cron.* /etc/crontab /var/spool/cron/ /etc/cron.d 2>/dev/null; then
    sec_audit_report_pass 123 "filesystem integrity is regularly checked (cron/cron.d entry references aide)"
elif systemctl is-enabled aidecheck.timer 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active aidecheck.timer 2>/dev/null | grep -q 'active'; then
        _a208_n=$(systemctl show aidecheck.timer -p NextElapseUSRealtime 2>/dev/null | cut -d= -f2-)
        sec_audit_report_pass 123 "aidecheck.timer enabled and active (next: ${_a208_n:-unknown})"
    else
        sec_audit_report_fail 123 "aidecheck.timer enabled but not active"
    fi
else
    sec_audit_report_fail 123 "filesystem integrity is regularly checked"
fi

# RULE124:
if stat -Lc '%a' /etc/passwd 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' /etc/passwd 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 124 "access to /etc/passwd is configured"
    else
        sec_audit_report_fail 124 "File /etc/passwd permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 124 "File /etc/passwd permissions or ownership not correct"
fi

# RULE125:
if [ -e /etc/shadow- ]; then
    if stat -Lc '%a' /etc/shadow- 2>/dev/null | grep -qE '^[0-6]40$'; then
        if stat -Lc '%U' /etc/shadow- 2>/dev/null | grep -q 'root'; then
            if stat -Lc '%G' /etc/shadow- 2>/dev/null | grep -qE 'root|shadow'; then
                sec_audit_report_pass 125 "access to /etc/shadow- is configured"
            else
                sec_audit_report_fail 125 "File /etc/shadow- permissions or ownership not correct"
            fi
        else
            sec_audit_report_fail 125 "File /etc/shadow- permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 125 "File /etc/shadow- permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 125 "/etc/shadow- is absent (optional file; permission check skipped)"
fi

# RULE126:
sec_audit_report_skip 126 "check requires host review — "
# RULE127:
if [ -e /etc/group- ]; then
    if stat -Lc '%a' /etc/group- 2>/dev/null | grep -qE '^[0-6]44$'; then
        if stat -Lc '%U:%G' /etc/group- 2>/dev/null | grep -q '^root:root$'; then
            sec_audit_report_pass 127 "access to /etc/group- is configured"
        else
            sec_audit_report_fail 127 "File /etc/group- permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 127 "File /etc/group- permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 127 "/etc/group- is absent (optional file; permission check skipped)"
fi

# RULE128:
sec_audit_report_skip 128 "check requires host review — "
# RULE129:
if [ -e /etc/gshadow- ]; then
    if stat -Lc '%a' /etc/gshadow- 2>/dev/null | grep -qE '^[0-6]40$'; then
        if stat -Lc '%U' /etc/gshadow- 2>/dev/null | grep -q 'root'; then
            if stat -Lc '%G' /etc/gshadow- 2>/dev/null | grep -qE 'root|shadow'; then
                sec_audit_report_pass 129 "access to /etc/gshadow- is configured"
            else
                sec_audit_report_fail 129 "File /etc/gshadow- permissions or ownership not correct"
            fi
        else
            sec_audit_report_fail 129 "File /etc/gshadow- permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 129 "File /etc/gshadow- permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 129 "/etc/gshadow- is absent (optional file; permission check skipped)"
fi

# RULE130:
sec_audit_report_skip 130 "check requires host review — "
# RULE131:
CRITICAL_PATHS="/bin /sbin /usr/bin /usr/sbin /etc /var /home"
if sec_audit_find_hit_timeout sec_audit_soft_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type f -perm -0002 -print; then
    sec_audit_report_fail 131 "incomplete_scan: world-writable file search timed out under critical paths"
elif sec_audit_find_hit_timeout sec_audit_soft_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type d -perm -0002 -print; then
    sec_audit_report_fail 131 "incomplete_scan: world-writable directory search timed out under critical paths"
else
    WW_FILES=$(sec_audit_soft_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type f -perm -0002 -print 2>/dev/null | wc -l)
    WW_DIRS=$(sec_audit_soft_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type d -perm -0002 -print 2>/dev/null | wc -l)
    if [ "${WW_FILES:-0}" -eq 0 ] && [ "${WW_DIRS:-0}" -eq 0 ]; then
        sec_audit_report_pass 131 "No critical world writable files or directories found"
    else
        sec_audit_report_fail 131 "Found potential world-writable items ($WW_FILES files, $WW_DIRS dirs)"
    fi
fi
# RULE132:
sec_audit_report_skip 132 "check requires host review — 6.1.10 Ensure no unowned files or directories exist"
# RULE133:
sec_audit_report_skip 133 "check requires host review — 6.1.11 Ensure no ungrouped files or directories exist"
# RULE134:
echo "RULE134= MANUAL: check requires host review — 6.1.13 Audit SUID executables"

# RULE135:
echo "RULE135= MANUAL: check requires host review — 6.1.14 Audit SGID executables"

# RULE136:
if awk -F: '($2 != "x" ) { print }' /etc/passwd 2>/dev/null | grep -q '.'; then
    sec_audit_report_fail 136 "Non-shadow password field found in /etc/passwd (second field not "x")"
else
    sec_audit_report_pass 136 "accounts in /etc/passwd use shadowed passwords"
fi

# RULE137:
if awk -F: '($3 == 0) { print $1 }' /etc/passwd 2>/dev/null | grep -qx "root"; then
    if [ $(awk -F: '($3 == 0) { print $1 }' /etc/passwd 2>/dev/null | wc -l) -eq 1 ]; then
        sec_audit_report_pass 137 "root is the only UID 0 account"
    else
        sec_audit_report_fail 137 "Multiple accounts with UID 0 exist in /etc/passwd"
    fi
else
    sec_audit_report_fail 137 "Multiple accounts with UID 0 exist in /etc/passwd"
fi

# RULE138:
if rpm -q ossec &>/dev/null; then
    sec_audit_report_fail 138 "package ossec is installed"
else
    sec_audit_report_pass 138 "package ossec is not installed"
fi

# RULE139:
sec_audit_report_skip 139 "check requires host review — "
# RULE140:
sec_audit_report_skip 140 "check requires host review — "
# RULE141:
_rule38_main=$(sec_audit_dnf_main_option gpgcheck)
_rule38_repo=$(sec_audit_yum_repo_list_explicit_gpgcheck0 | head -n1)
if sec_audit_truthy_false "$_rule38_main"; then
    sec_audit_report_fail 141 "merged [main] gpgcheck is disabled (effective value: ${_rule38_main})"
elif [ -n "$_rule38_repo" ]; then
    sec_audit_report_fail 141 "enabled repository section explicitly sets gpgcheck=0 (${_rule38_repo//|/ -> })"
else
    sec_audit_report_pass 141 "[main] gpgcheck is not false and no enabled .repo section forces gpgcheck=0"
fi

# RULE142:
if rpm -q xorg-x11-server &>/dev/null; then
    sec_audit_report_fail 142 "package xorg-x11-server is installed"
else
    sec_audit_report_pass 142 "package xorg-x11-server is not installed"
fi

# RULE143:
if compgen -G "/sys/class/net/*/wireless" >/dev/null; then
    sec_audit_report_fail 143 "Wireless interfaces are present under /sys/class/net"
else
    sec_audit_report_pass 143 "wireless interfaces are not available"
fi

# RULE144:
if rpm -q audit audit-libs &>/dev/null; then
    sec_audit_report_pass 144 "auditd packages are installed"
else
    sec_audit_report_fail 144 "audit audit-libs packages are not installed"
fi

# RULE145:
if grep -Psoi '^\h*GRUB_CMDLINE_LINUX=\"([^#\n\r]+\h+)?\baudit_backlog_limit=\d+\b' /etc/default/grub 2>/dev/null; then
    sec_audit_report_pass 145 "audit_backlog_limit is configured"
else
    sec_audit_report_fail 145 "audit_backlog_limit is not set appropriately in audit rules or sysctl"
fi

# RULE146:
sec_audit_report_skip 146 "check requires host review — 4.1.3.4 Ensure events that modify date and time information are collected"
# RULE147:
sec_audit_report_skip 147 "check requires host review — 4.1.3.8 Ensure events that modify user/group information are collected"
# RULE148:
if sec_audit_audit_rule_on_disk_and_loaded -q "dir=/etc/NetworkManager/"; then
    sec_audit_report_pass 148 "NetworkManager directory watch on disk and loaded"
else
    sec_audit_report_fail 148 "events that modify /etc/NetworkManager directory are not collected"
fi

# RULE149:
if sec_audit_audit_rule_on_disk_and_loaded -q "path=/etc/sudoers"; then
    if sec_audit_audit_rule_on_disk_and_loaded -q "dir=/etc/sudoers.d"; then
        sec_audit_report_pass 149 "sudoers and sudoers.d watch rules present in audit.rules and loaded in kernel"
    else
        sec_audit_report_fail 149 "/etc/sudoers.d directory watch missing on disk or not loaded"
    fi
else
    sec_audit_report_fail 149 "/etc/sudoers file watch missing on disk or not loaded"
fi

# RULE150:
sec_audit_report_skip 150 "check requires host review — 4.1.3.19 Ensure kernel module loading unloading and modification is collected"
# RULE151:
if rpm -q rsyslog &>/dev/null; then
    sec_audit_report_pass 151 "rsyslog is installed"
else
    sec_audit_report_fail 151 "rsyslog package is not installed"
fi

# RULE152:
sec_audit_report_skip 152 "check requires host review — 5.3.1 Ensure sudo is installed"
# RULE153:
sec_audit_report_skip 153 "check requires host review — 5.3.2 Ensure sudo commands use pty"
# RULE154:
sec_audit_report_skip 154 "check requires host review — 5.3.3 Ensure sudo log file exists"
# RULE155:
PRIV_KEYS=$(sec_audit_sshd_effective_config | awk '$1=="hostkey" {print $2}')
FAIL155=0
for key in $PRIV_KEYS; do
    if [ -f "$key" ]; then
        if ! stat -Lc '%a' "$key" 2>/dev/null | grep -q '^600$'; then
            FAIL155=1
        fi
        if ! stat -Lc '%U:%G' "$key" 2>/dev/null | grep -q '^root:root$'; then
            FAIL155=1
        fi
    else
        FAIL155=1
    fi
done
if [ $FAIL155 -eq 0 ]; then
    sec_audit_report_pass 155 "access to SSH private host key files is configured"
else
    sec_audit_report_fail 155 "File SSH private host key files permissions or ownership not correct"
fi

# RULE156:
PUB_KEYS=$(sec_audit_sshd_effective_config | awk '$1=="hostkey" {print $2".pub"}')
FAIL156=0
for key in $PUB_KEYS; do
    if [ -f "$key" ]; then
        if ! stat -Lc '%a' "$key" 2>/dev/null | grep -qE '^[0-6]44$'; then
            FAIL156=1
        fi
        if ! stat -Lc '%U:%G' "$key" 2>/dev/null | grep -q '^root:root$'; then
            FAIL156=1
        fi
    else
        FAIL156=1
    fi
done
if [ $FAIL156 -eq 0 ]; then
    sec_audit_report_pass 156 "access to SSH public host key files is configured"
else
    sec_audit_report_fail 156 "File SSH public host key files permissions or ownership not correct"
fi

# RULE157:
if sec_audit_sshd_config_grep -Piq '^\h*(allow|deny)(users|groups)\h+\H+'; then
    sec_audit_report_pass 157 "sshd access is configured"
else
    sec_audit_report_fail 157 "sshd access controls (AllowUsers/DenyUsers/AllowGroups/DenyGroups) are not set as required"
fi

# RULE158:
if sec_audit_sshd_config_grep -Piq '^ciphers\h+\"?([^#\n\r]+,)?((3des|blowfish|cast128|aes(128|192|256))-cbc|arcfour(128|256)?|rijndael-cbc@lysator\.liu\.se)\b'; then
    sec_audit_report_fail 158 "sshd Ciphers allow weak or legacy algorithms (see sshd -T)"
else
    sec_audit_report_pass 158 "sshd Ciphers are configured"
fi

# RULE159:
sec_audit_report_skip 159 "check requires host review — 5.6.2 Ensure system accounts are secured"
# RULE160:
if cut -f1 -d":" /etc/passwd 2>/dev/null | sort -n | uniq -c | while read -r count user; do [ "$count" -gt 1 ] && echo "found"; done | grep -q "found"; then
    sec_audit_report_fail 160 "Duplicate user names exist in /etc/passwd"
else
    sec_audit_report_pass 160 "no duplicate user names exist"
fi

# RULE161:
if cut -f1 -d":" /etc/group 2>/dev/null | sort -n | uniq -c | while read -r count group; do [ "$count" -gt 1 ] && echo "found"; done | grep -q "found"; then
    sec_audit_report_fail 161 "Duplicate group names exist in /etc/group"
else
    sec_audit_report_pass 161 "no duplicate group names exist"
fi

# RULE162:
if cut -f3 -d":" /etc/group 2>/dev/null | sort -n | uniq -c | while read -r count gid; do [ "$count" -gt 1 ] && echo "found"; done | grep -q "found"; then
    sec_audit_report_fail 162 "Duplicate GID entries exist in /etc/group"
else
    sec_audit_report_pass 162 "no duplicate GIDs exist"
fi

# RULE163:
sec_audit_report_skip 163 "check requires host review — 4.1.1.2 Ensure auditing for processes that start prior to auditd is enabled"
# RULE164:
if sec_audit_audit_rule_on_disk_and_loaded -E -q 'EACCES|EPERM'; then
    sec_audit_report_pass 164 "unsuccessful access (EACCES/EPERM) auditing on disk and loaded"
else
    sec_audit_report_fail 164 "unsuccessful file access attempts are not collected"
fi

# RULE165:
sec_audit_report_skip 165 "check requires host review — 4.1.3.12 Ensure login and logout events are collected"
# RULE166:
sec_audit_report_skip 166 "check requires host review — 4.1.3.13 Ensure file deletion events by users are collected"
# RULE167:
if sec_audit_mount_has_option /var nodev; then
    sec_audit_report_pass 167 "nodev option set on /var partition"
else
    sec_audit_report_fail 167 "nodev is not set on /var (or path not resolvable / not an explicit mount per policy)"
fi

# RULE168:
if sec_audit_mount_has_option /var nosuid; then
    sec_audit_report_pass 168 "nosuid option set on /var partition"
else
    sec_audit_report_fail 168 "nosuid is not set on /var (or path not resolvable / not an explicit mount per policy)"
fi

# RULE169:
if sec_audit_mount_has_option /var/log nodev; then
    sec_audit_report_pass 169 "nodev option set on /var/log partition"
else
    sec_audit_report_fail 169 "nodev is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
fi

# RULE170:
if sec_audit_mount_has_option /var/log noexec; then
    sec_audit_report_pass 170 "noexec option set on /var/log partition"
else
    sec_audit_report_fail 170 "noexec is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
fi

# RULE171:
if sec_audit_mount_has_option /var/log nosuid; then
    sec_audit_report_pass 171 "nosuid option set on /var/log partition"
else
    sec_audit_report_fail 171 "nosuid is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
fi

# RULE172:
if sec_audit_mount_has_option /var/log/audit noexec; then
    sec_audit_report_pass 172 "noexec option set on /var/log/audit partition"
else
    sec_audit_report_fail 172 "noexec is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
fi

# RULE173:
if sec_audit_mount_has_option /var/log/audit nodev; then
    sec_audit_report_pass 173 "nodev option set on /var/log/audit partition"
else
    sec_audit_report_fail 173 "nodev is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
fi

# RULE174:
if sec_audit_mount_has_option /var/log/audit nosuid; then
    sec_audit_report_pass 174 "nosuid option set on /var/log/audit partition"
else
    sec_audit_report_fail 174 "nosuid is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
fi

# RULE175:
if sec_audit_mount_has_option /home nosuid; then
    sec_audit_report_pass 175 "nosuid option set on /home partition"
else
    sec_audit_report_fail 175 "nosuid is not set on /home (or path not resolvable / not an explicit mount per policy)"
fi

# RULE176:
_rule39_main=$(sec_audit_dnf_main_option repo_gpgcheck)
_rule39_repo=$(sec_audit_yum_repo_list_explicit_repo_gpgcheck0 | head -n1)
if sec_audit_truthy_false "$_rule39_main"; then
    sec_audit_report_fail 176 "merged [main] repo_gpgcheck is disabled (effective value: ${_rule39_main})"
elif [ -z "$_rule39_main" ]; then
    sec_audit_report_fail 176 "repo_gpgcheck not explicitly enabled in merged [main] (dnf defaults to false when unset)"
elif ! sec_audit_truthy_true "$_rule39_main"; then
    sec_audit_report_fail 176 "repo_gpgcheck in [main] is not a true value (expected 1/true/yes/on; got: ${_rule39_main})"
elif [ -n "$_rule39_repo" ]; then
    sec_audit_report_fail 176 "enabled repository section explicitly sets repo_gpgcheck=0 (${_rule39_repo//|/ -> })"
else
    sec_audit_report_pass 176 "repo_gpgcheck enabled in [main] and no enabled .repo section forces repo_gpgcheck=0"
fi

# RULE177:
sec_audit_report_skip 177 "check requires host review — 1.3.2 Ensure filesystem integrity is regularly checked"
# RULE178:
if sec_audit_core_dumps_limited; then
    sec_audit_report_pass 178 "limits * hard core 0 present and systemd DefaultLimitCORE does not allow unlimited core dumps"
elif grep -Psi '^\*\s+hard\s+core\s+0\b' /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null; then
    sec_audit_report_fail 178 "limits.conf sets hard core 0 but systemd DefaultLimitCORE contradicts (check system.conf / user.conf drop-ins)"
else
    sec_audit_report_fail 178 "core file size limits are not configured (limits * hard core 0 not found)"
fi

# RULE179:
_ge45=$(getenforce 2>/dev/null || true)
if grep -Pi '^\h*SELINUX=disabled\b' /etc/selinux/config 2>/dev/null; then
    sec_audit_report_fail 179 "SELinux is disabled in /etc/selinux/config"
elif [[ "$_ge45" == "Disabled" ]]; then
    sec_audit_report_fail 179 "getenforce reports Disabled"
elif [[ "$_ge45" == "Permissive" ]]; then
    sec_audit_report_fail 179 "SELinux is permissive (CRE default requires enforcing; set waiver or fix before audit)"
elif grep -Pi '^\h*SELINUX=(enforcing|permissive)\b' /etc/selinux/config 2>/dev/null && [[ "$_ge45" == "Enforcing" ]]; then
    sec_audit_report_pass 179 "the SELinux mode is not disabled (enforcing)"
else
    sec_audit_report_fail 179 "SELinux mode is not in an acceptable state (config/getenforce mismatch or disabled)"
fi
# RULE180:
if grep -Pi '^\h*SELINUX=enforcing\b' /etc/selinux/config 2>/dev/null; then
    if getenforce | grep -q Enforcing; then
        sec_audit_report_pass 180 "the SELinux mode is enforcing"
    else
        sec_audit_report_fail 180 "SELinux is not enforcing in /etc/selinux/config or getenforce is not Enforcing"
    fi
else
    sec_audit_report_fail 180 "SELinux is not enforcing in /etc/selinux/config or getenforce is not Enforcing"
fi

# RULE181:
GDM_CONFIG="/etc/gdm/custom.conf"
if [ -f "$GDM_CONFIG" ]; then
    if grep -Pzo "\[org/gnome/login-screen\][^\[]*banner-message-enable=true" "$GDM_CONFIG" 2>/dev/null | grep -q .; then
        sec_audit_report_pass 181 "GDM login banner is configured"
    else
        sec_audit_report_fail 181 "GDM login banner is not configured in $GDM_CONFIG"
    fi
else
    sec_audit_report_fail 181 "GDM configuration file not found ($GDM_CONFIG)"
fi

# RULE182:
if rpm -q gdm &>/dev/null && grep -q "DisableUserList=true" /etc/gdm/custom.conf 2>/dev/null; then
    sec_audit_report_pass 182 "GDM disable-user-list is configured"
elif ! rpm -q gdm &>/dev/null; then
    sec_audit_report_pass 182 "GDM is not installed"
else
    sec_audit_report_fail 182 "GDM disable-user-list is not configured"
fi

# RULE183:
sec_audit_report_skip 183 "check requires host review — 1.8.10 Ensure XDCMP is not enabled"
# RULE184:
sec_audit_report_skip 184 "check requires host review — 1.10 Ensure system-wide crypto policy is not legacy"
# RULE185:
sec_audit_assert_service_unused 185 bind "dns server services are not in use" "dns server services are installed and enabled or actively running" "named.service"
# RULE186:
if sec_audit_pkg_any_installed dovecot cyrus-imapd; then
    if sec_audit_systemd_unit_live dovecot.socket dovecot.service cyrus-imapd.service; then
        sec_audit_report_fail 186 "message access server services are installed and enabled or actively running"
    else
        sec_audit_report_pass 186 "message access server services are not in use (package present but units masked/disabled/inactive)"
    fi
else
    sec_audit_report_pass 186 "message access server services are not in use"
fi
# RULE187:
sec_audit_assert_service_unused 187 vsftpd "ftp server services are not in use" "ftp server services are installed and enabled or actively running" "vsftpd.service"
# RULE188:
sec_audit_assert_service_unused 188 rpcbind "rpcbind services are not in use" "rpcbind services are installed and enabled or actively running" "rpcbind.socket" "rpcbind.service"
# RULE189:
if grep -Psi -- '^\h*OPTIONS=\"?\h*([^#\n\r]+\h+)?-u\h+root\b' /etc/sysconfig/chronyd 2>/dev/null; then
    sec_audit_report_fail 189 "chronyd is configured to run as root (OPTIONS in /etc/sysconfig/chronyd)"
else
    sec_audit_report_pass 189 "chrony is not run as the root user"
fi

# RULE190:
if sec_audit_audit_rule_on_disk_and_loaded -q "execve"; then
    sec_audit_report_pass 190 "execve auditing present on disk and loaded"
else
    sec_audit_report_fail 190 "actions as another user are not always logged (execve audit rule missing or not loaded)"
fi

# RULE191:
if [ -f /var/log/sudo.log ]; then
    if sec_audit_audit_rule_on_disk_and_loaded -q "path=/var/log/sudo.log"; then
        sec_audit_report_pass 191 "audit rule for /var/log/sudo.log on disk and loaded"
    else
        sec_audit_report_fail 191 "events that modify the sudo log file are not collected (audit watch for /var/log/sudo.log missing or not loaded)"
    fi
else
    sec_audit_report_fail 191 "events that modify the sudo log file are not collected (/var/log/sudo.log not found)"
fi

# RULE192:
sec_audit_report_skip 192 "check requires host review — 4.1.3.6 Ensure use of privileged commands are collected"
# RULE193:
sec_audit_report_skip 193 "check requires host review — 4.1.3.15 Ensure successful and unsuccessful attempts to use the chcon command are recorded"
# RULE194:
sec_audit_report_skip 194 "check requires host review — 4.1.3.16 Ensure successful and unsuccessful attempts to use the setfacl command are recorded"
# RULE195:
sec_audit_report_skip 195 "check requires host review — 4.1.3.17 Ensure successful and unsuccessful attempts to use the chacl command are recorded"
# RULE196:
sec_audit_report_skip 196 "check requires host review — 4.1.3.18 Ensure successful and unsuccessful attempts to use the usermod command are recorded"
# RULE197:
if sec_audit_audit_rule_on_disk_and_loaded -- '-e 2'; then
    sec_audit_report_pass 197 "the audit configuration is immutable (-e 2 loaded and on disk)"
elif sec_audit_audit_rules_file_grep -q -- '-e 2'; then
    sec_audit_report_fail 197 "Immutable rule (-e 2) is on disk but not loaded (auditctl -l)"
elif sec_audit_auditctl_list_grep -q -- '-e 2'; then
    sec_audit_report_fail 197 "Immutable rule (-e 2) is loaded but missing from on-disk audit rules"
else
    sec_audit_report_fail 197 "Immutable rule (-e 2) is missing from loaded and on-disk audit rules"
fi
# RULE198:
if sec_audit_audit_rule_on_disk_and_loaded -q "mount"; then
    sec_audit_report_pass 198 "mount syscall auditing on disk and loaded"
else
    sec_audit_report_fail 198 "successful file system mounts are not collected"
fi

# RULE199:
if stat -Lc '%a' /etc/ssh/sshd_config 2>/dev/null | grep -q '^600$'; then
    if stat -Lc '%U:%G' /etc/ssh/sshd_config 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 199 "access to /etc/ssh/sshd_config is configured"
    else
        sec_audit_report_fail 199 "File /etc/ssh/sshd_config permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 199 "File /etc/ssh/sshd_config permissions or ownership not correct"
fi

# RULE200:
if sec_audit_sshd_config_grep -iq 'loglevel VERBOSE\|loglevel INFO'; then
    sec_audit_report_pass 200 "sshd LogLevel is configured"
else
    sec_audit_report_fail 200 "sshd LogLevel does not meet the required policy (see sshd -T)"
fi

# RULE201:
sec_audit_report_skip 201 "check requires host review — 5.3.4 Ensure users must provide password for escalation"
# RULE202:
sec_audit_report_skip 202 "check requires host review — 5.3.5 Ensure re-authentication for privilege escalation is not disabled globally"
# RULE203:
sec_audit_report_skip 203 "check requires host review — 5.3.6 Ensure sudo authentication timeout is configured correctly"
# RULE204:
sec_audit_report_skip 204 "check requires host review — 5.3.7 Ensure access to the su command is restricted"
# RULE205:
sec_audit_report_skip 205 "check requires host review — 5.4.2 Ensure authselect includes with-faillock"
# RULE206:
sec_audit_report_skip 206 "check requires host review — 6.1.12 Ensure sticky bit is set on all world-writable directories"
# RULE207:
if cut -f3 -d":" /etc/passwd 2>/dev/null | sort -n | uniq -c | while read -r count uid; do [ "$count" -gt 1 ] && echo "found"; done | grep -q "found"; then
    sec_audit_report_fail 207 "Duplicate UID entries exist in /etc/passwd"
else
    sec_audit_report_pass 207 "no duplicate UIDs exist"
fi

# RULE208:
if sec_audit_path_is_isolated_volume /dev/shm; then
    sec_audit_report_pass 208 "separate partition exists for /dev/shm"
else
    sec_audit_report_fail 208 "no compliant dedicated mount for /dev/shm"
fi

# RULE209:
_rule40_dnf_n=$(sec_audit_dnf_enabled_repo_count)
if [ ! -d /etc/yum.repos.d ]; then
    sec_audit_report_fail 209 "/etc/yum.repos.d is missing"
else
    _rule40_nrepo=0
    shopt -s nullglob
    for _rf in /etc/yum.repos.d/*.repo; do
        [ -f "$_rf" ] && _rule40_nrepo=$((_rule40_nrepo + 1))
    done
    shopt -u nullglob
    if [ "${_rule40_nrepo:-0}" -eq 0 ]; then
        sec_audit_report_fail 209 "no .repo files under /etc/yum.repos.d"
    elif ! sec_audit_yum_repo_any_enabled_has_uris; then
        sec_audit_report_fail 209 "no enabled repository section defines a non-empty baseurl, mirrorlist, or metalink"
    elif sec_audit_have_bin dnf && [ "${_rule40_dnf_n:-0}" -eq 0 ]; then
        sec_audit_report_fail 209 ".repo files define URIs but dnf repolist enabled reports 0 repos (metadata, plugin, or config error)"
    else
        if sec_audit_have_bin dnf && [ "${_rule40_dnf_n:-0}" -gt 0 ]; then
            sec_audit_report_pass 209 "${_rule40_nrepo} .repo file(s); dnf reports ${_rule40_dnf_n} enabled repo(s); enabled sections include package URIs"
        else
            sec_audit_report_pass 209 "${_rule40_nrepo} .repo file(s); enabled sections include baseurl/mirrorlist/metalink (dnf not used for count)"
        fi
    fi
fi

# RULE210:
sec_audit_report_skip 210 "check requires host review — 1.3.3 Ensure cryptographic mechanisms are used to protect the integrity of audit tools"
# RULE211:
if grep -q "idle-delay=uint32" /etc/dconf/db/gdm.d/* 2>/dev/null || \
   grep -q "lock-delay=uint32" /etc/dconf/db/gdm.d/* 2>/dev/null; then
    sec_audit_report_pass 211 "GDM screen lock is configured"
else
    sec_audit_report_fail 211 "GDM screen lock is not configured"
fi

# RULE212:
if grep -q "automount=false" /etc/dconf/db/gdm.d/* 2>/dev/null || \
   grep -q "automount-open=false" /etc/dconf/db/gdm.d/* 2>/dev/null; then
    sec_audit_report_pass 212 "GDM automount is configured"
else
    sec_audit_report_fail 212 "GDM automount is not configured"
fi

# RULE213:
if grep -q "autorun-never=true" /etc/dconf/db/gdm.d/* 2>/dev/null; then
    sec_audit_report_pass 213 "GDM autorun-never is configured"
else
    sec_audit_report_fail 213 "GDM autorun-never is not configured"
fi

# RULE214:
if sec_audit_kmod_autoload_listed removable; then
    sec_audit_report_fail 214 "removable kernel module is listed in modules-load.d (auto-load at boot)"
elif ! sec_audit_soft_find --timeout=20 /usr/lib/modules/ /lib/modules/ -xdev -ignore_readdir_race -type f -name "removable.ko*" 2>/dev/null | grep -q .; then
    sec_audit_report_pass 214 "removable kernel module is not available"
else
    if ! lsmod | grep -q removable && modprobe --showconfig 2>/dev/null | grep -Eq '^(blacklist|install)[[:space:]]+removable\b'; then
        sec_audit_report_pass 214 "removable kernel module is not available"
    else
        sec_audit_report_fail 214 "removable kernel module is available, loaded, or not effectively blocked (modprobe blacklist/install)"
    fi
fi

# RULE215:
sec_audit_report_skip 215 "check requires host review — 1.8.7 Ensure GDM disabling automatic mounting of removable media is not overridden"
# RULE216:
sec_audit_report_skip 216 "check requires host review — 1.8.8 Ensure GDM autorun-never is enabled"
# RULE217:
sec_audit_report_skip 217 "check requires host review — 1.8.9 Ensure GDM autorun-never is not overridden"
# RULE218:
if rpm -q avahi &>/dev/null; then
    if systemctl is-enabled avahi-daemon.socket avahi-daemon.service 2>/dev/null | grep -q 'enabled'; then
        sec_audit_report_fail 218 "avahi daemon services are installed and enabled or actively running"
    elif systemctl is-active avahi-daemon.socket avahi-daemon.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_fail 218 "avahi daemon services are installed and enabled or actively running"
    else
        sec_audit_report_pass 218 "avahi daemon services are not in use"
    fi
else
    sec_audit_report_pass 218 "avahi daemon services are not in use"
fi

# RULE219:
if rpm -q dnsmasq &>/dev/null; then
    sec_audit_report_fail 219 "package dnsmasq is installed"
else
    sec_audit_report_pass 219 "package dnsmasq is not installed"
fi

# RULE220:
sec_audit_report_skip 220 "check requires host review — 2.3.4 Ensure FTP client is not installed"
# RULE221:
echo "RULE221= MANUAL: check requires host review — 3.1.1 Ensure IPv6 status is identified"

# RULE222:
sec_audit_assert_service_unused 222 bluez "bluetooth services are not in use" "bluetooth services are installed and enabled or actively running" "bluetooth.service"
# RULE223:
sec_audit_report_skip 223 "check requires host review — 3.4.1.2 Ensure a single firewall configuration utility is in use"
# RULE224:
sec_audit_report_skip 224 "check requires host review — 4.1.3.7 Ensure unsuccessful file access attempts are collected"
# RULE225:
sec_audit_report_skip 225 "check requires host review — 4.2.1.7 Ensure rsyslog is not configured to receive logs from a remote client"
# RULE226:
sec_audit_report_skip 226 "check requires host review — 5.6.1.2 Ensure minimum days between password changes is configured"
# RULE227:
sec_audit_report_skip 227 "check requires host review — 5.6.6 Ensure root password is set"
# RULE228:
if awk -F: '($2 != "x" ) { print }' /etc/passwd 2>/dev/null | grep -q '.'; then
    sec_audit_report_fail 228 "Non-shadow password field found in /etc/passwd (second field not "x")"
else
    sec_audit_report_pass 228 "accounts in /etc/passwd use shadowed passwords"
fi

# RULE229:
if awk -F: '($2 == "" ) { print }' /etc/shadow 2>/dev/null | grep -q '.'; then
    sec_audit_report_fail 229 "Empty password hash found in /etc/shadow"
else
    sec_audit_report_pass 229 "/etc/shadow password fields are not empty"
fi

# RULE230:
sec_audit_report_skip 230 "check requires host review — 6.2.8 Ensure root PATH Integrity"
# RULE231:
sec_audit_report_skip 231 "check requires host review — 6.2.11 Ensure local interactive users own their home directories"
# RULE232:
FAIL232=0
while IFS=: read -r user pass uid gid rest; do
    if [ "$uid" -ge 1000 ] 2>/dev/null && [ "$uid" -lt 65534 ]; then
        home=$(echo "$rest" | cut -d: -f1)
        for dotfile in "$home/.bashrc" "$home/.bash_profile" "$home/.profile" "$home/.bash_logout"; do
            if [ -f "$dotfile" ]; then
                perm=$(stat -c '%a' "$dotfile" 2>/dev/null)
                if [ "${perm:2:1}" -gt 0 ] 2>/dev/null || [ "${perm:1:1}" -gt 0 ] 2>/dev/null; then
                    sec_audit_report_fail 232 "User $user dot file $dotfile has world/group write permissions ($perm)"
                    FAIL232=1
                fi
            fi
        done
    fi
done < /etc/passwd 2>/dev/null
[ $FAIL232 -eq 0 ] && echo "RULE232= PASS: Local interactive user dot files access is configured"

exit 0

exit 0

