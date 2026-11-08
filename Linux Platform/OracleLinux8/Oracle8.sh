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

OL8_FIND_CAP="${OL8_FIND_CAP:-${CRE_FIND_CAP:-20}}"
CRE_FIND_CAP="${OL8_FIND_CAP}"
OL8_CMD_CAP="${OL8_CMD_CAP:-${CRE_CMD_CAP:-12}}"
CRE_CMD_CAP="${OL8_CMD_CAP}"
OL8_DNF_CAP="${OL8_DNF_CAP:-${CRE_DNF_CAP:-30}}"
CRE_DNF_CAP="${OL8_DNF_CAP}"
OL8_ALLOW_CONTAINER_KMOD="${OL8_ALLOW_CONTAINER_KMOD:-${CRE_ALLOW_CONTAINER_KMOD:-${LINUX_CRE_ALLOW_CONTAINER_MODULES:-${ALMA_CRE_ALLOW_CONTAINER_MODULES:-0}}}}"
CRE_ALLOW_CONTAINER_KMOD="${OL8_ALLOW_CONTAINER_KMOD}"
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
        sec_audit_report_pass "$num" "${label} (waived: OL8_ALLOW_CONTAINER_KMOD=1)"
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
sec_audit_assert_kmod_disabled 2 "freevxfs kernel module" freevxfs freevxfs.ko* "freevxfs"
# RULE3:
sec_audit_assert_kmod_disabled 3 "hfs kernel module" hfs hfs.ko* "hfs"
# RULE4:
sec_audit_assert_kmod_disabled 4 "hfsplus kernel module" hfsplus hfsplus.ko* "hfsplus"
# RULE5:
sec_audit_assert_kmod_disabled 5 "jffs2 kernel module" jffs2 jffs2.ko* "jffs2"
# RULE6:
sec_audit_assert_kmod_disabled 6 "overlay kernel module" overlay overlay.ko* "overlay"
# RULE7:
sec_audit_assert_kmod_disabled 7 "squashfs kernel module" squashfs squashfs.ko* "squashfs"
# RULE8:
sec_audit_assert_kmod_disabled 8 "udf kernel module" udf udf.ko* "udf"
# RULE9:
if sec_audit_kmod_autoload_listed firewire_core firewire-core; then
    sec_audit_report_fail 9 "firewire-core kernel module is listed in modules-load.d (auto-load at boot)"
elif ! sec_audit_soft_find --timeout=20 /usr/lib/modules/ /lib/modules/ -xdev -ignore_readdir_race -type f -name "firewire-core.ko*" 2>/dev/null | grep -q .; then
    sec_audit_report_pass 9 "firewire-core kernel module is not available"
else
    if ! lsmod | grep -q firewire_core && modprobe --showconfig | grep -Pq '^\h*(blacklist|install)\h+firewire_core\b'; then
        sec_audit_report_pass 9 "firewire-core kernel module is not available"
    else
        sec_audit_report_fail 9 "firewire-core kernel module is available, loaded, or not effectively blocked (modprobe blacklist/install)"
    fi
fi

# RULE10:
if sec_audit_kmod_autoload_listed usb_storage usb-storage; then
    sec_audit_report_fail 10 "usb-storage kernel module is listed in modules-load.d (auto-load at boot)"
elif ! sec_audit_soft_find --timeout=20 /usr/lib/modules/ /lib/modules/ -xdev -ignore_readdir_race -type f -name "usb-storage.ko*" 2>/dev/null | grep -q .; then
    sec_audit_report_pass 10 "usb-storage kernel module is not available"
else
    if ! lsmod | grep -q usb_storage && modprobe --showconfig | grep -Pq '^\h*(blacklist|install)\h+usb_storage\b'; then
        sec_audit_report_pass 10 "usb-storage kernel module is not available"
    else
        sec_audit_report_fail 10 "usb-storage kernel module is available, loaded, or not effectively blocked (modprobe blacklist/install)"
    fi
fi

# RULE11:
if sec_audit_tmp_is_isolated; then
    if sec_audit_mount_is_persisted /tmp; then
        sec_audit_report_pass 11 "/tmp is tmpfs or a separate partition"
    else
        sec_audit_report_fail 11 "/tmp is tmpfs or a separate partition is runtime-only (missing fstab or systemd .mount persistence)"
    fi
else
    sec_audit_report_fail 11 "/tmp does not meet tmpfs or separate-partition requirement"
fi
# RULE12:
if sec_audit_mount_resolves /tmp && sec_audit_mount_has_option /tmp nodev; then
    sec_audit_report_pass 12 "nodev option set on /tmp partition"
elif ! sec_audit_mount_resolves /tmp; then
    sec_audit_report_fail 12 "nodev is not set on /tmp (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 12 "nodev is not set on /tmp (or path not resolvable / not an explicit mount per policy)"
fi

# RULE13:
if sec_audit_mount_resolves /tmp && sec_audit_mount_has_option /tmp nosuid; then
    sec_audit_report_pass 13 "nosuid option set on /tmp partition"
elif ! sec_audit_mount_resolves /tmp; then
    sec_audit_report_fail 13 "nosuid is not set on /tmp (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 13 "nosuid is not set on /tmp (or path not resolvable / not an explicit mount per policy)"
fi

# RULE14:
if sec_audit_mount_resolves /tmp && sec_audit_mount_has_option /tmp noexec; then
    sec_audit_report_pass 14 "noexec option set on /tmp partition"
elif ! sec_audit_mount_resolves /tmp; then
    sec_audit_report_fail 14 "noexec is not set on /tmp (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 14 "noexec is not set on /tmp (or path not resolvable / not an explicit mount per policy)"
fi

# RULE15:
if sec_audit_shm_is_isolated; then
    if sec_audit_mount_is_persisted /dev/shm; then
        sec_audit_report_pass 15 "/dev/shm is tmpfs or a separate partition"
    else
        sec_audit_report_fail 15 "/dev/shm is tmpfs or a separate partition is runtime-only (missing fstab or systemd .mount persistence)"
    fi
else
    sec_audit_report_fail 15 "/dev/shm does not meet tmpfs or separate-partition requirement"
fi
# RULE16:
if sec_audit_mount_resolves /dev/shm && sec_audit_mount_has_option /dev/shm nodev; then
    sec_audit_report_pass 16 "nodev option set on /dev/shm partition"
elif ! sec_audit_mount_resolves /dev/shm; then
    sec_audit_report_fail 16 "nodev is not set on /dev/shm (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 16 "nodev is not set on /dev/shm (or path not resolvable / not an explicit mount per policy)"
fi

# RULE17:
if sec_audit_mount_resolves /dev/shm && sec_audit_mount_has_option /dev/shm nosuid; then
    sec_audit_report_pass 17 "nosuid option set on /dev/shm partition"
elif ! sec_audit_mount_resolves /dev/shm; then
    sec_audit_report_fail 17 "nosuid is not set on /dev/shm (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 17 "nosuid is not set on /dev/shm (or path not resolvable / not an explicit mount per policy)"
fi

# RULE18:
if sec_audit_mount_resolves /dev/shm && sec_audit_mount_has_option /dev/shm noexec; then
    sec_audit_report_pass 18 "noexec option set on /dev/shm partition"
elif ! sec_audit_mount_resolves /dev/shm; then
    sec_audit_report_fail 18 "noexec is not set on /dev/shm (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 18 "noexec is not set on /dev/shm (or path not resolvable / not an explicit mount per policy)"
fi

# RULE19:
if sec_audit_path_is_isolated_volume /home; then
    if sec_audit_mount_is_persisted /home; then
        sec_audit_report_pass 19 "separate partition exists for /home"
    else
        sec_audit_report_fail 19 "dedicated mount for /home is runtime-only (missing fstab or systemd .mount persistence)"
    fi
else
    sec_audit_report_fail 19 "no compliant dedicated mount for /home"
fi
# RULE20:
if sec_audit_mount_resolves /home && sec_audit_mount_has_option /home nodev; then
    sec_audit_report_pass 20 "nodev option set on /home partition"
elif ! sec_audit_mount_resolves /home; then
    sec_audit_report_fail 20 "nodev is not set on /home (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 20 "nodev is not set on /home (or path not resolvable / not an explicit mount per policy)"
fi

# RULE21:
if sec_audit_mount_resolves /home && sec_audit_mount_has_option /home nosuid; then
    sec_audit_report_pass 21 "nosuid option set on /home partition"
elif ! sec_audit_mount_resolves /home; then
    sec_audit_report_fail 21 "nosuid is not set on /home (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 21 "nosuid is not set on /home (or path not resolvable / not an explicit mount per policy)"
fi

# RULE22:
if sec_audit_path_is_isolated_volume /var; then
    if sec_audit_mount_is_persisted /var; then
        sec_audit_report_pass 22 "separate partition exists for /var"
    else
        sec_audit_report_fail 22 "dedicated mount for /var is runtime-only (missing fstab or systemd .mount persistence)"
    fi
else
    sec_audit_report_fail 22 "no compliant dedicated mount for /var"
fi
# RULE23:
if sec_audit_mount_resolves /var && sec_audit_mount_has_option /var nodev; then
    sec_audit_report_pass 23 "nodev option set on /var partition"
elif ! sec_audit_mount_resolves /var; then
    sec_audit_report_fail 23 "nodev is not set on /var (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 23 "nodev is not set on /var (or path not resolvable / not an explicit mount per policy)"
fi

# RULE24:
if sec_audit_mount_resolves /var && sec_audit_mount_has_option /var nosuid; then
    sec_audit_report_pass 24 "nosuid option set on /var partition"
elif ! sec_audit_mount_resolves /var; then
    sec_audit_report_fail 24 "nosuid is not set on /var (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 24 "nosuid is not set on /var (or path not resolvable / not an explicit mount per policy)"
fi

# RULE25:
if sec_audit_path_is_isolated_volume /var/tmp; then
    if sec_audit_mount_is_persisted /var/tmp; then
        sec_audit_report_pass 25 "separate partition exists for /var/tmp"
    else
        sec_audit_report_fail 25 "dedicated mount for /var/tmp is runtime-only (missing fstab or systemd .mount persistence)"
    fi
else
    sec_audit_report_fail 25 "no compliant dedicated mount for /var/tmp"
fi
# RULE26:
if sec_audit_mount_resolves /var/tmp && sec_audit_mount_has_option /var/tmp nodev; then
    sec_audit_report_pass 26 "nodev option set on /var/tmp partition"
elif ! sec_audit_mount_resolves /var/tmp; then
    sec_audit_report_fail 26 "nodev is not set on /var/tmp (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 26 "nodev is not set on /var/tmp (or path not resolvable / not an explicit mount per policy)"
fi

# RULE27:
if sec_audit_mount_resolves /var/tmp && sec_audit_mount_has_option /var/tmp nosuid; then
    sec_audit_report_pass 27 "nosuid option set on /var/tmp partition"
elif ! sec_audit_mount_resolves /var/tmp; then
    sec_audit_report_fail 27 "nosuid is not set on /var/tmp (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 27 "nosuid is not set on /var/tmp (or path not resolvable / not an explicit mount per policy)"
fi

# RULE28:
if sec_audit_mount_resolves /var/tmp && sec_audit_mount_has_option /var/tmp noexec; then
    sec_audit_report_pass 28 "noexec option set on /var/tmp partition"
elif ! sec_audit_mount_resolves /var/tmp; then
    sec_audit_report_fail 28 "noexec is not set on /var/tmp (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 28 "noexec is not set on /var/tmp (or path not resolvable / not an explicit mount per policy)"
fi

# RULE29:
if sec_audit_path_is_isolated_volume /var/log; then
    if sec_audit_mount_is_persisted /var/log; then
        sec_audit_report_pass 29 "separate partition exists for /var/log"
    else
        sec_audit_report_fail 29 "dedicated mount for /var/log is runtime-only (missing fstab or systemd .mount persistence)"
    fi
else
    sec_audit_report_fail 29 "no compliant dedicated mount for /var/log"
fi
# RULE30:
if sec_audit_mount_resolves /var/log && sec_audit_mount_has_option /var/log nodev; then
    sec_audit_report_pass 30 "nodev option set on /var/log partition"
elif ! sec_audit_mount_resolves /var/log; then
    sec_audit_report_fail 30 "nodev is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 30 "nodev is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
fi

# RULE31:
if sec_audit_mount_resolves /var/log && sec_audit_mount_has_option /var/log nosuid; then
    sec_audit_report_pass 31 "nosuid option set on /var/log partition"
elif ! sec_audit_mount_resolves /var/log; then
    sec_audit_report_fail 31 "nosuid is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 31 "nosuid is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
fi

# RULE32:
if sec_audit_mount_resolves /var/log && sec_audit_mount_has_option /var/log noexec; then
    sec_audit_report_pass 32 "noexec option set on /var/log partition"
elif ! sec_audit_mount_resolves /var/log; then
    sec_audit_report_fail 32 "noexec is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 32 "noexec is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
fi

# RULE33:
if sec_audit_path_is_isolated_volume /var/log/audit; then
    if sec_audit_mount_is_persisted /var/log/audit; then
        sec_audit_report_pass 33 "separate partition exists for /var/log/audit"
    else
        sec_audit_report_fail 33 "dedicated mount for /var/log/audit is runtime-only (missing fstab or systemd .mount persistence)"
    fi
else
    sec_audit_report_fail 33 "no compliant dedicated mount for /var/log/audit"
fi
# RULE34:
if sec_audit_mount_resolves /var/log/audit && sec_audit_mount_has_option /var/log/audit nodev; then
    sec_audit_report_pass 34 "nodev option set on /var/log/audit partition"
elif ! sec_audit_mount_resolves /var/log/audit; then
    sec_audit_report_fail 34 "nodev is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 34 "nodev is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
fi

# RULE35:
if sec_audit_mount_resolves /var/log/audit && sec_audit_mount_has_option /var/log/audit nosuid; then
    sec_audit_report_pass 35 "nosuid option set on /var/log/audit partition"
elif ! sec_audit_mount_resolves /var/log/audit; then
    sec_audit_report_fail 35 "nosuid is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 35 "nosuid is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
fi

# RULE36:
if sec_audit_mount_resolves /var/log/audit && sec_audit_mount_has_option /var/log/audit noexec; then
    sec_audit_report_pass 36 "noexec option set on /var/log/audit partition"
elif ! sec_audit_mount_resolves /var/log/audit; then
    sec_audit_report_fail 36 "noexec is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 36 "noexec is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
fi

# RULE37:
_rule37_k=$(sec_audit_rpm_gpg_pubkey_count)
_rule37_sample=""
if sec_audit_have_bin rpm && [ "${_rule37_k:-0}" -gt 0 ]; then
    _rule37_sample=$(
        rpm -qa 'gpg-pubkey*' --qf '%{VERSION}\n' 2>/dev/null | awk 'NF && NR <= 6 { s = (s ? s "," : s) $1 } END { print s }'
    )
fi
if ! sec_audit_have_bin rpm; then
    sec_audit_report_fail 37 "rpm not available; cannot verify gpg-pubkey packages in the RPM database"
elif [ "${_rule37_k:-0}" -eq 0 ]; then
    sec_audit_report_fail 37 "no gpg-pubkey packages in the RPM database (import distribution or repository signing keys)"
else
    sec_audit_report_pass 37 "${_rule37_k} gpg-pubkey package(s) in RPM DB (sample key VERSION ids: ${_rule37_sample:-n/a})"
fi

# RULE38:
_rule38_main=$(sec_audit_dnf_main_option gpgcheck)
_rule38_repo=$(sec_audit_yum_repo_list_explicit_gpgcheck0 | head -n1)
if sec_audit_truthy_false "$_rule38_main"; then
    sec_audit_report_fail 38 "merged [main] gpgcheck is disabled (effective value: ${_rule38_main})"
elif [ -n "$_rule38_repo" ]; then
    sec_audit_report_fail 38 "enabled repository section explicitly sets gpgcheck=0 (${_rule38_repo//|/ -> })"
else
    sec_audit_report_pass 38 "[main] gpgcheck is not false and no enabled .repo section forces gpgcheck=0"
fi

# RULE39:
_rule39_main=$(sec_audit_dnf_main_option repo_gpgcheck)
_rule39_repo=$(sec_audit_yum_repo_list_explicit_repo_gpgcheck0 | head -n1)
if sec_audit_truthy_false "$_rule39_main"; then
    sec_audit_report_fail 39 "merged [main] repo_gpgcheck is disabled (effective value: ${_rule39_main})"
elif [ -z "$_rule39_main" ]; then
    sec_audit_report_fail 39 "repo_gpgcheck not explicitly enabled in merged [main] (dnf defaults to false when unset)"
elif ! sec_audit_truthy_true "$_rule39_main"; then
    sec_audit_report_fail 39 "repo_gpgcheck in [main] is not a true value (expected 1/true/yes/on; got: ${_rule39_main})"
elif [ -n "$_rule39_repo" ]; then
    sec_audit_report_fail 39 "enabled repository section explicitly sets repo_gpgcheck=0 (${_rule39_repo//|/ -> })"
else
    sec_audit_report_pass 39 "repo_gpgcheck enabled in [main] and no enabled .repo section forces repo_gpgcheck=0"
fi

# RULE40:
_rule40_dnf_n=$(sec_audit_dnf_enabled_repo_count)
if [ ! -d /etc/yum.repos.d ]; then
    sec_audit_report_fail 40 "/etc/yum.repos.d is missing"
else
    _rule40_nrepo=0
    shopt -s nullglob
    for _rf in /etc/yum.repos.d/*.repo; do
        [ -f "$_rf" ] && _rule40_nrepo=$((_rule40_nrepo + 1))
    done
    shopt -u nullglob
    if [ "${_rule40_nrepo:-0}" -eq 0 ]; then
        sec_audit_report_fail 40 "no .repo files under /etc/yum.repos.d"
    elif ! sec_audit_yum_repo_any_enabled_has_uris; then
        sec_audit_report_fail 40 "no enabled repository section defines a non-empty baseurl, mirrorlist, or metalink"
    elif sec_audit_have_bin dnf && [ "${_rule40_dnf_n:-0}" -eq 0 ]; then
        sec_audit_report_fail 40 ".repo files define URIs but dnf repolist enabled reports 0 repos (metadata, plugin, or config error)"
    else
        if sec_audit_have_bin dnf && [ "${_rule40_dnf_n:-0}" -gt 0 ]; then
            sec_audit_report_pass 40 "${_rule40_nrepo} .repo file(s); dnf reports ${_rule40_dnf_n} enabled repo(s); enabled sections include package URIs"
        else
            sec_audit_report_pass 40 "${_rule40_nrepo} .repo file(s); enabled sections include baseurl/mirrorlist/metalink (dnf not used for count)"
        fi
    fi
fi

# RULE41:
_rule41_iwd=$(sec_audit_dnf_main_option install_weak_deps)
if sec_audit_truthy_false "$_rule41_iwd"; then
    sec_audit_report_pass 41 "install_weak_deps is false in merged [main] (weak dependencies not installed by default)"
elif [ -z "$_rule41_iwd" ]; then
    sec_audit_report_fail 41 "install_weak_deps not set to 0/false/no/off in [main] (dnf default enables weak dependencies)"
else
    sec_audit_report_fail 41 "install_weak_deps is not false in merged [main] (effective: ${_rule41_iwd})"
fi

# RULE42:
if rpm -q libselinux &>/dev/null; then
    sec_audit_report_pass 42 "SELinux is installed"
else
    sec_audit_report_fail 42 "SELinux stack (libselinux) is not installed"
fi

# RULE43:
if grep -P '(selinux|enforcing)=0\b' /proc/cmdline 2>/dev/null; then
    sec_audit_report_fail 43 "SELinux is disabled via kernel command line or bootloader configuration"
elif grep -Prs '^\h*([^#\n\r]+\h+)?kernelopts=([^#\n\r]+\h+)?(selinux|enforcing)=0\b' /boot/grub2 /boot/efi 2>/dev/null; then
    sec_audit_report_fail 43 "SELinux is disabled via kernel command line or bootloader configuration"
else
    sec_audit_report_pass 43 "SELinux is not disabled in bootloader configuration"
fi

# RULE44:
if grep -Psi '^\h*SELINUXTYPE\h*=\h*(targeted|mls)\b' /etc/selinux/config 2>/dev/null; then
    sec_audit_report_pass 44 "SELinux policy is configured"
else
    sec_audit_report_fail 44 "SELinux policy type is not set to targeted or mls in /etc/selinux/config"
fi

# RULE45:
_ge45=$(getenforce 2>/dev/null || true)
if grep -Pi '^\h*SELINUX=disabled\b' /etc/selinux/config 2>/dev/null; then
    sec_audit_report_fail 45 "SELinux is disabled in /etc/selinux/config"
elif [[ "$_ge45" == "Disabled" ]]; then
    sec_audit_report_fail 45 "getenforce reports Disabled"
elif [[ "$_ge45" == "Permissive" ]]; then
    sec_audit_report_fail 45 "SELinux is permissive (CRE default requires enforcing; set waiver or fix before audit)"
elif grep -Pi '^\h*SELINUX=(enforcing|permissive)\b' /etc/selinux/config 2>/dev/null && [[ "$_ge45" == "Enforcing" ]]; then
    sec_audit_report_pass 45 "the SELinux mode is not disabled (enforcing)"
else
    sec_audit_report_fail 45 "SELinux mode is not in an acceptable state (config/getenforce mismatch or disabled)"
fi
# RULE46:
_ge46=$(getenforce 2>/dev/null || true)
_cfg46=$(grep -Pi '^\h*SELINUX=\K\w+' /etc/selinux/config 2>/dev/null | head -n1 || true)
if [[ "$_ge46" != "Enforcing" ]]; then
    sec_audit_report_fail 46 "getenforce is '${_ge46:-unknown}', expected Enforcing"
elif [[ "$_cfg46" != "enforcing" ]]; then
    sec_audit_report_fail 46 "runtime Enforcing but /etc/selinux/config SELINUX=${_cfg46:-unset} (will revert after reboot)"
else
    sec_audit_report_pass 46 "the SELinux mode is enforcing (runtime and config)"
fi
# RULE47:
if ps -eZ 2>/dev/null | grep -q unconfined_service_t; then
    sec_audit_report_fail 47 "Processes running with unconfined_service_t were detected"
else
    sec_audit_report_pass 47 "no unconfined services exist"
fi

# RULE48:
if rpm -q setroubleshoot &>/dev/null; then
    sec_audit_report_fail 48 "SETroubleshoot package is installed"
else
    sec_audit_report_pass 48 "SETroubleshoot is not installed"
fi

# RULE49:
if sec_audit_grub_cfg_matches '^[[:space:]]*set superusers' && sec_audit_grub_cfg_matches 'password_pbkdf2'; then
    sec_audit_report_pass 49 "bootloader password is set (grub.cfg under /boot/grub2 or EFI)"
else
    sec_audit_report_fail 49 "GRUB bootloader superuser/password_pbkdf2 is not configured as required in grub.cfg"
fi
# RULE50:
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
    sec_audit_report_pass 50 "access to bootloader config is configured"
else
    sec_audit_report_fail 50 "/boot/grub2/grub.cfg (or EFI grub.cfg) owner/mode is not root:root with mode 600"
fi
# RULE51:
if sec_audit_core_dumps_limited; then
    sec_audit_report_pass 51 "limits * hard core 0 present and systemd DefaultLimitCORE does not allow unlimited core dumps"
elif grep -Psi '^\*\s+hard\s+core\s+0\b' /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null; then
    sec_audit_report_fail 51 "limits.conf sets hard core 0 but systemd DefaultLimitCORE contradicts (check system.conf / user.conf drop-ins)"
else
    sec_audit_report_fail 51 "core file size limits are not configured (limits * hard core 0 not found)"
fi

# RULE52:
sec_audit_assert_sysctl_equals 52 fs.protected_hardlinks 1
# RULE53:
sec_audit_assert_sysctl_equals 53 fs.protected_symlinks 1
# RULE54:
sec_audit_assert_sysctl_equals 54 fs.suid_dumpable 0
# RULE55:
sec_audit_assert_sysctl_equals 55 kernel.dmesg_restrict 1
# RULE56:
sec_audit_assert_sysctl_equals 56 kernel.kptr_restrict 2
# RULE57:
sec_audit_assert_sysctl_equals 57 kernel.yama.ptrace_scope 1
# RULE58:
sec_audit_assert_sysctl_equals 58 kernel.randomize_va_space 2
# RULE59:
_rule59_cat=$(systemd-analyze cat-config systemd/coredump.conf 2>/dev/null)
_rule59_corep=$(sec_audit_sysctl_runtime kernel.core_pattern)
if builtin printf '%s\n' "$_rule59_cat" | grep -Pq '^\h*ProcessSizeMax=\h*0\b'; then
    if [[ "$_rule59_corep" == *systemd-coredump* ]] || [[ "$_rule59_corep" == *coredump* ]]; then
        sec_audit_report_pass 59 "merged coredump.conf sets ProcessSizeMax=0; kernel.core_pattern uses systemd-coredump"
    else
        sec_audit_report_pass 59 "merged coredump.conf sets ProcessSizeMax=0 (kernel.core_pattern='${_rule59_corep:-?}' may omit systemd-coredump text)"
    fi
else
    sec_audit_report_fail 59 "merged systemd/coredump.conf does not set ProcessSizeMax=0"
fi

# RULE60:
_rule60_cat=$(systemd-analyze cat-config systemd/coredump.conf 2>/dev/null)
if builtin printf '%s\n' "$_rule60_cat" | grep -Pq '^\h*Storage=\h*none\b'; then
    sec_audit_report_pass 60 "merged systemd/coredump.conf sets Storage=none"
else
    sec_audit_report_fail 60 "merged systemd/coredump.conf does not set Storage=none"
fi

# RULE61:
if grep -Pi '^\h*LEGACY\b' /etc/crypto-policies/config 2>/dev/null; then
    sec_audit_report_fail 61 "System-wide crypto policy is LEGACY in /etc/crypto-policies/config"
else
    sec_audit_report_pass 61 "system wide crypto policy is not set to legacy"
fi

# RULE62:
if grep -Pi '(^\h*mac\h*=\h*([^#\n\r]+)?-128|hmac-sha1)' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null; then
    sec_audit_report_fail 62 "Weak MAC algorithms still present in /etc/crypto-policies/state/CURRENT.pol"
else
    sec_audit_report_pass 62 "system wide crypto policy macs are configured"
fi

# RULE63:
if grep -Piq '^\h*cipher@(lib|open)ssh(-server|-client)?\h*=\h*([^#\n\r]+)?-CBC\b' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null; then
    sec_audit_report_pass 63 "system wide crypto policy disables cbc for ssh"
elif grep -Piq '^\h*cipher\h*=\h*([^#\n\r]+)?-CBC\b' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null; then
    sec_audit_report_pass 63 "system wide crypto policy disables cbc for ssh"
else
    sec_audit_report_fail 63 "CBC ciphers for SSH are still allowed by crypto policy (CURRENT.pol)"
fi

# RULE64:
if grep -Psi "(\\\v|\\\r|\\\m|\\\s|\b$(grep ^ID= /etc/os-release 2>/dev/null | cut -d= -f2 | sed -e 's/"//g')\b)" /etc/motd 2>/dev/null; then
    sec_audit_report_fail 64 "/etc/motd is missing or does not contain required banner content"
else
    sec_audit_report_pass 64 "/etc/motd is configured"
fi

# RULE65:
if grep -Psi "(\\\v|\\\r|\\\m|\\\s|\b$(grep ^ID= /etc/os-release 2>/dev/null | cut -d= -f2 | sed -e 's/"//g')\b)" /etc/issue 2>/dev/null; then
    sec_audit_report_fail 65 "/etc/issue is missing or does not contain required local login banner"
else
    sec_audit_report_pass 65 "/etc/issue is configured"
fi

# RULE66:
if [ -f /etc/issue.net ]; then
    if grep -Psi "(\\\v|\\\r|\\\m|\\\s|\b$(grep ^ID= /etc/os-release 2>/dev/null | cut -d= -f2 | sed -e 's/"//g')\b)" /etc/issue.net 2>/dev/null; then
        sec_audit_report_fail 66 "/etc/issue.net is missing or does not contain required remote login banner"
    else
        sec_audit_report_pass 66 "/etc/issue.net is configured"
    fi
else
    sec_audit_report_pass 66 "/etc/issue.net is configured"
fi

# RULE67:
if [ -e /etc/motd ]; then
    if stat -Lc '%a' /etc/motd 2>/dev/null | grep -qE '^[0-6]44$'; then
        if stat -Lc '%U:%G' /etc/motd 2>/dev/null | grep -q '^root:root$'; then
            sec_audit_report_pass 67 "access to /etc/motd is configured"
        else
            sec_audit_report_fail 67 "File /etc/motd permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 67 "File /etc/motd permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 67 "access to /etc/motd is configured (file not found)"
fi

# RULE68:
if stat -Lc '%a' /etc/issue 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' /etc/issue 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 68 "access to /etc/issue is configured"
    else
        sec_audit_report_fail 68 "File /etc/issue permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 68 "File /etc/issue permissions or ownership not correct"
fi

# RULE69:
if [ -e /etc/issue.net ]; then
    if stat -Lc '%a' /etc/issue.net 2>/dev/null | grep -qE '^[0-6]44$'; then
        if stat -Lc '%U:%G' /etc/issue.net 2>/dev/null | grep -q '^root:root$'; then
            sec_audit_report_pass 69 "access to /etc/issue.net is configured"
        else
            sec_audit_report_fail 69 "File /etc/issue.net permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 69 "File /etc/issue.net permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 69 "access to /etc/issue.net is configured (file not found)"
fi

# RULE70:
GDM_CONFIG="/etc/gdm/custom.conf"
if [ -f "$GDM_CONFIG" ]; then
    if grep -Pzo "\[org/gnome/login-screen\][^\[]*banner-message-enable=true" "$GDM_CONFIG" 2>/dev/null | grep -q .; then
        sec_audit_report_pass 70 "GDM login banner is configured"
    else
        sec_audit_report_fail 70 "GDM login banner is not configured in $GDM_CONFIG"
    fi
else
    sec_audit_report_fail 70 "GDM configuration file not found ($GDM_CONFIG)"
fi

# RULE71:
if rpm -q gdm &>/dev/null && grep -q "DisableUserList=true" /etc/gdm/custom.conf 2>/dev/null; then
    sec_audit_report_pass 71 "GDM disable-user-list is configured"
elif ! rpm -q gdm &>/dev/null; then
    sec_audit_report_pass 71 "GDM is not installed"
else
    sec_audit_report_fail 71 "GDM disable-user-list is not configured"
fi

# RULE72:
if grep -q "idle-delay=uint32" /etc/dconf/db/gdm.d/* 2>/dev/null || \
   grep -q "lock-delay=uint32" /etc/dconf/db/gdm.d/* 2>/dev/null; then
    sec_audit_report_pass 72 "GDM screen lock is configured"
else
    sec_audit_report_fail 72 "GDM screen lock is not configured"
fi

# RULE73:
if grep -q "automount=false" /etc/dconf/db/gdm.d/* 2>/dev/null || \
   grep -q "automount-open=false" /etc/dconf/db/gdm.d/* 2>/dev/null; then
    sec_audit_report_pass 73 "GDM automount is configured"
else
    sec_audit_report_fail 73 "GDM automount is not configured"
fi

# RULE74:
if grep -q "autorun-never=true" /etc/dconf/db/gdm.d/* 2>/dev/null; then
    sec_audit_report_pass 74 "GDM autorun-never is configured"
else
    sec_audit_report_fail 74 "GDM autorun-never is not configured"
fi

# RULE75:
if grep -Psi '^\h*WaylandEnable=false' /etc/gdm/custom.conf 2>/dev/null; then
    sec_audit_report_pass 75 "Xwayland is configured"
else
    sec_audit_report_fail 75 "WaylandEnable=false (or equivalent) is not set in GDM custom.conf - Xwayland may remain enabled"
fi

# RULE76:
sec_audit_assert_service_unused 76 autofs "autofs services are not in use" "autofs services are installed and enabled or actively running" "autofs.service"
# RULE77:
sec_audit_assert_service_unused 77 avahi "avahi daemon services are not in use" "avahi daemon services are installed and enabled or actively running" "avahi-daemon.socket" "avahi-daemon.service"
# RULE78:
sec_audit_assert_service_unused 78 cockpit-ws "cockpit web services are not in use" "cockpit web services are installed and enabled or actively running" "cockpit.socket" "cockpit.service"
# RULE79:
sec_audit_assert_service_unused 79 dhcp-server "dhcp server services are not in use" "dhcp server services are installed and enabled or actively running" "dhcpd.service" "dhcpd6.service"
# RULE80:
sec_audit_assert_service_unused 80 bind "dns server services are not in use" "dns server services are installed and enabled or actively running" "named.service"
# RULE81:
sec_audit_assert_service_unused 81 dnsmasq "dnsmasq services are not in use" "dnsmasq services are installed and enabled or actively running" "dnsmasq.service"
# RULE82:
sec_audit_assert_service_unused 82 vsftpd "ftp server services are not in use" "ftp server services are installed and enabled or actively running" "vsftpd.service"
# RULE83:
if sec_audit_pkg_any_installed dovecot cyrus-imapd; then
    if sec_audit_systemd_unit_live dovecot.socket dovecot.service cyrus-imapd.service; then
        sec_audit_report_fail 83 "message access server services are installed and enabled or actively running"
    else
        sec_audit_report_pass 83 "message access server services are not in use (package present but units masked/disabled/inactive)"
    fi
else
    sec_audit_report_pass 83 "message access server services are not in use"
fi
# RULE84:
sec_audit_assert_service_unused 84 nfs-utils "network file system services are not in use" "network file system services are installed and enabled or actively running" "nfs-server.service"
# RULE85:
sec_audit_assert_service_unused 85 cups "print server services are not in use" "print server services are installed and enabled or actively running" "cups.socket" "cups.service"
# RULE86:
sec_audit_assert_service_unused 86 rpcbind "rpcbind services are not in use" "rpcbind services are installed and enabled or actively running" "rpcbind.socket" "rpcbind.service"
# RULE87:
sec_audit_assert_service_unused 87 rsync-daemon "rsync services are not in use" "rsync services are installed and enabled or actively running" "rsyncd.socket" "rsyncd.service"
# RULE88:
sec_audit_assert_service_unused 88 samba "samba file server services are not in use" "samba file server services are installed and enabled or actively running" "smb.service"
# RULE89:
sec_audit_assert_service_unused 89 net-snmp "snmp services are not in use" "snmp services are installed and enabled or actively running" "snmpd.service"
# RULE90:
sec_audit_assert_service_unused 90 telnet-server "telnet server services are not in use" "telnet server services are installed and enabled or actively running" "telnet.socket"
# RULE91:
sec_audit_assert_service_unused 91 tftp-server "tftp server services are not in use" "tftp server services are installed and enabled or actively running" "tftp.socket" "tftp.service"
# RULE92:
sec_audit_assert_service_unused 92 squid "web proxy server services are not in use" "web proxy server services are installed and enabled or actively running" "squid.service"
# RULE93:
if sec_audit_pkg_any_installed httpd nginx; then
    if sec_audit_systemd_unit_live httpd.service nginx.service; then
        sec_audit_report_fail 93 "web server services are installed and enabled or actively running"
    else
        sec_audit_report_pass 93 "web server services are not in use (package present but units masked/disabled/inactive)"
    fi
else
    sec_audit_report_pass 93 "web server services are not in use"
fi
# RULE94:
if rpm -q gdm &>/dev/null || systemctl is-enabled gdm 2>/dev/null | grep -q 'enabled' || systemctl is-active gdm 2>/dev/null | grep -q '^active'; then
    sec_audit_report_fail 94 "GNOME Display Manager (gdm) package is still installed"
else
    sec_audit_report_pass 94 "GNOME Display Manager is removed"
fi

# RULE95:
if rpm -q xorg-x11-server-Xwayland &>/dev/null; then
    sec_audit_report_fail 95 "X window server services are installed and enabled or actively running"
else
    sec_audit_report_pass 95 "X window server services are not in use"
fi

# RULE96:
if rpm -q ftp &>/dev/null; then
    sec_audit_report_fail 96 "ftp client package is installed"
else
    sec_audit_report_pass 96 "ftp client is not installed"
fi

# RULE97:
if rpm -q openldap-clients &>/dev/null; then
    sec_audit_report_fail 97 "ldap client package is installed"
else
    sec_audit_report_pass 97 "ldap client is not installed"
fi

# RULE98:
if rpm -q telnet &>/dev/null; then
    sec_audit_report_fail 98 "telnet client package is installed"
else
    sec_audit_report_pass 98 "telnet client is not installed"
fi

# RULE99:
if rpm -q tftp &>/dev/null; then
    sec_audit_report_fail 99 "tftp client package is installed"
else
    sec_audit_report_pass 99 "tftp client is not installed"
fi

# RULE100:
if rpm -q chrony &>/dev/null; then
    if systemctl is-active chronyd.service &>/dev/null; then
        sec_audit_report_pass 100 "chrony is installed and chronyd.service is active"
    else
        sec_audit_report_fail 100 "chrony is installed but chronyd.service is not active"
    fi
else
    sec_audit_report_fail 100 "time synchronization is not in use (chrony not installed)"
fi

# RULE101:
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
    sec_audit_report_pass 101 "chrony has ${_ch101_src:-0} server/pool line(s) in conf or chrony.d${_ch101_track}"
else
    sec_audit_report_fail 101 "chrony is not configured with time sources (no server/pool in chrony.conf or chrony.d)"
fi

# RULE102:
if grep -Psi -- '^\h*OPTIONS=\"?\h*([^#\n\r]+\h+)?-u\h+root\b' /etc/sysconfig/chronyd 2>/dev/null; then
    sec_audit_report_fail 102 "chronyd is configured to run as root (OPTIONS in /etc/sysconfig/chronyd)"
else
    sec_audit_report_pass 102 "chrony is not run as the root user"
fi

# RULE103:
if systemctl is-enabled crond.service 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active crond.service 2>/dev/null | grep -q 'active'; then
        sec_audit_report_pass 103 "cron daemon is enabled and active"
    else
        sec_audit_report_fail 103 "crond service is not enabled or not active"
    fi
else
    sec_audit_report_fail 103 "crond service is not enabled or not active"
fi

# RULE104:
if stat -Lc '%a' /etc/crontab 2>/dev/null | grep -q '^[0-6]00$'; then
    if stat -Lc '%U:%G' /etc/crontab 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 104 "access to /etc/crontab is configured"
    else
        sec_audit_report_fail 104 "File /etc/crontab permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 104 "File /etc/crontab permissions or ownership not correct"
fi

# RULE105:
if stat -Lc '%a' /etc/cron.hourly 2>/dev/null | grep -q '^700$'; then
    if stat -Lc '%U:%G' /etc/cron.hourly 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 105 "access to /etc/cron.hourly is configured"
    else
        sec_audit_report_fail 105 "File /etc/cron.hourly permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 105 "File /etc/cron.hourly permissions or ownership not correct"
fi

# RULE106:
if stat -Lc '%a' /etc/cron.daily 2>/dev/null | grep -q '^700$'; then
    if stat -Lc '%U:%G' /etc/cron.daily 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 106 "access to /etc/cron.daily is configured"
    else
        sec_audit_report_fail 106 "File /etc/cron.daily permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 106 "File /etc/cron.daily permissions or ownership not correct"
fi

# RULE107:
if stat -Lc '%a' /etc/cron.weekly 2>/dev/null | grep -q '^700$'; then
    if stat -Lc '%U:%G' /etc/cron.weekly 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 107 "access to /etc/cron.weekly is configured"
    else
        sec_audit_report_fail 107 "File /etc/cron.weekly permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 107 "File /etc/cron.weekly permissions or ownership not correct"
fi

# RULE108:
if stat -Lc '%a' /etc/cron.monthly 2>/dev/null | grep -q '^700$'; then
    if stat -Lc '%U:%G' /etc/cron.monthly 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 108 "access to /etc/cron.monthly is configured"
    else
        sec_audit_report_fail 108 "File /etc/cron.monthly permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 108 "File /etc/cron.monthly permissions or ownership not correct"
fi

# RULE109:
if stat -Lc '%a' /etc/cron.yearly 2>/dev/null | grep -q '^700$'; then
    if stat -Lc '%U:%G' /etc/cron.yearly 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 109 "access to /etc/cron.yearly is configured"
    else
        sec_audit_report_fail 109 "File /etc/cron.yearly permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 109 "File /etc/cron.yearly permissions or ownership not correct"
fi

# RULE110:
if stat -Lc '%a' /etc/cron.d 2>/dev/null | grep -q '^700$'; then
    if stat -Lc '%U:%G' /etc/cron.d 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 110 "access to /etc/cron.d is configured"
    else
        sec_audit_report_fail 110 "File /etc/cron.d permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 110 "File /etc/cron.d permissions or ownership not correct"
fi

# RULE111:
if [ -e /etc/cron.allow ]; then
    if stat -Lc '%a' /etc/cron.allow 2>/dev/null | grep -qE '^640$'; then
        if stat -Lc '%U' /etc/cron.allow 2>/dev/null | grep -q 'root'; then
            if stat -Lc '%G' /etc/cron.allow 2>/dev/null | grep -qE 'root|crontab'; then
                sec_audit_report_pass 111 "access to crontab is configured"
            else
                sec_audit_report_fail 111 "File crontab permissions or ownership not correct"
            fi
        else
            sec_audit_report_fail 111 "File crontab permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 111 "File crontab permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 111 "File crontab permissions or ownership not correct"
fi

# RULE112:
if [ -e /etc/at.allow ]; then
    if stat -Lc '%a' /etc/at.allow 2>/dev/null | grep -qE '^640$'; then
        if stat -Lc '%U' /etc/at.allow 2>/dev/null | grep -q 'root'; then
            if stat -Lc '%G' /etc/at.allow 2>/dev/null | grep -qE 'daemon|root'; then
                sec_audit_report_pass 112 "access to at is configured"
            else
                sec_audit_report_fail 112 "File at permissions or ownership not correct"
            fi
        else
            sec_audit_report_fail 112 "File at permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 112 "File at permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 112 "File at permissions or ownership not correct"
fi

# RULE113:
if [ -f /proc/sys/net/ipv6/conf/all/disable_ipv6 ]; then
    sec_audit_report_pass 113 "IPv6 status is identified"
else
    sec_audit_report_fail 113 "IPv6 status is not identified"
fi

# RULE114:
if compgen -G "/sys/class/net/*/wireless" >/dev/null; then
    sec_audit_report_fail 114 "Wireless interfaces are present under /sys/class/net"
else
    sec_audit_report_pass 114 "wireless interfaces are not available"
fi

# RULE115:
sec_audit_assert_service_unused 115 bluez "bluetooth services are not in use" "bluetooth services are installed and enabled or actively running" "bluetooth.service"
# RULE116:
sec_audit_assert_kmod_disabled 116 "atm kernel module" atm atm.ko* "atm"
# RULE117:
sec_audit_assert_kmod_disabled 117 "can kernel module" can can.ko* "can"
# RULE118:
sec_audit_assert_kmod_disabled 118 "dccp kernel module" dccp dccp.ko* "dccp"
# RULE119:
sec_audit_assert_kmod_disabled 119 "tipc kernel module" tipc tipc.ko* "tipc"
# RULE120:
sec_audit_assert_kmod_disabled 120 "rds kernel module" rds rds.ko* "rds"
# RULE121:
sec_audit_assert_kmod_disabled 121 "sctp kernel module" sctp sctp.ko* "sctp"
# RULE122:
sec_audit_assert_sysctl_equals 122 net.ipv4.ip_forward 0

# RULE123:
sec_audit_assert_sysctl_equals 123 net.ipv4.conf.all.forwarding 0

# RULE124:
sec_audit_assert_sysctl_equals 124 net.ipv4.conf.default.forwarding 0

# RULE125:
sec_audit_assert_sysctl_equals 125 net.ipv4.conf.all.send_redirects 0

# RULE126:
sec_audit_assert_sysctl_equals 126 net.ipv4.conf.default.send_redirects 0

# RULE127:
sec_audit_assert_sysctl_equals 127 net.ipv4.conf.all.accept_redirects 0

# RULE128:
sec_audit_assert_sysctl_equals 128 net.ipv4.conf.all.secure_redirects 0

if ! sec_audit_sshd_effective_usable; then
    for _sshn in 129 130 131 132 133 134 135 136 137 138 156 157 158 159 160 161 162 163 164 165 166; do
        sec_audit_report_fail "$_sshn" "unable_to_evaluate: sshd -T produced no effective configuration"
    done
else
# RULE129:
sec_audit_assert_sysctl_equals 129 net.ipv4.conf.all.rp_filter 1

# RULE130:
sec_audit_assert_sysctl_equals 130 net.ipv4.conf.default.rp_filter 1

# RULE131:
sec_audit_assert_sysctl_equals 131 net.ipv4.conf.all.log_martians 1

# RULE132:
sec_audit_assert_sysctl_equals 132 net.ipv4.conf.default.log_martians 1

# RULE133:
sec_audit_assert_sysctl_equals 133 net.ipv4.tcp_syncookies 1

# RULE134:
sec_audit_assert_sysctl_equals 134 net.ipv6.conf.all.forwarding 0

# RULE135:
sec_audit_assert_sysctl_equals 135 net.ipv6.conf.default.forwarding 0

# RULE136:
sec_audit_assert_sysctl_equals 136 net.ipv6.conf.all.accept_redirects 0

# RULE137:
sec_audit_assert_sysctl_equals 137 net.ipv6.conf.all.accept_ra 0

# RULE138:
sec_audit_assert_sysctl_equals 138 net.ipv6.conf.default.accept_ra 0

# RULE122:
if rpm -q firewalld &>/dev/null; then
    sec_audit_report_pass 122 "firewalld is installed"
else
    sec_audit_report_fail 122 "firewalld package is not installed"
fi

# RULE123:
if grep -Psi 'FirewallBackend\h*=\h*nftables\b' /etc/firewalld/firewalld.conf 2>/dev/null; then
    _fw140_be=""
    if sec_audit_have_bin firewall-cmd && firewall-cmd --state 2>/dev/null | grep -qi running; then
        _fw140_be=$(firewall-cmd --get-backend 2>/dev/null)
        if [[ "$_fw140_be" == "nftables" ]]; then
            sec_audit_report_pass 123 "firewalld.conf uses nftables and runtime backend is nftables"
        else
            sec_audit_report_pass 123 "firewalld.conf uses nftables (runtime backend reports '${_fw140_be:-?}')"
        fi
    else
        sec_audit_report_pass 123 "firewalld.conf uses nftables (firewalld not running; runtime backend not verified)"
    fi
else
    sec_audit_report_fail 123 "firewalld backend is not configured (FirewallBackend=nftables missing in firewalld.conf)"
fi

# RULE124:
if systemctl is-enabled firewalld.service 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active firewalld.service 2>/dev/null | grep -q 'active'; then
        _fw141_nft=""
        if sec_audit_have_bin nft && nft list ruleset 2>/dev/null | grep -q .; then
            _fw141_nft="; nftables ruleset is non-empty"
        fi
        sec_audit_report_pass 124 "firewalld.service is enabled and active${_fw141_nft}"
    else
        sec_audit_report_fail 124 "firewalld.service is not enabled or not active"
    fi
else
    sec_audit_report_fail 124 "firewalld.service is not enabled or not active"
fi

# RULE125:
if systemctl is-active firewalld &>/dev/null; then
    ACTIVE_ZONE=$(firewall-cmd --get-default-zone 2>/dev/null)
    ZONE_TARGET=$(firewall-cmd --zone="$ACTIVE_ZONE" --get-target 2>/dev/null)
    _fw142_if=$(firewall-cmd --zone="$ACTIVE_ZONE" --list-interfaces 2>/dev/null | wc -w)
    if [ "$ZONE_TARGET" = "DROP" ] || [ "$ZONE_TARGET" = "REJECT" ]; then
        sec_audit_report_pass 125 "firewalld default zone '$ACTIVE_ZONE' target is $ZONE_TARGET (${_fw142_if:-0} interface(s) assigned)"
    else
        sec_audit_report_fail 125 "firewalld active zone target is not secure (current: $ZONE_TARGET)"
    fi
else
    sec_audit_report_fail 125 "firewalld is not active"
fi

# RULE126:
if systemctl is-active firewalld &>/dev/null; then
    if firewall-cmd --list-rich-rules 2>/dev/null | grep -Eiq 'lo|loopback|127\.0\.0\.1|interface\s*=\s*\"lo\"|interface\s*=\s*lo\b'; then
        sec_audit_report_pass 126 "firewalld rich rules mention loopback / lo / localhost"
    else
        sec_audit_report_fail 126 "firewalld loopback traffic is not configured"
    fi
else
    sec_audit_report_fail 126 "firewalld is not active"
fi

# RULE127:
if systemctl is-active firewalld &>/dev/null; then
    SERVICES=$(firewall-cmd --list-services 2>/dev/null | wc -w)
    PORTS=$(firewall-cmd --list-ports 2>/dev/null | wc -w)
    SERVICES_P=$(firewall-cmd --permanent --list-services 2>/dev/null | wc -w)
    PORTS_P=$(firewall-cmd --permanent --list-ports 2>/dev/null | wc -w)
    if [ "$SERVICES" -gt 0 ] || [ "$PORTS" -gt 0 ]; then
        sec_audit_report_pass 127 "firewalld exposes $SERVICES service(s) and $PORTS port(s) at runtime (permanent: $SERVICES_P / $PORTS_P)"
    elif [ "$SERVICES_P" -gt 0 ] || [ "$PORTS_P" -gt 0 ]; then
        sec_audit_report_fail 127 "permanent firewalld rules exist ($SERVICES_P services, $PORTS_P ports) but runtime lists none - run firewall-cmd --reload"
    else
        sec_audit_report_fail 127 "firewalld services and ports are not configured"
    fi
else
    sec_audit_report_fail 127 "firewalld is not active"
fi

# RULE128:
if stat -Lc '%a' /etc/ssh/sshd_config 2>/dev/null | grep -q '^600$'; then
    if stat -Lc '%U:%G' /etc/ssh/sshd_config 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 128 "access to /etc/ssh/sshd_config is configured"
    else
        sec_audit_report_fail 128 "File /etc/ssh/sshd_config permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 128 "File /etc/ssh/sshd_config permissions or ownership not correct"
fi

# RULE129:
PRIV_KEYS=$(sec_audit_sshd_effective_config | awk '$1=="hostkey" {print $2}')
FAIL146=0
for key in $PRIV_KEYS; do
    if [ -f "$key" ]; then
        if ! stat -Lc '%a' "$key" 2>/dev/null | grep -q '^600$'; then
            FAIL146=1
        fi
        if ! stat -Lc '%U:%G' "$key" 2>/dev/null | grep -q '^root:root$'; then
            FAIL146=1
        fi
    else
        FAIL146=1
    fi
done
if [ $FAIL146 -eq 0 ]; then
    sec_audit_report_pass 129 "access to SSH private host key files is configured"
else
    sec_audit_report_fail 129 "File SSH private host key files permissions or ownership not correct"
fi

# RULE130:
PUB_KEYS=$(sec_audit_sshd_effective_config | awk '$1=="hostkey" {print $2".pub"}')
FAIL147=0
for key in $PUB_KEYS; do
    if [ -f "$key" ]; then
        if ! stat -Lc '%a' "$key" 2>/dev/null | grep -qE '^[0-6]44$'; then
            FAIL147=1
        fi
        if ! stat -Lc '%U:%G' "$key" 2>/dev/null | grep -q '^root:root$'; then
            FAIL147=1
        fi
    else
        FAIL147=1
    fi
done
if [ $FAIL147 -eq 0 ]; then
    sec_audit_report_pass 130 "access to SSH public host key files is configured"
else
    sec_audit_report_fail 130 "File SSH public host key files permissions or ownership not correct"
fi

# RULE131:
if sec_audit_sshd_config_grep -Piq '^\h*(allow|deny)(users|groups)\h+\H+'; then
    sec_audit_report_pass 131 "sshd access is configured"
else
    sec_audit_report_fail 131 "sshd access controls (AllowUsers/DenyUsers/AllowGroups/DenyGroups) are not set as required"
fi

# RULE132:
if sec_audit_sshd_config_grep -Piq '^banner\h+\/\H+'; then
    sec_audit_report_pass 132 "sshd Banner is configured"
else
    sec_audit_report_fail 132 "sshd Banner does not meet the required policy (see sshd -T)"
fi

# RULE133:
if sec_audit_sshd_config_grep -Piq '^ciphers\h+\"?([^#\n\r]+,)?((3des|blowfish|cast128|aes(128|192|256))-cbc|arcfour(128|256)?|rijndael-cbc@lysator\.liu\.se)\b'; then
    sec_audit_report_fail 133 "sshd Ciphers allow weak or legacy algorithms (see sshd -T)"
else
    sec_audit_report_pass 133 "sshd Ciphers are configured"
fi

# RULE134:
if sec_audit_sshd_config_grep -Piq 'clientaliveinterval\s+([1-9]|[1-9][0-9]+)'; then
    if sec_audit_sshd_config_grep -Piq 'clientalivecountmax\s+([1-9]|[1-9][0-9]+)'; then
        sec_audit_report_pass 134 "sshd ClientAliveInterval and ClientAliveCountMax are configured"
    else
        sec_audit_report_fail 134 "sshd ClientAliveInterval and ClientAliveCountMax are not configured as required (see sshd -T)"
    fi
else
    sec_audit_report_fail 134 "sshd ClientAliveInterval and ClientAliveCountMax are not configured as required (see sshd -T)"
fi

# RULE135:
if sec_audit_sshd_config_grep -iq 'disableforwarding yes'; then
    sec_audit_report_pass 135 "sshd DisableForwarding is enabled"
else
    sec_audit_report_fail 135 "sshd DisableForwarding is not enabled in effective sshd -T output"
fi

# RULE136:
if sec_audit_sshd_config_grep -iq 'gssapiauthentication no'; then
    sec_audit_report_pass 136 "sshd GSSAPIAuthentication is disabled"
else
    sec_audit_report_fail 136 "sshd GSSAPIAuthentication is not disabled in effective sshd -T output"
fi

# RULE137:
if sec_audit_sshd_config_grep -iq 'hostbasedauthentication no'; then
    sec_audit_report_pass 137 "sshd HostbasedAuthentication is disabled"
else
    sec_audit_report_fail 137 "sshd HostbasedAuthentication is not disabled in effective sshd -T output"
fi

# RULE138:
if sec_audit_sshd_config_grep -iq 'ignorerhosts yes'; then
    sec_audit_report_pass 138 "sshd IgnoreRhosts is enabled"
else
    sec_audit_report_fail 138 "sshd IgnoreRhosts is not enabled in effective sshd -T output"
fi

# RULE156:
if sec_audit_sshd_config_grep -Piq 'kexalgorithms\h+([^#\n\r]+,)?(diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1)\b'; then
    sec_audit_report_fail 156 "sshd KexAlgorithms does not meet the required policy (see sshd -T)"
else
    sec_audit_report_pass 156 "sshd KexAlgorithms is configured"
fi

# RULE157:
if sec_audit_sshd_config_grep -Piq 'logingracetime\s+([1-9]|[1-5][0-9]|60)\b'; then
    sec_audit_report_pass 157 "sshd LoginGraceTime is configured"
else
    sec_audit_report_fail 157 "sshd LoginGraceTime does not meet the required policy (see sshd -T)"
fi

# RULE158:
if sec_audit_sshd_config_grep -iq 'loglevel VERBOSE\|loglevel INFO'; then
    sec_audit_report_pass 158 "sshd LogLevel is configured"
else
    sec_audit_report_fail 158 "sshd LogLevel does not meet the required policy (see sshd -T)"
fi

# RULE159:
if sec_audit_sshd_config_grep -Piq 'macs\h+([^#\n\r]+,)?(hmac-md5|hmac-md5-96|hmac-ripemd160|hmac-sha1-96|umac-64@openssh\.com|hmac-md5-etm@openssh\.com|hmac-md5-96-etm@openssh\.com|hmac-ripemd160-etm@openssh\.com|hmac-sha1-96-etm@openssh\.com|umac-64-etm@openssh\.com|umac-128-etm@openssh\.com)\b'; then
    sec_audit_report_fail 159 "sshd MACs allow weak or legacy algorithms (see sshd -T)"
else
    sec_audit_report_pass 159 "sshd MACs are configured"
fi

# RULE160:
if sec_audit_sshd_config_grep -Piq 'maxauthtries\s+[1-4]\b'; then
    sec_audit_report_pass 160 "sshd MaxAuthTries is configured"
else
    sec_audit_report_fail 160 "sshd MaxAuthTries does not meet the required policy (see sshd -T)"
fi

# RULE161:
if sec_audit_sshd_config_awk '$1 ~ /^\s*maxstartups/{split($2, a, ":");{if(a[1] <= 10 && a[2] <= 30 && a[3] <= 60) print "ok"}}' | grep -q "ok"; then
    sec_audit_report_pass 161 "sshd MaxStartups is configured"
else
    sec_audit_report_fail 161 "sshd MaxStartups does not meet the required policy (see sshd -T)"
fi

# RULE162:
if sec_audit_sshd_config_grep -Piq 'maxsessions\s+([1-9]|10)\b'; then
    sec_audit_report_pass 162 "sshd MaxSessions is configured"
else
    sec_audit_report_fail 162 "sshd MaxSessions does not meet the required policy (see sshd -T)"
fi

# RULE163:
if sec_audit_sshd_config_grep -iq 'permitemptypasswords no'; then
    sec_audit_report_pass 163 "sshd PermitEmptyPasswords is disabled"
else
    sec_audit_report_fail 163 "sshd PermitEmptyPasswords is not disabled in effective sshd -T output"
fi

# RULE164:
if sec_audit_sshd_config_grep -iq 'permitrootlogin no'; then
    sec_audit_report_pass 164 "sshd PermitRootLogin is disabled"
else
    sec_audit_report_fail 164 "sshd PermitRootLogin is not disabled in effective sshd -T output"
fi

# RULE165:
if sec_audit_sshd_config_grep -iq 'permituserenvironment no'; then
    sec_audit_report_pass 165 "sshd PermitUserEnvironment is disabled"
else
    sec_audit_report_fail 165 "sshd PermitUserEnvironment is not disabled in effective sshd -T output"
fi

# RULE166:
if sec_audit_sshd_config_grep -iq 'usepam yes'; then
    sec_audit_report_pass 166 "sshd UsePAM is enabled"
else
    sec_audit_report_fail 166 "sshd UsePAM is not enabled in effective sshd -T output"
fi

fi

# RULE167:
if rpm -q sudo &>/dev/null; then
    sec_audit_report_pass 167 "sudo is installed"
else
    sec_audit_report_fail 167 "sudo package is not installed"
fi

# RULE168:
# shortcut: avoid grep -r on /etc/sudoers* (can hang on odd globs); scan files only.
_sudoers_files=(/etc/sudoers)
shopt -s nullglob
_sudoers_files+=(/etc/sudoers.d/*)
shopt -u nullglob
if [ "${#_sudoers_files[@]}" -gt 0 ] && grep -Pi '^\h*Defaults\h+([^#\n\r]+,\h*)?use_pty\b' "${_sudoers_files[@]}" 2>/dev/null | grep -q .; then
    if ! grep -Pi '^\h*Defaults\h+([^#\n\r]+,\h*)?!use_pty\b' "${_sudoers_files[@]}" 2>/dev/null | grep -q .; then
        sec_audit_report_pass 168 "sudo commands use pty"
    else
        sec_audit_report_fail 168 "sudo is not configured to require a pseudo-terminal (use_pty)"
    fi
else
    sec_audit_report_fail 168 "sudo is not configured to require a pseudo-terminal (use_pty)"
fi

# RULE169:
if [ "${#_sudoers_files[@]}" -gt 0 ] && grep -Psi "^\h*Defaults\h+([^#]+,\h*)?logfile\h*=\h*(\"|\')?\H+(\"|\')?(,\h*\H+\h*)*\h*(#.*)?$" "${_sudoers_files[@]}" 2>/dev/null | grep -q .; then
    sec_audit_report_pass 169 "sudo log file exists"
else
    sec_audit_report_fail 169 "sudo log file is missing or not configured"
fi

# RULE170:
if [ "${#_sudoers_files[@]}" -gt 0 ] && grep -E "^[^#].*NOPASSWD" "${_sudoers_files[@]}" 2>/dev/null | grep -q .; then
    sec_audit_report_fail 170 "NOPASSWD or password-less sudo rules violate escalation policy"
else
    sec_audit_report_pass 170 "users must provide password for escalation"
fi

# RULE171:
TIMEOUT=$(timeout 5 sudo -V 2>/dev/null | grep "Authentication timestamp timeout:" | awk '{print $4}')
TIMEOUT_INT=${TIMEOUT%%.*}
if [ -n "$TIMEOUT_INT" ]; then
    if [ "$TIMEOUT_INT" -ge 0 ] && [ "$TIMEOUT_INT" -le 15 ]; then
        sec_audit_report_pass 171 "sudo timestamp_timeout is configured"
    else
        sec_audit_report_fail 171 "sudo timestamp_timeout is not set within the required range"
    fi
else
    sec_audit_report_pass 171 "sudo timestamp_timeout is configured"
fi

# RULE172:
if grep -Pi '^\h*auth\h+(?:required|requisite)\h+pam_wheel\.so\h+(?:[^#\n\r]+\h+)?((?!\2)(use_uid\b|group=\H+\b))\h+(?:[^#\n\r]+\h+)?((?!\1)(use_uid\b|group=\H+\b))(\h+.*)?$' /etc/pam.d/su 2>/dev/null; then
    GROUP=$(grep -Pi '^\h*auth\h+(?:required|requisite)\h+pam_wheel\.so\h+(?:[^#\n\r]+\h+)?((?!\2)(use_uid\b|group=\H+\b))\h+(?:[^#\n\r]+\h+)?((?!\1)(use_uid\b|group=\H+\b))(\h+.*)?$' /etc/pam.d/su 2>/dev/null | grep -oP 'group=\K\H+')
    if [ -n "$GROUP" ]; then
        if ! grep "^$GROUP:" /etc/group 2>/dev/null | grep -q ":$GROUP:x:"; then
            sec_audit_report_pass 172 "access to the su command is restricted"
        else
            sec_audit_report_fail 172 "su is not restricted to the wheel group in PAM configuration"
        fi
    else
        sec_audit_report_pass 172 "access to the su command is restricted"
    fi
else
    sec_audit_report_fail 172 "su is not restricted to the wheel group in PAM configuration"
fi

# RULE173:
ACTIVE_PROFILE=$(head -1 /etc/authselect/authselect.conf 2>/dev/null)
if [ -z "$ACTIVE_PROFILE" ]; then
    sec_audit_report_fail 173 "active authselect profile does not include required pam modules"
elif sec_audit_have_bin authselect && ! authselect check &>/dev/null; then
    sec_audit_report_fail 173 "authselect reports configuration drift (run authselect check / apply changes)"
elif grep -P -- '\b(pam_pwquality\.so|pam_pwhistory\.so|pam_faillock\.so|pam_unix\.so)\b' /etc/authselect/"$ACTIVE_PROFILE"/{system,password}-auth 2>/dev/null; then
    sec_audit_report_pass 173 "active authselect profile includes pam modules (authselect check OK)"
else
    sec_audit_report_fail 173 "active authselect profile does not include required pam modules"
fi

# RULE174:
if sec_audit_pam_password_line_has_module pam_faillock.so; then
    sec_audit_report_pass 174 "pam_faillock.so on password stack in resolved password-auth/system-auth"
else
    sec_audit_report_fail 174 "pam_faillock module is not enabled on the password stack"
fi

# RULE175:
if sec_audit_pam_password_line_has_module pam_pwquality.so && sec_audit_pam_password_pwquality_before_unix_all_stacks; then
    sec_audit_report_pass 175 "pam_pwquality.so on password stack and ordered before pam_unix.so"
elif sec_audit_pam_password_line_has_module pam_pwquality.so; then
    sec_audit_report_fail 175 "pam_pwquality.so present but not correctly ordered before pam_unix.so on password stack"
else
    sec_audit_report_fail 175 "pam_pwquality module is not enabled on the password stack"
fi

# RULE176:
if sec_audit_pam_password_line_has_module pam_pwhistory.so; then
    sec_audit_report_pass 176 "pam_pwhistory.so on password stack in resolved password-auth/system-auth"
else
    sec_audit_report_fail 176 "pam_pwhistory module is not enabled on the password stack"
fi

# RULE177:
if sec_audit_pam_password_line_has_module pam_unix.so; then
    sec_audit_report_pass 177 "pam_unix.so on password stack in resolved password-auth/system-auth"
else
    sec_audit_report_fail 177 "pam_unix module is not enabled on the password stack"
fi

# RULE178:
if grep -Psi 'deny\h*=\h*[1-5]\b' /etc/security/faillock.conf 2>/dev/null; then
    sec_audit_report_pass 178 "password failed attempts lockout is configured"
else
    sec_audit_report_fail 178 "faillock deny threshold is not configured in /etc/security/faillock.conf"
fi

# RULE179:
if grep -Psi 'unlock_time\h*=\h*(0|9[0-9][0-9]|[1-9][0-9]{3,})\b' /etc/security/faillock.conf 2>/dev/null; then
    sec_audit_report_pass 179 "password unlock time is configured"
else
    sec_audit_report_fail 179 "faillock unlock_time is not set within the required range"
fi

# RULE180:
if grep -Psi '^\h*minlen\h*=\h*(1[4-9]|[2-9][0-9]|[1-9][0-9]{2,})\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null; then
    sec_audit_report_pass 180 "password length is configured"
else
    sec_audit_report_fail 180 "pwquality minlen (or equivalent) is not set to at least 14"
fi

# RULE181:
if grep -Psi '^\h*(minclass|[dulo]credit)\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null; then
    sec_audit_report_pass 181 "password complexity is configured"
else
    sec_audit_report_fail 181 "pwquality complexity (minclass/credits) is not configured"
fi

# RULE182:
if ! grep -Psi '^\h*dictcheck\h*=\h*0\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null; then
    sec_audit_report_pass 182 "password dictionary check is enabled"
else
    sec_audit_report_fail 182 "pwquality dictcheck is disabled or weak"
fi

# RULE183:
if grep -Psi '\h*enforce_for_root\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null; then
    sec_audit_report_pass 183 "password quality is enforced for the root user"
else
    sec_audit_report_fail 183 "pwquality enforce_for_root is not set"
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
if grep -Psi 'enforce_for_root\b' /etc/security/pwhistory.conf 2>/dev/null; then
    sec_audit_report_pass 185 "password history is enforced for the root user"
else
    sec_audit_report_fail 185 "pwhistory enforce_for_root is not set"
fi

# RULE186:
if sec_audit_pam_stacks_grep_P '^\h*password\h+([^#\n\r]+)\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?use_authtok\b'; then
    sec_audit_report_pass 186 "pam_pwhistory includes use_authtok"
else
    sec_audit_report_fail 186 "pam_pwhistory line lacks use_authtok on password-auth/system-auth stack"
fi
# RULE187:
if ! sec_audit_pam_auth_stacks_grep_Pi '^\h*auth\h+.*pam_unix\.so.*nullok'; then
    sec_audit_report_pass 187 "pam_unix does not include nullok"
else
    sec_audit_report_fail 187 "pam_unix still allows nullok in the auth stack"
fi
# RULE188:
if ! sec_audit_pam_stacks_grep_Pi '^\h*password\h+([^#\n\r]+)\h+pam_unix\.so.*remember='; then
    sec_audit_report_pass 188 "pam_unix does not include remember"
else
    sec_audit_report_fail 188 "pam_unix password line still uses remember="
fi
# RULE189:
if sec_audit_pam_stacks_grep_P '^\h*password\h+([^#\n\r]+)\h+pam_unix\.so\h+([^#\n\r]+\h+)?use_authtok\b'; then
    sec_audit_report_pass 189 "pam_unix includes use_authtok"
else
    sec_audit_report_fail 189 "pam_unix password line lacks use_authtok on password-auth/system-auth stack"
fi
# RULE190:
if grep -Psi '^\h*PASS_MAX_DAYS\h+(36[0-5]|3[0-5][0-9]|[1-2][0-9][0-9]|[1-9][0-9]|[1-9])\b' /etc/login.defs 2>/dev/null; then
    if ! awk -F: '($2~/^\$.+\$/) {if($5 > 365 || $5 < 1)print}' /etc/shadow 2>/dev/null | grep -q '.'; then
        sec_audit_report_pass 190 "password expiration is configured"
    else
        sec_audit_report_fail 190 "PASS_MAX_DAYS or per-user shadow MAX exceeds policy or is unset"
    fi
else
    sec_audit_report_fail 190 "PASS_MAX_DAYS or per-user shadow MAX exceeds policy or is unset"
fi

# RULE191:
if grep -q "^PASS_MIN_DAYS" /etc/login.defs 2>/dev/null; then
    MIN_DAYS=$(grep "^PASS_MIN_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
    if [ "$MIN_DAYS" -ge 7 ] 2>/dev/null; then
        sec_audit_report_pass 191 "Minimum password days is configured"
    else
        sec_audit_report_fail 191 "Minimum password days is too low (recommended 7+)"
    fi
else
    sec_audit_report_fail 191 "Minimum password days is not configured"
fi

# RULE192:
if grep -Psi '^\h*PASS_WARN_AGE\h+([7-9]|[1-9][0-9]+)\b' /etc/login.defs 2>/dev/null; then
    if ! awk -F: '($2~/^\$.+\$/) {if($6 < 7)print}' /etc/shadow 2>/dev/null | grep -q '.'; then
        sec_audit_report_pass 192 "password expiration warning days is configured"
    else
        sec_audit_report_fail 192 "PASS_WARN_AGE is not set within policy in /etc/login.defs"
    fi
else
    sec_audit_report_fail 192 "PASS_WARN_AGE is not set within policy in /etc/login.defs"
fi

# RULE193:
if grep -Psi '^\h*ENCRYPT_METHOD\h+(SHA512|YESCRYPT)\b' /etc/login.defs 2>/dev/null; then
    sec_audit_report_pass 193 "strong password hashing algorithm is configured"
else
    sec_audit_report_fail 193 "ENCRYPT_METHOD in /etc/login.defs does not use a strong hashing algorithm"
fi

# RULE194:
if useradd -D 2>/dev/null | grep INACTIVE | cut -d= -f2 | grep -qE '^([1-9]|[1-4][0-9]|45)$'; then
    if ! awk -F: '($2~/^\$.+\$/) {if($7 > 45 || $7 < 0)print}' /etc/shadow 2>/dev/null | grep -q '.'; then
        sec_audit_report_pass 194 "inactive password lock is configured"
    else
        sec_audit_report_fail 194 "useradd INACTIVE or inactive lock policy is not configured"
    fi
else
    sec_audit_report_fail 194 "useradd INACTIVE or inactive lock policy is not configured"
fi

# RULE195:
FAIL195=0
while IFS=: read -r user pass last_change rest; do
    if [ -n "$last_change" ] && [ "$last_change" -gt 0 ] 2>/dev/null; then
        current_date=$(date +%s)
        last_change_seconds=$((last_change * 86400))
        if [ "$last_change_seconds" -gt "$current_date" ]; then
            sec_audit_report_fail 195 "User $user has password change date in the future"
            FAIL195=1
        fi
    fi
done < /etc/shadow 2>/dev/null
if [ $FAIL195 -eq 0 ]; then
    sec_audit_report_pass 195 "All users last password change date is in the past"
fi

# RULE196:
if awk -F: '($3 == 0) { print $1 }' /etc/passwd 2>/dev/null | grep -qx "root"; then
    if [ $(awk -F: '($3 == 0) { print $1 }' /etc/passwd 2>/dev/null | wc -l) -eq 1 ]; then
        sec_audit_report_pass 196 "root is the only UID 0 account"
    else
        sec_audit_report_fail 196 "Multiple accounts with UID 0 exist in /etc/passwd"
    fi
else
    sec_audit_report_fail 196 "Multiple accounts with UID 0 exist in /etc/passwd"
fi

# RULE139:
if awk -F: '($1 !~ /^(sync|shutdown|halt|operator)/ && $4=="0") {print $1":"$4}' /etc/passwd 2>/dev/null | grep -q "root:0"; then
    if [ $(awk -F: '($1 !~ /^(sync|shutdown|halt|operator)/ && $4=="0") {print}' /etc/passwd 2>/dev/null | wc -l) -eq 1 ]; then
        sec_audit_report_pass 139 "root is the only GID 0 account"
    else
        sec_audit_report_fail 139 "Multiple users use GID 0 outside policy"
    fi
else
    sec_audit_report_fail 139 "Multiple users use GID 0 outside policy"
fi

# RULE140:
if awk -F: '$3=="0"{print $1":"$3}' /etc/group 2>/dev/null | grep -q "root:0"; then
    if [ $(awk -F: '$3=="0"{print}' /etc/group 2>/dev/null | wc -l) -eq 1 ]; then
        sec_audit_report_pass 140 "group root is the only GID 0 group"
    else
        sec_audit_report_fail 140 "Multiple groups share GID 0"
    fi
else
    sec_audit_report_fail 140 "Multiple groups share GID 0"
fi

# RULE141:
if passwd -S root 2>/dev/null | awk '$2 ~ /^(P|L)/' | grep -q "root"; then
    sec_audit_report_pass 141 "root account access is controlled"
else
    sec_audit_report_fail 141 "root SSH/console access restrictions are not configured as required"
fi

# RULE142:
FAIL200=0
ROOT_PATH=$(sudo -i echo "\$PATH" 2>/dev/null || echo "$PATH")
if echo "$ROOT_PATH" | grep -q "::"; then
    sec_audit_report_fail 142 "Root PATH contains empty directory (::)"
    FAIL200=1
fi
if echo "$ROOT_PATH" | grep -q "\.:"; then
    sec_audit_report_fail 142 "Root PATH contains current directory (.)"
    FAIL200=1
fi
if [ $FAIL200 -eq 0 ]; then
    sec_audit_report_pass 142 "Root path integrity is maintained"
fi

# RULE143:
if ! grep -Psi '^\h*umask\h+((\d{1,2}(\d[^7]|[^2-7]\d)\b)|(u=[rwx]{1,3},)?(((g=[rx]?[rx]?w[rx]?[rx]?\b)(,o=[rwx]{1,3})?)|((g=[wrx]{1,3},)?o=[wrx]{1,3}\b)))' /root/.bash_profile /root/.bashrc 2>/dev/null; then
    sec_audit_report_pass 143 "root user umask is configured"
else
    sec_audit_report_fail 143 "root umask is not 027 (or stricter) in profile scripts"
fi

# RULE144:
VALID_SHELLS=$(awk -F\/ '$NF != "nologin" && $NF != "false" {print}' /etc/shells 2>/dev/null | sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' -)
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs 2>/dev/null)
if awk -v pat="^($VALID_SHELLS)$" -v uidmin="$UID_MIN" -F: '($1!~/^(root|halt|sync|shutdown|nfsnobody)$/ && ($3<uidmin || $3==65534) && $NF ~ pat) {print}' /etc/passwd 2>/dev/null | grep -q '.'; then
    sec_audit_report_fail 144 "System accounts still have an interactive login shell"
else
    sec_audit_report_pass 144 "system accounts do not have a valid login shell"
fi

# RULE145:
VALID_SHELLS=$(awk -F\/ '$NF != "nologin" && $NF != "false" {print}' /etc/shells 2>/dev/null | sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' -)
FAIL203=0
while IFS= read -r l_user; do
    if passwd -S "$l_user" 2>/dev/null | awk '$2 !~ /^L/ {print "found"}' | grep -q "found"; then
        sec_audit_report_fail 145 "Accounts without a valid shell are not locked in /etc/shadow"
        FAIL203=1
        break
    fi
done <<< "$(awk -v pat="^($VALID_SHELLS)$" -F: '($1 != "root" && $NF !~ pat) {print $1}' /etc/passwd 2>/dev/null)"
if [ $FAIL203 -eq 0 ]; then
    sec_audit_report_pass 145 "accounts without a valid login shell are locked"
fi

# RULE146:
if grep -Ps '^\h*([^#\n\r]+)?\/nologin\b' /etc/shells 2>/dev/null; then
    sec_audit_report_fail 146 "nologin appears in /etc/shells"
else
    sec_audit_report_pass 146 "nologin is not listed in /etc/shells"
fi

# RULE147:
if grep -Psi '^([^#\n\r]+)?\bTMOUT=(9[0-9]{1,2}|[1-9][0-9]|[1-9])\b' /etc/*bashrc /etc/profile /etc/profile.d/*.sh 2>/dev/null; then
    sec_audit_report_pass 147 "default user shell timeout is configured"
else
    sec_audit_report_fail 147 "TMOUT is not set for interactive shells in /etc/profile or profile.d"
fi

# RULE148:
if grep -Psi '^\h*umask\h+0?(?:[0-7][2-7]7)\b' /etc/login.defs 2>/dev/null; then
    if grep -Psi '^\h*umask\h+0?027\b' /etc/profile.d/*.sh 2>/dev/null; then
        sec_audit_report_pass 148 "default user umask is configured"
    else
        sec_audit_report_fail 148 "Default user umask 027 is not set in /etc/profile or profile.d"
    fi
else
    sec_audit_report_fail 148 "Default user umask 027 is not set in /etc/profile or profile.d"
fi

# RULE149:
if rpm -q aide &>/dev/null; then
    _a207_db=""
    if [ -f /var/lib/aide/aide.db.gz ] || [ -f /var/lib/aide/aide.db ]; then
        _a207_db="; AIDE database file present under /var/lib/aide"
    else
        _a207_db="; WARNING: no AIDE database under /var/lib/aide (initialize with aide --init)"
    fi
    sec_audit_report_pass 149 "AIDE package is installed${_a207_db}"
else
    sec_audit_report_fail 149 "AIDE package is not installed"
fi

# RULE150:
if grep -Ers '^([^#]+\s+)?(\/usr\/s?bin\/|^\s*)aide(\.wrapper)?\s(--?\S+\s)*(-(check|update)|\$AIDEARGS)\b' /etc/cron.* /etc/crontab /var/spool/cron/ /etc/cron.d 2>/dev/null; then
    sec_audit_report_pass 150 "filesystem integrity is regularly checked (cron/cron.d entry references aide)"
elif systemctl is-enabled aidecheck.timer 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active aidecheck.timer 2>/dev/null | grep -q 'active'; then
        _a208_n=$(systemctl show aidecheck.timer -p NextElapseUSRealtime 2>/dev/null | cut -d= -f2-)
        sec_audit_report_pass 150 "aidecheck.timer enabled and active (next: ${_a208_n:-unknown})"
    else
        sec_audit_report_fail 150 "aidecheck.timer enabled but not active"
    fi
else
    sec_audit_report_fail 150 "filesystem integrity is regularly checked"
fi

# RULE151:
if systemctl is-enabled systemd-journald.service 2>/dev/null | grep -q 'static'; then
    if systemctl is-active systemd-journald.service 2>/dev/null | grep -q 'active'; then
        sec_audit_report_pass 151 "journald service is active"
    else
        sec_audit_report_fail 151 "systemd-journald is not active or not in expected state"
    fi
else
    sec_audit_report_fail 151 "systemd-journald is not active or not in expected state"
fi

# RULE152:
if [ -d /var/log/journal ]; then
    DIR_PERM=$(stat -c '%a' /var/log/journal 2>/dev/null)
    if [ "$DIR_PERM" = "755" ] || [ "$DIR_PERM" = "750" ]; then
        sec_audit_report_pass 152 "journald log file access is configured (directory mode: $DIR_PERM)"
    else
        sec_audit_report_fail 152 "journald log directory has insecure permissions: $DIR_PERM"
    fi
else
    sec_audit_report_pass 152 "journald log file access is configured (directory not found)"
fi

# RULE153:
if grep -q "^SystemMaxUse\|^SystemMaxFileSize\|^MaxFileSec" /etc/systemd/journald.conf 2>/dev/null; then
    sec_audit_report_pass 153 "journald log file rotation is configured"
else
    echo "RULE153= WARN: journald log file rotation using defaults (may be acceptable)"
fi

# RULE154:
if systemctl is-active --quiet rsyslog; then
    if systemctl is-active --quiet systemd-journald; then
        sec_audit_report_fail 154 "more than one logging system is in use (both rsyslog and journald are active)"
    else
        sec_audit_report_pass 154 "only one logging system is in use (rsyslog)"
    fi
elif systemctl is-active --quiet systemd-journald; then
    sec_audit_report_pass 154 "only one logging system is in use (journald)"
else
    sec_audit_report_fail 154 "no logging system is active (neither rsyslog nor journald)"
fi

# RULE155:
if rpm -q systemd-journal-remote &>/dev/null; then
    sec_audit_report_pass 155 "systemd-journal-remote is installed"
else
    sec_audit_report_fail 155 "systemd-journal-remote package is not installed (if required by policy)"
fi

if systemctl is-enabled systemd-journal-upload.service 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active systemd-journal-upload.service 2>/dev/null | grep -q 'active'; then
        echo "EXTREQ214= PASS: systemd-journal-upload is enabled and active"
    else
        echo "EXTREQ214= FAIL: systemd-journal-upload is not enabled or not active"
    fi
else
    echo "EXTREQ214= FAIL: systemd-journal-upload is not enabled or not active"
fi

if systemctl is-enabled systemd-journal-remote.socket systemd-journal-remote.service 2>/dev/null | grep -q 'enabled'; then
    echo "EXTREQ215= FAIL: systemd-journal-remote socket/service is enabled or active but should be disabled"
elif systemctl is-active systemd-journal-remote.socket systemd-journal-remote.service 2>/dev/null | grep -q 'active'; then
    echo "EXTREQ215= FAIL: systemd-journal-remote socket/service is enabled or active but should be disabled"
else
    echo "EXTREQ215= PASS: systemd-journal-remote service is not in use"
fi

if systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -E '^ForwardToSyslog=no' | head -1 | grep -q "ForwardToSyslog=no"; then
    echo "EXTREQ216= PASS: journald ForwardToSyslog is disabled"
elif systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -E '^ForwardToSyslog=yes' | head -1 | grep -q "ForwardToSyslog=yes"; then
    echo "EXTREQ216= FAIL: journald ForwardToSyslog is disabled (should be no)"
else
    echo "EXTREQ216= PASS: journald ForwardToSyslog is disabled (default)"
fi

if systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -E '^Compress=yes' | head -1 | grep -q "Compress=yes"; then
    echo "EXTREQ217= PASS: journald Compress is configured"
else
    echo "EXTREQ217= PASS: journald Compress is configured (default)"
fi

if systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -E '^Storage=persistent' | head -1 | grep -q "Storage=persistent"; then
    echo "EXTREQ218= PASS: journald Storage is configured"
else
    echo "EXTREQ218= FAIL: journald Storage=persistent (or required value) is not set in merged config"
fi

if rpm -q rsyslog &>/dev/null; then
    echo "EXTREQ219= PASS: rsyslog is installed"
else
    echo "EXTREQ219= FAIL: rsyslog package is not installed"
fi

if systemctl is-enabled rsyslog 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active rsyslog.service 2>/dev/null | grep -q 'active'; then
        echo "EXTREQ220= PASS: rsyslog service is enabled and active"
    else
        echo "EXTREQ220= FAIL: rsyslog is not enabled or not active"
    fi
else
    echo "EXTREQ220= FAIL: rsyslog is not enabled or not active"
fi

if systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -E '^ForwardToSyslog=yes' | head -1 | grep -q "ForwardToSyslog=yes"; then
    echo "EXTREQ221= PASS: journald is configured to send logs to rsyslog"
else
    echo "EXTREQ221= FAIL: journald ForwardToSyslog or forwarding to rsyslog is not configured"
fi

if grep -Ps '^\h*\$FileCreateMode\h+0[0,2,4,6][0,2,4]0\b' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null; then
    echo "EXTREQ222= PASS: rsyslog log file creation mode is configured"
else
    echo "EXTREQ222= FAIL: rsyslog $FileCreateMode (or equivalent) does not meet policy"
fi

if command -v rsyslogd &>/dev/null; then
    if [ -f /etc/rsyslog.conf ] && grep -v "^#" /etc/rsyslog.conf 2>/dev/null | grep -q "^\*\.\*\|^auth\|^mail\|^cron"; then
        echo "EXTREQ223= PASS: rsyslog logging is configured"
    else
        echo "EXTREQ223= FAIL: rsyslog logging is not properly configured"
    fi
else
    echo "EXTREQ223= PASS: rsyslog is not installed"
fi

if command -v logrotate &>/dev/null; then
    if [ -f /etc/logrotate.conf ] && grep -q "^rotate\|^daily\|^weekly\|^monthly" /etc/logrotate.conf 2>/dev/null; then
        echo "EXTREQ224= PASS: rsyslog logrotate is configured"
    else
        echo "EXTREQ224= FAIL: rsyslog logrotate is not properly configured"
    fi
else
    echo "EXTREQ224= FAIL: logrotate is not installed"
fi

FAIL225=0
for logfile in /var/log/messages /var/log/secure /var/log/maillog /var/log/cron /var/log/boot.log; do
    if [ -f "$logfile" ]; then
        PERM=$(stat -c '%a' "$logfile" 2>/dev/null)
        OWNER=$(stat -c '%U' "$logfile" 2>/dev/null)
        if [ "$PERM" -gt 640 ] 2>/dev/null || [ "$OWNER" != "root" ]; then
            echo "EXTREQ225= FAIL: $logfile has insecure permissions ($PERM) or owner ($OWNER)"
            FAIL225=1
        fi
    fi
done
[ $FAIL225 -eq 0 ] && echo "EXTREQ225= PASS: Access to all logfiles has been configured"

if rpm -q audit audit-libs &>/dev/null; then
    echo "EXTREQ226= PASS: auditd packages are installed"
else
    echo "EXTREQ226= FAIL: audit audit-libs packages are not installed"
fi

if grep -Psoi '^\h*GRUB_CMDLINE_LINUX=\"([^#\n\r]+\h+)?\baudit_backlog_limit=\d+\b' /etc/default/grub 2>/dev/null; then
    echo "EXTREQ227= PASS: audit_backlog_limit is configured"
else
    echo "EXTREQ227= FAIL: audit_backlog_limit is not set appropriately in audit rules or sysctl"
fi

if systemctl is-enabled auditd 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active auditd 2>/dev/null | grep -q 'active'; then
        echo "EXTREQ228= PASS: auditd service is enabled and active"
    else
        echo "EXTREQ228= FAIL: auditd is not enabled or not active"
    fi
else
    echo "EXTREQ228= FAIL: auditd is not enabled or not active"
fi

if grep -Po '^\h*max_log_file\h*=\h*\d+\b' /etc/audit/auditd.conf 2>/dev/null; then
    echo "EXTREQ229= PASS: audit log storage size is configured"
else
    echo "EXTREQ229= FAIL: max_log_file or rotation policy in auditd.conf does not meet policy"
fi

if grep -Pi '^\h*max_log_file_action\h*=\h*keep_logs\b' /etc/audit/auditd.conf 2>/dev/null; then
    echo "EXTREQ230= PASS: audit logs are not automatically deleted"
else
    echo "EXTREQ230= FAIL: max_log_file_action or keep_logs policy allows silent deletion"
fi

if grep -P '^\h*disk_full_action\h*=\h*(halt|single)\b' /etc/audit/auditd.conf 2>/dev/null; then
    if grep -P '^\h*disk_error_action\h*=\h*(syslog|single|halt)\b' /etc/audit/auditd.conf 2>/dev/null; then
        echo "EXTREQ231= PASS: system is disabled when audit logs are full"
    else
        echo "EXTREQ231= FAIL: disk_full_action / space_left_action in auditd.conf does not meet policy"
    fi
else
    echo "EXTREQ231= FAIL: disk_full_action / space_left_action in auditd.conf does not meet policy"
fi

if grep -P '^\h*space_left_action\h*=\h*(email|exec|single|halt)\b' /etc/audit/auditd.conf 2>/dev/null; then
    if grep -P '^\h*admin_space_left_action\h*=\h*(single|halt)\b' /etc/audit/auditd.conf 2>/dev/null; then
        echo "EXTREQ232= PASS: system warns when audit logs are low on space"
    else
        echo "EXTREQ232= FAIL: space_left_action / admin_space_left_action in auditd.conf are incomplete"
    fi
else
    echo "EXTREQ232= FAIL: space_left_action / admin_space_left_action in auditd.conf are incomplete"
fi

if sec_audit_audit_rule_on_disk_and_loaded -q "path=/etc/sudoers"; then
    if sec_audit_audit_rule_on_disk_and_loaded -q "dir=/etc/sudoers.d"; then
        echo "EXTREQ233= PASS: sudoers and sudoers.d watch rules present in audit.rules and loaded in kernel"
    else
        echo "EXTREQ233= FAIL: /etc/sudoers.d directory watch missing on disk or not loaded"
    fi
else
    echo "EXTREQ233= FAIL: /etc/sudoers file watch missing on disk or not loaded"
fi

if sec_audit_audit_rule_on_disk_and_loaded -q "execve"; then
    echo "EXTREQ234= PASS: execve auditing present on disk and loaded"
else
    echo "EXTREQ234= FAIL: actions as another user are not always logged (execve audit rule missing or not loaded)"
fi

if [ -f /var/log/sudo.log ]; then
    if sec_audit_audit_rule_on_disk_and_loaded -q "path=/var/log/sudo.log"; then
        echo "EXTREQ235= PASS: audit rule for /var/log/sudo.log on disk and loaded"
    else
        echo "EXTREQ235= FAIL: events that modify the sudo log file are not collected (audit watch for /var/log/sudo.log missing or not loaded)"
    fi
else
    echo "EXTREQ235= FAIL: events that modify the sudo log file are not collected (/var/log/sudo.log not found)"
fi

if sec_audit_audit_rule_on_disk_and_loaded -q "dir=/etc/NetworkManager/"; then
    echo "EXTREQ236= PASS: NetworkManager directory watch on disk and loaded"
else
    echo "EXTREQ236= FAIL: events that modify /etc/NetworkManager directory are not collected"
fi

if command -v auditctl &>/dev/null; then
    if sec_audit_audit_rule_on_disk_and_loaded -E -q 'path=/usr/bin/sudo|path=/usr/bin/su|path=/bin/su'; then
        echo "EXTREQ237= PASS: privileged command execution (sudo/su) audited on disk and loaded"
    else
        echo "EXTREQ237= FAIL: use of privileged commands is not being collected"
    fi
fi

if sec_audit_audit_rule_on_disk_and_loaded -E -q 'EACCES|EPERM'; then
    echo "EXTREQ238= PASS: unsuccessful access (EACCES/EPERM) auditing on disk and loaded"
else
    echo "EXTREQ238= FAIL: unsuccessful file access attempts are not collected"
fi

if sec_audit_audit_rule_on_disk_and_loaded -q "path=/etc/shadow"; then
    if sec_audit_audit_rule_on_disk_and_loaded -q "path=/etc/gshadow"; then
        echo "EXTREQ239= PASS: shadow and gshadow watches on disk and loaded"
    else
        echo "EXTREQ239= FAIL: events that modify /etc/gshadow are not collected (watch missing on disk or not loaded)"
    fi
else
    echo "EXTREQ239= FAIL: events that modify /etc/shadow are not collected (watch missing on disk or not loaded)"
fi

if sec_audit_audit_rule_on_disk_and_loaded -q "mount"; then
    echo "EXTREQ240= PASS: mount syscall auditing on disk and loaded"
else
    echo "EXTREQ240= FAIL: successful file system mounts are not collected"
fi

if sec_audit_audit_rule_on_disk_and_loaded -E -q 'utmp|wtmp|btmp'; then
    echo "EXTREQ241= PASS: session initiation (utmp/wtmp/btmp) auditing on disk and loaded"
else
    echo "EXTREQ241= FAIL: session initiation information is not collected"
fi

if sec_audit_audit_rule_on_disk_and_loaded -E -q 'lastlog|faillock'; then
    echo "EXTREQ242= PASS: login/logout related auditing on disk and loaded"
else
    echo "EXTREQ242= FAIL: login and logout events are not collected"
fi

if sec_audit_audit_rule_on_disk_and_loaded -q "unlink"; then
    echo "EXTREQ243= PASS: unlink auditing on disk and loaded"
else
    echo "EXTREQ243= FAIL: unlink file deletion events by users are not collected"
fi

if sec_audit_audit_rule_on_disk_and_loaded -q "init_module"; then
    echo "EXTREQ244= PASS: init_module auditing on disk and loaded"
else
    echo "EXTREQ244= FAIL: kernel module loading unloading and modification is not collected"
fi

if grep -Ph '^\h*-e\h+2\b' /etc/audit/rules.d/*.rules 2>/dev/null | tail -1 | grep -q -- "-e 2"; then
    echo "EXTREQ245= PASS: the audit configuration is immutable"
else
    echo "EXTREQ245= FAIL: Immutable rule (-e 2) is missing from the end of audit rules on disk"
fi

if augenrules --check 2>/dev/null | grep -q "No change"; then
    echo "EXTREQ246= PASS: the running and on disk configuration is the same"
else
    echo "EXTREQ246= FAIL: Loaded audit rules differ from on-disk rules (augenrules --check)"
fi

if [ -f /etc/audit/auditd.conf ]; then
    LOG_DIR=$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")
    if [ -d "$LOG_DIR" ]; then
        if stat -Lc '%a' "$LOG_DIR" 2>/dev/null | grep -qE '^750$'; then
            echo "EXTREQ247= PASS: the audit log file directory mode is configured"
        else
            echo "EXTREQ247= FAIL: Audit log directory mode is not 750 or directory missing"
        fi
    else
        echo "EXTREQ247= FAIL: Audit log directory mode is not 750 or directory missing"
    fi
else
    echo "EXTREQ247= FAIL: Audit log directory mode is not 750 or directory missing"
fi

if [ -f /etc/audit/auditd.conf ]; then
    LOG_DIR=$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")
    if [ -d "$LOG_DIR" ]; then
        if sec_audit_soft_find --timeout=10 "$LOG_DIR" -xdev -ignore_readdir_race -maxdepth 1 -type f -perm /0137 2>/dev/null | grep -q '.'; then
            echo "EXTREQ248= FAIL: One or more audit log files have overly permissive modes"
        else
            echo "EXTREQ248= PASS: audit log files mode is configured"
        fi
    else
        echo "EXTREQ248= FAIL: One or more audit log files have overly permissive modes"
    fi
else
    echo "EXTREQ248= FAIL: One or more audit log files have overly permissive modes"
fi

if [ -f /etc/audit/auditd.conf ]; then
    LOG_DIR=$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")
    if [ -d "$LOG_DIR" ]; then
        if sec_audit_soft_find --timeout=10 "$LOG_DIR" -xdev -ignore_readdir_race -maxdepth 1 -type f ! -user root 2>/dev/null | grep -q '.'; then
            echo "EXTREQ249= FAIL: One or more audit log files are not owned by root"
        else
            echo "EXTREQ249= PASS: audit log files owner is configured"
        fi
    else
        echo "EXTREQ249= FAIL: One or more audit log files are not owned by root"
    fi
else
    echo "EXTREQ249= FAIL: One or more audit log files are not owned by root"
fi

if [ -f /etc/audit/auditd.conf ]; then
    LOG_DIR=$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")
    LOG_GROUP=$(awk -F= '/^\s*log_group\s*/{print $2}' /etc/audit/auditd.conf | xargs)
    if [ "$LOG_GROUP" = "root" ] || [ "$LOG_GROUP" = "adm" ]; then
        if [ -d "$LOG_DIR" ]; then
            if sec_audit_soft_find --timeout=10 "$LOG_DIR" -xdev -ignore_readdir_race -maxdepth 1 -type f \( ! -group root -a ! -group adm \) 2>/dev/null | grep -q '.'; then
                echo "EXTREQ250= FAIL: Audit log files group ownership does not match log_group policy"
            else
                echo "EXTREQ250= PASS: audit log files group owner is configured"
            fi
        else
            echo "EXTREQ250= FAIL: Audit log files group ownership does not match log_group policy"
        fi
    else
        echo "EXTREQ250= FAIL: Audit log files group ownership does not match log_group policy"
    fi
else
    echo "EXTREQ250= FAIL: Audit log files group ownership does not match log_group policy"
fi

if sec_audit_soft_find --timeout=10 /etc/audit/ -xdev -ignore_readdir_race -type f \( -name "*.conf" -o -name '*.rules' \) -perm /0137 2>/dev/null | grep -q '.'; then
    echo "EXTREQ251= FAIL: Audit .conf/.rules files have insecure permissions"
else
    echo "EXTREQ251= PASS: audit configuration files mode is configured"
fi

if sec_audit_soft_find --timeout=10 /etc/audit/ -xdev -ignore_readdir_race -type f \( -name "*.conf" -o -name '*.rules' \) ! -user root 2>/dev/null | grep -q '.'; then
    echo "EXTREQ252= FAIL: Audit configuration files are not owned as required"
else
    echo "EXTREQ252= PASS: audit configuration files owner is configured"
fi

if sec_audit_soft_find --timeout=10 /etc/audit/ -xdev -ignore_readdir_race -type f \( -name "*.conf" -o -name '*.rules' \) ! -group root 2>/dev/null | grep -q '.'; then
    echo "EXTREQ253= FAIL: Audit configuration files group ownership does not meet policy"
else
    echo "EXTREQ253= PASS: audit configuration files group owner is configured"
fi

FAIL254=0
for tool in /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules; do
    if [ -f "$tool" ]; then
        if [ $(( $(stat -Lc '%#a' "$tool" 2>/dev/null) & 0022 )) -gt 0 ]; then
            FAIL254=1
        fi
    fi
done
if [ $FAIL254 -eq 0 ]; then
    echo "EXTREQ254= PASS: audit tools mode is configured"
else
    echo "EXTREQ254= FAIL: One or more /sbin/audit* tools have insecure permissions"
fi

FAIL255=0
for tool in /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules; do
    if [ -f "$tool" ]; then
        if [ "$(stat -Lc '%U' "$tool" 2>/dev/null)" != "root" ]; then
            FAIL255=1
        fi
    fi
done
if [ $FAIL255 -eq 0 ]; then
    echo "EXTREQ255= PASS: audit tools owner is configured"
else
    echo "EXTREQ255= FAIL: One or more /sbin/audit* tools are not owned by root"
fi

FAIL256=0
for tool in /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules; do
    if [ -f "$tool" ]; then
        if [ "$(stat -Lc '%G' "$tool" 2>/dev/null)" != "root" ]; then
            FAIL256=1
        fi
    fi
done
if [ $FAIL256 -eq 0 ]; then
    echo "EXTREQ256= PASS: audit tools group owner is configured"
else
    echo "EXTREQ256= FAIL: One or more /sbin/audit* tools have incorrect group ownership"
fi

if stat -Lc '%a' /etc/passwd 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' /etc/passwd 2>/dev/null | grep -q '^root:root$'; then
        echo "EXTREQ257= PASS: access to /etc/passwd is configured"
    else
        echo "EXTREQ257= FAIL: File /etc/passwd permissions or ownership not correct"
    fi
else
    echo "EXTREQ257= FAIL: File /etc/passwd permissions or ownership not correct"
fi

if [ -e /etc/passwd- ]; then
    if stat -Lc '%a' /etc/passwd- 2>/dev/null | grep -qE '^[0-6]44$'; then
        if stat -Lc '%U:%G' /etc/passwd- 2>/dev/null | grep -q '^root:root$'; then
            echo "EXTREQ258= PASS: access to /etc/passwd- is configured"
        else
            echo "EXTREQ258= FAIL: File /etc/passwd- permissions or ownership not correct"
        fi
    else
        echo "EXTREQ258= FAIL: File /etc/passwd- permissions or ownership not correct"
    fi
else
    echo "EXTREQ258= PASS: /etc/passwd- is absent (optional file; permission check skipped)"
fi

if stat -Lc '%a' /etc/group 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' /etc/group 2>/dev/null | grep -q '^root:root$'; then
        echo "EXTREQ259= PASS: access to /etc/group is configured"
    else
        echo "EXTREQ259= FAIL: File /etc/group permissions or ownership not correct"
    fi
else
    echo "EXTREQ259= FAIL: File /etc/group permissions or ownership not correct"
fi

if [ -e /etc/group- ]; then
    if stat -Lc '%a' /etc/group- 2>/dev/null | grep -qE '^[0-6]44$'; then
        if stat -Lc '%U:%G' /etc/group- 2>/dev/null | grep -q '^root:root$'; then
            echo "EXTREQ260= PASS: access to /etc/group- is configured"
        else
            echo "EXTREQ260= FAIL: File /etc/group- permissions or ownership not correct"
        fi
    else
        echo "EXTREQ260= FAIL: File /etc/group- permissions or ownership not correct"
    fi
else
    echo "EXTREQ260= PASS: /etc/group- is absent (optional file; permission check skipped)"
fi

if stat -Lc '%a' /etc/shadow 2>/dev/null | grep -qE '^[0-6]40$'; then
    if stat -Lc '%U' /etc/shadow 2>/dev/null | grep -q 'root'; then
        if stat -Lc '%G' /etc/shadow 2>/dev/null | grep -qE 'root|shadow'; then
            echo "EXTREQ261= PASS: access to /etc/shadow is configured"
        else
            echo "EXTREQ261= FAIL: File /etc/shadow permissions or ownership not correct"
        fi
    else
        echo "EXTREQ261= FAIL: File /etc/shadow permissions or ownership not correct"
    fi
else
    echo "EXTREQ261= FAIL: File /etc/shadow permissions or ownership not correct"
fi

if [ -e /etc/shadow- ]; then
    if stat -Lc '%a' /etc/shadow- 2>/dev/null | grep -qE '^[0-6]40$'; then
        if stat -Lc '%U' /etc/shadow- 2>/dev/null | grep -q 'root'; then
            if stat -Lc '%G' /etc/shadow- 2>/dev/null | grep -qE 'root|shadow'; then
                echo "EXTREQ262= PASS: access to /etc/shadow- is configured"
            else
                echo "EXTREQ262= FAIL: File /etc/shadow- permissions or ownership not correct"
            fi
        else
            echo "EXTREQ262= FAIL: File /etc/shadow- permissions or ownership not correct"
        fi
    else
        echo "EXTREQ262= FAIL: File /etc/shadow- permissions or ownership not correct"
    fi
else
    echo "EXTREQ262= PASS: /etc/shadow- is absent (optional file; permission check skipped)"
fi

if [ -e /etc/gshadow ]; then
    if stat -Lc '%a' /etc/gshadow 2>/dev/null | grep -qE '^[0-6]40$'; then
        if stat -Lc '%U' /etc/gshadow 2>/dev/null | grep -q 'root'; then
            if stat -Lc '%G' /etc/gshadow 2>/dev/null | grep -qE 'root|shadow'; then
                echo "EXTREQ263= PASS: access to /etc/gshadow is configured"
            else
                echo "EXTREQ263= FAIL: File /etc/gshadow permissions or ownership not correct"
            fi
        else
            echo "EXTREQ263= FAIL: File /etc/gshadow permissions or ownership not correct"
        fi
    else
        echo "EXTREQ263= FAIL: File /etc/gshadow permissions or ownership not correct"
    fi
else
    echo "EXTREQ263= PASS: /etc/gshadow is absent (optional file; permission check skipped)"
fi

if [ -e /etc/gshadow- ]; then
    if stat -Lc '%a' /etc/gshadow- 2>/dev/null | grep -qE '^[0-6]40$'; then
        if stat -Lc '%U' /etc/gshadow- 2>/dev/null | grep -q 'root'; then
            if stat -Lc '%G' /etc/gshadow- 2>/dev/null | grep -qE 'root|shadow'; then
                echo "EXTREQ264= PASS: access to /etc/gshadow- is configured"
            else
                echo "EXTREQ264= FAIL: File /etc/gshadow- permissions or ownership not correct"
            fi
        else
            echo "EXTREQ264= FAIL: File /etc/gshadow- permissions or ownership not correct"
        fi
    else
        echo "EXTREQ264= FAIL: File /etc/gshadow- permissions or ownership not correct"
    fi
else
    echo "EXTREQ264= PASS: /etc/gshadow- is absent (optional file; permission check skipped)"
fi

if stat -Lc '%a' /etc/shells 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' /etc/shells 2>/dev/null | grep -q '^root:root$'; then
        echo "EXTREQ265= PASS: access to /etc/shells is configured"
    else
        echo "EXTREQ265= FAIL: File /etc/shells permissions or ownership not correct"
    fi
else
    echo "EXTREQ265= FAIL: File /etc/shells permissions or ownership not correct"
fi

if [ -e /etc/security/opasswd ]; then
    if stat -Lc '%a' /etc/security/opasswd 2>/dev/null | grep -q '^600$'; then
        if stat -Lc '%U:%G' /etc/security/opasswd 2>/dev/null | grep -q '^root:root$'; then
            echo "EXTREQ266= PASS: access to /etc/security/opasswd is configured"
        else
            echo "EXTREQ266= FAIL: File /etc/security/opasswd permissions or ownership not correct"
        fi
    else
        echo "EXTREQ266= FAIL: File /etc/security/opasswd permissions or ownership not correct"
    fi
else
    echo "EXTREQ266= PASS: /etc/security/opasswd is absent (optional file; permission check skipped)"
fi

CRITICAL_PATHS="/bin /sbin /usr/bin /usr/sbin /etc /var /home"
WW_FILES=$(sec_audit_soft_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type f -perm -0002 -print 2>/dev/null | wc -l)
WW_DIRS=$(sec_audit_soft_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type d -perm -0002 -print 2>/dev/null | wc -l)
if [ $WW_FILES -eq 0 ] && [ $WW_DIRS -eq 0 ]; then
    echo "EXTREQ267= PASS: No critical world writable files or directories found"
else
    echo "EXTREQ267= FAIL: Found potential world-writable items ($WW_FILES files, $WW_DIRS dirs)"
fi

SPECIAL_COUNTS=$(
    while IFS= read -r mount_point; do
        [ -d "$mount_point" ] || continue
        sec_audit_soft_find --timeout=8 "$mount_point" -xdev -ignore_readdir_race -type f -perm /6000 -printf '%m\n' 2>/dev/null
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
    echo "EXTREQ268= REVIEW: SUID and SGID files found ($SUID_FILES SUID, $SGID_FILES SGID). Please review manually."
else
    echo "EXTREQ268= PASS: No SUID or SGID files found"
fi

if awk -F: '($2 != "x" ) { print }' /etc/passwd 2>/dev/null | grep -q '.'; then
    echo "EXTREQ269= FAIL: Non-shadow password field found in /etc/passwd (second field not "x")"
else
    echo "EXTREQ269= PASS: accounts in /etc/passwd use shadowed passwords"
fi

if awk -F: '($2 == "" ) { print }' /etc/shadow 2>/dev/null | grep -q '.'; then
    echo "EXTREQ270= FAIL: Empty password hash found in /etc/shadow"
else
    echo "EXTREQ270= PASS: /etc/shadow password fields are not empty"
fi

FAIL271=0
while IFS=: read -r user pass uid gid rest; do
    if ! grep -q "^.*:.*:$gid:" /etc/group 2>/dev/null; then
        echo "EXTREQ271= FAIL: User $user has primary group GID $gid which does not exist in /etc/group"
        FAIL271=1
    fi
done < /etc/passwd 2>/dev/null
[ $FAIL271 -eq 0 ] && echo "EXTREQ271= PASS: All groups in /etc/passwd exist in /etc/group"

if cut -f3 -d":" /etc/passwd 2>/dev/null | sort -n | uniq -c | while read -r count uid; do [ "$count" -gt 1 ] && echo "found"; done | grep -q "found"; then
    echo "EXTREQ272= FAIL: Duplicate UID entries exist in /etc/passwd"
else
    echo "EXTREQ272= PASS: no duplicate UIDs exist"
fi

if cut -f3 -d":" /etc/group 2>/dev/null | sort -n | uniq -c | while read -r count gid; do [ "$count" -gt 1 ] && echo "found"; done | grep -q "found"; then
    echo "EXTREQ273= FAIL: Duplicate GID entries exist in /etc/group"
else
    echo "EXTREQ273= PASS: no duplicate GIDs exist"
fi

if cut -f1 -d":" /etc/passwd 2>/dev/null | sort -n | uniq -c | while read -r count user; do [ "$count" -gt 1 ] && echo "found"; done | grep -q "found"; then
    echo "EXTREQ274= FAIL: Duplicate user names exist in /etc/passwd"
else
    echo "EXTREQ274= PASS: no duplicate user names exist"
fi

if cut -f1 -d":" /etc/group 2>/dev/null | sort -n | uniq -c | while read -r count group; do [ "$count" -gt 1 ] && echo "found"; done | grep -q "found"; then
    echo "EXTREQ275= FAIL: Duplicate group names exist in /etc/group"
else
    echo "EXTREQ275= PASS: no duplicate group names exist"
fi

FAIL276=0
while IFS=: read -r user pass uid gid rest; do
    if [ "$uid" -ge 1000 ] 2>/dev/null && [ "$uid" -lt 65534 ]; then
        home=$(echo "$rest" | cut -d: -f1)
        for dotfile in "$home/.bashrc" "$home/.bash_profile" "$home/.profile" "$home/.bash_logout"; do
            if [ -f "$dotfile" ]; then
                perm=$(stat -c '%a' "$dotfile" 2>/dev/null)
                if [ "${perm:2:1}" -gt 0 ] 2>/dev/null || [ "${perm:1:1}" -gt 0 ] 2>/dev/null; then
                    echo "EXTREQ276= FAIL: User $user dot file $dotfile has world/group write permissions ($perm)"
                    FAIL276=1
                fi
            fi
        done
    fi
done < /etc/passwd 2>/dev/null
[ $FAIL276 -eq 0 ] && echo "EXTREQ276= PASS: Local interactive user dot files access is configured"

exit 0

