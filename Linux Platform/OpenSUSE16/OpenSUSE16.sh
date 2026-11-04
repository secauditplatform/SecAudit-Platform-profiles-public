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

CRE_FIND_CAP="${CRE_FIND_CAP:-20}"
CRE_CMD_CAP="${CRE_CMD_CAP:-12}"
CRE_DNF_CAP="${CRE_DNF_CAP:-30}"
CRE_ALLOW_CONTAINER_KMOD="${CRE_ALLOW_CONTAINER_KMOD:-${LINUX_CRE_ALLOW_CONTAINER_MODULES:-${ALMA_CRE_ALLOW_CONTAINER_MODULES:-0}}}"

# --- emission ---
sec_audit_report_pass() { printf 'RULE%s= PASS: %s\n' "$1" "$2"; }
sec_audit_report_fail() { printf 'RULE%s= FAIL: %s\n' "$1" "${3:-$2}"; }
sec_audit_report_skip() { printf 'RULE%s= SKIP: %s\n' "$1" "$2"; }
sec_audit_report_error() { printf 'RULE%s= ERROR: %s\n' "$1" "$2"; }

# --- primitives ---
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
    local key="$1" proc_path val
    if sec_audit_have_bin sysctl; then
        sysctl -n "$key" 2>/dev/null | tr -d '
' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
        return 0
    fi
    proc_path="/proc/sys/${key//.//}"
    if [[ -r $proc_path ]]; then
        val=$(tr -d '
' <"$proc_path" 2>/dev/null | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        printf '%s' "$val"
        return 0
    fi
    return 1
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
        sec_audit_report_pass "$num" "${label} (waived: CRE_ALLOW_CONTAINER_KMOD=1)"
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

# --- legacy CRE compatibility aliases ---
sec_audit_low_impact_find() { sec_audit_soft_find "$@"; }
sec_audit_low_impact_find_timed_out() { sec_audit_find_hit_timeout "$@"; }
sec_audit_safe_find_roots() { sec_audit_local_fs_roots; }
sec_audit_pkg_installed() { sec_audit_pkg_is_installed "$@"; }
sec_audit_rule_pass() { sec_audit_report_pass "$@"; }
sec_audit_rule_fail() { sec_audit_report_fail "$@"; }
sec_audit_emit_pass() { sec_audit_report_pass "$@"; }
sec_audit_emit_fail() { sec_audit_report_fail "$@"; }
sec_audit__rule_kernel_mod_unavailable() { sec_audit_assert_kmod_disabled "$@"; }
sec_audit__rule_service_not_in_use() { sec_audit_assert_service_unused "$@"; }
sec_audit__rule_sysctl_check() { sec_audit_assert_sysctl_equals "$@"; }
sec_audit_mount_persisted() { sec_audit_mount_is_persisted "$@"; }
sec_audit_mount_is_mounted() { sec_audit_mount_is_dedicated "$@"; }
sec_audit_mount_has_option() { sec_audit_mount_has_option "$@"; }
sec_audit_mount_separate_partition_ok() { sec_audit_path_is_isolated_volume "$@"; }
sec_audit_findmnt_have() { sec_audit_findmnt_available; }
sec_audit_findmnt_path_resolvable() { sec_audit_mount_resolves "$@"; }
sec_audit_findmnt_is_explicit_mountpoint() { sec_audit_mount_is_dedicated "$@"; }
sec_audit_findmnt_source_for() { sec_audit_mount_source "$@"; }
sec_audit_findmnt_fstype_for() { sec_audit_mount_fstype "$@"; }
sec_audit_findmnt_options_raw() { sec_audit_mount_options "$@"; }
sec_audit_findmnt_has_mnt_option() { sec_audit_mount_has_option "$@"; }
sec_audit_findmnt_separate_partition_ok() { sec_audit_path_is_isolated_volume "$@"; }
sec_audit_findmnt_tmp_sec_ok() { sec_audit_tmp_is_isolated; }
sec_audit_findmnt_shm_sec_ok() { sec_audit_shm_is_isolated; }
sec_audit_kernel_mod_in_modules_load() { sec_audit_kmod_autoload_listed "$@"; }
sec_audit_kernel_mod_lsmod_name_loaded() { sec_audit_kmod_is_loaded "$@"; }
sec_audit_kernel_mod_ko_scan() { sec_audit_kmod_object_exists "$@"; }
sec_audit_kernel_mod_refuses_load() { sec_audit_kmod_is_blocked "$@"; }
sec_audit_kernel_mod_cre_waiver() { sec_audit_kmod_container_exception "$@"; }
sec_audit_systemd_unit_enabled_or_active() { sec_audit_systemd_unit_live "$@"; }

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

sec_audit__yum_repo_list_explicit_gpgcheck0() {
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

sec_audit__yum_repo_list_explicit_repo_gpgcheck0() {
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

sec_audit__yum_repo_any_enabled_has_uris() {
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

_SSHD_T_READY=0
_sshd_t_cache=""

sec_audit__sshd_t_ensure() {
    [ "${_SSHD_T_READY:-0}" -eq 1 ] && return 0
    _SSHD_T_READY=1
    if sec_audit_have_bin sshd; then
        _sshd_t_cache=$(sshd -T 2>/dev/null) || _sshd_t_cache=""
    else
        _sshd_t_cache=""
    fi
}

sec_audit_sshd_effective_dump() {
    sec_audit__sshd_t_ensure
    builtin printf '%s\n' "$_sshd_t_cache"
}

sec_audit_sshd_t_grep() {
    sec_audit__sshd_t_ensure
    builtin printf '%s\n' "$_sshd_t_cache" | grep "$@"
}

sec_audit_sshd_t_awk() {
    sec_audit__sshd_t_ensure
    builtin printf '%s\n' "$_sshd_t_cache" | awk "$@"
}

_AUDITCTL_L_READY=0
_auditctl_l_cache=""

sec_audit__auditctl_l_ensure() {
    [ "${_AUDITCTL_L_READY:-0}" -eq 1 ] && return 0
    _AUDITCTL_L_READY=1
    if sec_audit_have_bin auditctl; then
        _auditctl_l_cache=$(auditctl -l 2>/dev/null) || _auditctl_l_cache=""
    else
        _auditctl_l_cache=""
    fi
}

sec_audit_auditctl_rules_grep() {
    sec_audit__auditctl_l_ensure
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
    if grep -rPi '^\h*DefaultLimitCORE\h*=\h*(infinity|unlimited)\b' /etc/systemd/system.conf /etc/systemd/user.conf /etc/systemd/system.conf.d/*.conf /etc/systemd/user.conf.d/*.conf 2>/dev/null; then
        return 1
    fi
    if grep -rPi '^\h*DefaultLimitCORE\h*=\h*[1-9][0-9]*\b' /etc/systemd/system.conf /etc/systemd/user.conf /etc/systemd/system.conf.d/*.conf /etc/systemd/user.conf.d/*.conf 2>/dev/null; then
        return 1
    fi
    return 0
}

_audit_rules_files_ready=0
_audit_rules_files_cache=""

sec_audit__audit_rules_files_ensure() {
    [ "${_audit_rules_files_ready:-0}" -eq 1 ] && return 0
    _audit_rules_files_ready=1
    shopt -s nullglob
    _audit_rules_files_cache=$(cat /etc/audit/rules.d/*.rules /etc/audit/audit.rules 2>/dev/null)
    shopt -u nullglob
}

sec_audit_audit_rules_files_grep() {
    sec_audit__audit_rules_files_ensure
    builtin printf '%s\n' "$_audit_rules_files_cache" | grep "$@"
}

sec_audit_audit_rule_loaded_and_on_disk() {
    sec_audit__audit_rules_files_ensure
    sec_audit__auditctl_l_ensure
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
    sec_audit__sshd_t_ensure
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


# =============================================================================
# Entry
# =============================================================================

sec_audit_run_kernel_modules() {
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
if sec_audit_kernel_mod_in_modules_load firewire_core firewire-core; then
sec_audit_report_fail 9 "firewire-core kernel module is listed in modules-load.d (auto-load at boot)"
elif ! sec_audit_low_impact_find --timeout=20 /usr/lib/modules/ /lib/modules/ -xdev -ignore_readdir_race -type f -name "firewire-core.ko*" 2>/dev/null | grep -q .; then
sec_audit_report_pass 9 "firewire-core kernel module is not available"
else
if ! lsmod | grep -q firewire_core && modprobe --showconfig | grep -Pq '^\h*(blacklist|install)\h+firewire_core\b'; then
    sec_audit_report_pass 9 "firewire-core kernel module is not available"
else
    sec_audit_report_fail 9 "firewire-core kernel module is available, loaded, or not effectively blocked (modprobe blacklist/install)"
fi
fi

# RULE10:
if sec_audit_kernel_mod_in_modules_load usb_storage usb-storage; then
sec_audit_report_fail 10 "usb-storage kernel module is listed in modules-load.d (auto-load at boot)"
elif ! sec_audit_low_impact_find --timeout=20 /usr/lib/modules/ /lib/modules/ -xdev -ignore_readdir_race -type f -name "usb-storage.ko*" 2>/dev/null | grep -q .; then
sec_audit_report_pass 10 "usb-storage kernel module is not available"
else
if ! lsmod | grep -q usb_storage && modprobe --showconfig | grep -Pq '^\h*(blacklist|install)\h+usb_storage\b'; then
    sec_audit_report_pass 10 "usb-storage kernel module is not available"
else
    sec_audit_report_fail 10 "usb-storage kernel module is available, loaded, or not effectively blocked (modprobe blacklist/install)"
fi
fi
}

sec_audit_run_filesystem_partitions() {
# RULE11:
if sec_audit_findmnt_tmp_sec_ok; then
if sec_audit_mount_persisted /tmp; then
    sec_audit_report_pass 11 "/tmp is tmpfs or a separate partition"
else
    sec_audit_report_fail 11 "/tmp is tmpfs or a separate partition is runtime-only (missing fstab or systemd .mount persistence)"
fi
else
sec_audit_report_fail 11 "/tmp does not meet tmpfs or separate-partition requirement"
fi
# RULE12:
if sec_audit_findmnt_path_resolvable /tmp && sec_audit_findmnt_has_mnt_option /tmp nodev; then
sec_audit_report_pass 12 "nodev option set on /tmp partition"
elif ! sec_audit_findmnt_path_resolvable /tmp; then
sec_audit_report_fail 12 "nodev is not set on /tmp (or path not resolvable / not an explicit mount per policy)"
else
sec_audit_report_fail 12 "nodev is not set on /tmp (or path not resolvable / not an explicit mount per policy)"
fi

# RULE13:
if sec_audit_findmnt_path_resolvable /tmp && sec_audit_findmnt_has_mnt_option /tmp nosuid; then
sec_audit_report_pass 13 "nosuid option set on /tmp partition"
elif ! sec_audit_findmnt_path_resolvable /tmp; then
sec_audit_report_fail 13 "nosuid is not set on /tmp (or path not resolvable / not an explicit mount per policy)"
else
sec_audit_report_fail 13 "nosuid is not set on /tmp (or path not resolvable / not an explicit mount per policy)"
fi

# RULE14:
if sec_audit_findmnt_path_resolvable /tmp && sec_audit_findmnt_has_mnt_option /tmp noexec; then
sec_audit_report_pass 14 "noexec option set on /tmp partition"
elif ! sec_audit_findmnt_path_resolvable /tmp; then
sec_audit_report_fail 14 "noexec is not set on /tmp (or path not resolvable / not an explicit mount per policy)"
else
sec_audit_report_fail 14 "noexec is not set on /tmp (or path not resolvable / not an explicit mount per policy)"
fi

# RULE15:
if sec_audit_findmnt_shm_sec_ok; then
if sec_audit_mount_persisted /dev/shm; then
    sec_audit_report_pass 15 "/dev/shm is tmpfs or a separate partition"
else
    sec_audit_report_fail 15 "/dev/shm is tmpfs or a separate partition is runtime-only (missing fstab or systemd .mount persistence)"
fi
else
sec_audit_report_fail 15 "/dev/shm does not meet tmpfs or separate-partition requirement"
fi
# RULE16:
if sec_audit_findmnt_path_resolvable /dev/shm && sec_audit_findmnt_has_mnt_option /dev/shm nodev; then
sec_audit_report_pass 16 "nodev option set on /dev/shm partition"
elif ! sec_audit_findmnt_path_resolvable /dev/shm; then
sec_audit_report_fail 16 "nodev is not set on /dev/shm (or path not resolvable / not an explicit mount per policy)"
else
sec_audit_report_fail 16 "nodev is not set on /dev/shm (or path not resolvable / not an explicit mount per policy)"
fi

# RULE17:
if sec_audit_findmnt_path_resolvable /dev/shm && sec_audit_findmnt_has_mnt_option /dev/shm nosuid; then
sec_audit_report_pass 17 "nosuid option set on /dev/shm partition"
elif ! sec_audit_findmnt_path_resolvable /dev/shm; then
sec_audit_report_fail 17 "nosuid is not set on /dev/shm (or path not resolvable / not an explicit mount per policy)"
else
sec_audit_report_fail 17 "nosuid is not set on /dev/shm (or path not resolvable / not an explicit mount per policy)"
fi

# RULE18:
if sec_audit_findmnt_path_resolvable /dev/shm && sec_audit_findmnt_has_mnt_option /dev/shm noexec; then
sec_audit_report_pass 18 "noexec option set on /dev/shm partition"
elif ! sec_audit_findmnt_path_resolvable /dev/shm; then
sec_audit_report_fail 18 "noexec is not set on /dev/shm (or path not resolvable / not an explicit mount per policy)"
else
sec_audit_report_fail 18 "noexec is not set on /dev/shm (or path not resolvable / not an explicit mount per policy)"
fi

# RULE19:
if sec_audit_findmnt_separate_partition_ok /home; then
if sec_audit_mount_persisted /home; then
    sec_audit_report_pass 19 "separate partition exists for /home"
else
    sec_audit_report_fail 19 "dedicated mount for /home is runtime-only (missing fstab or systemd .mount persistence)"
fi
else
sec_audit_report_fail 19 "no compliant dedicated mount for /home"
fi
# RULE20:
if sec_audit_findmnt_path_resolvable /home && sec_audit_findmnt_has_mnt_option /home nodev; then
sec_audit_report_pass 20 "nodev option set on /home partition"
elif ! sec_audit_findmnt_path_resolvable /home; then
sec_audit_report_fail 20 "nodev is not set on /home (or path not resolvable / not an explicit mount per policy)"
else
sec_audit_report_fail 20 "nodev is not set on /home (or path not resolvable / not an explicit mount per policy)"
fi

# RULE21:
if sec_audit_findmnt_path_resolvable /home && sec_audit_findmnt_has_mnt_option /home nosuid; then
sec_audit_report_pass 21 "nosuid option set on /home partition"
elif ! sec_audit_findmnt_path_resolvable /home; then
sec_audit_report_fail 21 "nosuid is not set on /home (or path not resolvable / not an explicit mount per policy)"
else
sec_audit_report_fail 21 "nosuid is not set on /home (or path not resolvable / not an explicit mount per policy)"
fi

# RULE22:
if sec_audit_findmnt_separate_partition_ok /var; then
if sec_audit_mount_persisted /var; then
    sec_audit_report_pass 22 "separate partition exists for /var"
else
    sec_audit_report_fail 22 "dedicated mount for /var is runtime-only (missing fstab or systemd .mount persistence)"
fi
else
sec_audit_report_fail 22 "no compliant dedicated mount for /var"
fi
# RULE23:
if sec_audit_findmnt_path_resolvable /var && sec_audit_findmnt_has_mnt_option /var nodev; then
sec_audit_report_pass 23 "nodev option set on /var partition"
elif ! sec_audit_findmnt_path_resolvable /var; then
sec_audit_report_fail 23 "nodev is not set on /var (or path not resolvable / not an explicit mount per policy)"
else
sec_audit_report_fail 23 "nodev is not set on /var (or path not resolvable / not an explicit mount per policy)"
fi

# RULE24:
if sec_audit_findmnt_path_resolvable /var && sec_audit_findmnt_has_mnt_option /var nosuid; then
sec_audit_report_pass 24 "nosuid option set on /var partition"
elif ! sec_audit_findmnt_path_resolvable /var; then
sec_audit_report_fail 24 "nosuid is not set on /var (or path not resolvable / not an explicit mount per policy)"
else
sec_audit_report_fail 24 "nosuid is not set on /var (or path not resolvable / not an explicit mount per policy)"
fi

# RULE25:
if sec_audit_findmnt_separate_partition_ok /var/tmp; then
if sec_audit_mount_persisted /var/tmp; then
    sec_audit_report_pass 25 "separate partition exists for /var/tmp"
else
    sec_audit_report_fail 25 "dedicated mount for /var/tmp is runtime-only (missing fstab or systemd .mount persistence)"
fi
else
sec_audit_report_fail 25 "no compliant dedicated mount for /var/tmp"
fi
# RULE26:
if sec_audit_findmnt_path_resolvable /var/tmp && sec_audit_findmnt_has_mnt_option /var/tmp nodev; then
sec_audit_report_pass 26 "nodev option set on /var/tmp partition"
elif ! sec_audit_findmnt_path_resolvable /var/tmp; then
sec_audit_report_fail 26 "nodev is not set on /var/tmp (or path not resolvable / not an explicit mount per policy)"
else
sec_audit_report_fail 26 "nodev is not set on /var/tmp (or path not resolvable / not an explicit mount per policy)"
fi

# RULE27:
if sec_audit_findmnt_path_resolvable /var/tmp && sec_audit_findmnt_has_mnt_option /var/tmp nosuid; then
sec_audit_report_pass 27 "nosuid option set on /var/tmp partition"
elif ! sec_audit_findmnt_path_resolvable /var/tmp; then
sec_audit_report_fail 27 "nosuid is not set on /var/tmp (or path not resolvable / not an explicit mount per policy)"
else
sec_audit_report_fail 27 "nosuid is not set on /var/tmp (or path not resolvable / not an explicit mount per policy)"
fi

# RULE28:
if sec_audit_findmnt_path_resolvable /var/tmp && sec_audit_findmnt_has_mnt_option /var/tmp noexec; then
sec_audit_report_pass 28 "noexec option set on /var/tmp partition"
elif ! sec_audit_findmnt_path_resolvable /var/tmp; then
sec_audit_report_fail 28 "noexec is not set on /var/tmp (or path not resolvable / not an explicit mount per policy)"
else
sec_audit_report_fail 28 "noexec is not set on /var/tmp (or path not resolvable / not an explicit mount per policy)"
fi

# RULE29:
if sec_audit_findmnt_separate_partition_ok /var/log; then
if sec_audit_mount_persisted /var/log; then
    sec_audit_report_pass 29 "separate partition exists for /var/log"
else
    sec_audit_report_fail 29 "dedicated mount for /var/log is runtime-only (missing fstab or systemd .mount persistence)"
fi
else
sec_audit_report_fail 29 "no compliant dedicated mount for /var/log"
fi
# RULE30:
if sec_audit_findmnt_path_resolvable /var/log && sec_audit_findmnt_has_mnt_option /var/log nodev; then
sec_audit_report_pass 30 "nodev option set on /var/log partition"
elif ! sec_audit_findmnt_path_resolvable /var/log; then
sec_audit_report_fail 30 "nodev is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
else
sec_audit_report_fail 30 "nodev is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
fi

# RULE31:
if sec_audit_findmnt_path_resolvable /var/log && sec_audit_findmnt_has_mnt_option /var/log nosuid; then
sec_audit_report_pass 31 "nosuid option set on /var/log partition"
elif ! sec_audit_findmnt_path_resolvable /var/log; then
sec_audit_report_fail 31 "nosuid is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
else
sec_audit_report_fail 31 "nosuid is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
fi

# RULE32:
if sec_audit_findmnt_path_resolvable /var/log && sec_audit_findmnt_has_mnt_option /var/log noexec; then
sec_audit_report_pass 32 "noexec option set on /var/log partition"
elif ! sec_audit_findmnt_path_resolvable /var/log; then
sec_audit_report_fail 32 "noexec is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
else
sec_audit_report_fail 32 "noexec is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
fi

# RULE33:
if sec_audit_findmnt_separate_partition_ok /var/log/audit; then
if sec_audit_mount_persisted /var/log/audit; then
    sec_audit_report_pass 33 "separate partition exists for /var/log/audit"
else
    sec_audit_report_fail 33 "dedicated mount for /var/log/audit is runtime-only (missing fstab or systemd .mount persistence)"
fi
else
sec_audit_report_fail 33 "no compliant dedicated mount for /var/log/audit"
fi
# RULE34:
if sec_audit_findmnt_path_resolvable /var/log/audit && sec_audit_findmnt_has_mnt_option /var/log/audit nodev; then
sec_audit_report_pass 34 "nodev option set on /var/log/audit partition"
elif ! sec_audit_findmnt_path_resolvable /var/log/audit; then
sec_audit_report_fail 34 "nodev is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
else
sec_audit_report_fail 34 "nodev is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
fi

# RULE35:
if sec_audit_findmnt_path_resolvable /var/log/audit && sec_audit_findmnt_has_mnt_option /var/log/audit nosuid; then
sec_audit_report_pass 35 "nosuid option set on /var/log/audit partition"
elif ! sec_audit_findmnt_path_resolvable /var/log/audit; then
sec_audit_report_fail 35 "nosuid is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
else
sec_audit_report_fail 35 "nosuid is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
fi

# RULE36:
if sec_audit_findmnt_path_resolvable /var/log/audit && sec_audit_findmnt_has_mnt_option /var/log/audit noexec; then
sec_audit_report_pass 36 "noexec option set on /var/log/audit partition"
elif ! sec_audit_findmnt_path_resolvable /var/log/audit; then
sec_audit_report_fail 36 "noexec is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
else
sec_audit_report_fail 36 "noexec is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
fi
}

sec_audit_run_package_security() {
# RULE37:
_rule37_k=$(sec_audit_rpm_gpg_pubkey_pkg_count)
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
_rule38_main=$(sec_audit_dnf_main_last_value gpgcheck)
_rule38_repo=$(sec_audit__yum_repo_list_explicit_gpgcheck0 | head -n1)
if sec_audit_dnf_val_is_false "$_rule38_main"; then
sec_audit_report_fail 38 "merged [main] gpgcheck is disabled (effective value: ${_rule38_main})"
elif [ -n "$_rule38_repo" ]; then
sec_audit_report_fail 38 "enabled repository section explicitly sets gpgcheck=0 (${_rule38_repo//|/ -> })"
else
sec_audit_report_pass 38 "[main] gpgcheck is not false and no enabled .repo section forces gpgcheck=0"
fi

# RULE39:
_rule39_main=$(sec_audit_dnf_main_last_value repo_gpgcheck)
_rule39_repo=$(sec_audit__yum_repo_list_explicit_repo_gpgcheck0 | head -n1)
if sec_audit_dnf_val_is_false "$_rule39_main"; then
sec_audit_report_fail 39 "merged [main] repo_gpgcheck is disabled (effective value: ${_rule39_main})"
elif [ -z "$_rule39_main" ]; then
sec_audit_report_fail 39 "repo_gpgcheck not explicitly enabled in merged [main] (dnf defaults to false when unset)"
elif ! sec_audit_dnf_val_is_true "$_rule39_main"; then
sec_audit_report_fail 39 "repo_gpgcheck in [main] is not a true value (expected 1/true/yes/on; got: ${_rule39_main})"
elif [ -n "$_rule39_repo" ]; then
sec_audit_report_fail 39 "enabled repository section explicitly sets repo_gpgcheck=0 (${_rule39_repo//|/ -> })"
else
sec_audit_report_pass 39 "repo_gpgcheck enabled in [main] and no enabled .repo section forces repo_gpgcheck=0"
fi

# RULE40:
_rule40_dnf_n=$(sec_audit_dnf_repolist_enabled_count)
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
elif ! sec_audit__yum_repo_any_enabled_has_uris; then
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
_rule41_iwd=$(sec_audit_dnf_main_last_value install_weak_deps)
if sec_audit_dnf_val_is_false "$_rule41_iwd"; then
sec_audit_report_pass 41 "install_weak_deps is false in merged [main] (weak dependencies not installed by default)"
elif [ -z "$_rule41_iwd" ]; then
sec_audit_report_fail 41 "install_weak_deps not set to 0/false/no/off in [main] (dnf default enables weak dependencies)"
else
sec_audit_report_fail 41 "install_weak_deps is not false in merged [main] (effective: ${_rule41_iwd})"
fi
}

sec_audit_run_selinux() {
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
if rpm -q mcstrans &>/dev/null || dpkg -s mcstrans &>/dev/null; then
sec_audit_report_fail 45 "package mcstrans is installed"
else
sec_audit_report_pass 45 "package mcstrans is not installed"
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
if rpm -q setroubleshoot &>/dev/null || dpkg -s setroubleshoot &>/dev/null; then
sec_audit_report_fail 48 "package setroubleshoot is installed"
else
sec_audit_report_pass 48 "package setroubleshoot is not installed"
fi
}

sec_audit_run_bootloader() {
# RULE49:
if sec_audit_grub_cfg_grep '^[[:space:]]*set superusers' && sec_audit_grub_cfg_grep 'password_pbkdf2'; then
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
done <<< "$(sec_audit_grub_cfg_paths)"
if [ "$_fail50" -eq 0 ]; then
sec_audit_report_pass 50 "access to bootloader config is configured"
else
sec_audit_report_fail 50 "/boot/grub2/grub.cfg (or EFI grub.cfg) owner/mode is not root:root with mode 600"
fi
}

sec_audit_run_process_hardening() {
# RULE51:
if sec_audit_limits_core_zero_and_systemd_ok; then
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
_rule59_corep=$(sec_audit_sysctl_key_runtime kernel.core_pattern)
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
if grep -Pi '^\h*LEGACY\b' /etc/crypto-policies/config 2>/dev/null; then
sec_audit_report_fail 60 "System-wide crypto policy is LEGACY in /etc/crypto-policies/config"
else
sec_audit_report_pass 60 "system wide crypto policy is not set to legacy"
fi
}

sec_audit_run_crypto_policy() {
# RULE61:
if grep -Pi '^\h*LEGACY\b' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null | grep -q .; then
sec_audit_report_fail 61 "System-wide crypto policy state is LEGACY in CURRENT.pol"
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
}

sec_audit_run_banners() {
# RULE64:
if grep -Pi '(^\h*mac\h*=\h*([^#\n\r]+)?-128|hmac-sha1)' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null | grep -q .; then
sec_audit_report_fail 64 "Weak MAC algorithms still present in /etc/crypto-policies/state/CURRENT.pol"
else
sec_audit_report_pass 64 "system wide crypto policy macs are configured"
fi

# RULE65:
if grep -Piq '^\h*cipher@(lib|open)ssh(-server|-client)?\h*=\h*([^#\n\r]+)?-CBC\b' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null; then
sec_audit_report_pass 65 "system wide crypto policy disables cbc for ssh (ssh-specific override found)"
elif grep -Piq '^\h*cipher\h*=\h*([^#\n\r]+)?-CBC\b' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null; then
sec_audit_report_pass 65 "system wide crypto policy disables cbc for ssh"
else
sec_audit_report_fail 65 "CBC ciphers for SSH are still allowed by active crypto policy state (CURRENT.pol)"
fi

# RULE66:
if grep -Piq '^\h*cipher@(lib|open)ssh(-server|-client)?\h*=\h*([^#\n\r]+,)?chacha20-poly1305\b' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null; then
sec_audit_report_fail 66 "chacha20-poly1305 is still listed for SSH in active crypto policy (CURRENT.pol)"
else
sec_audit_report_pass 66 "system wide crypto policy disables chacha20-poly1305 for ssh"
fi

# RULE67:
if grep -Psi "(\\\v|\\\r|\\\m|\\\s|\b$(grep ^ID= /etc/os-release 2>/dev/null | cut -d= -f2 | sed -e 's/"//g')\b)" /etc/motd 2>/dev/null; then
sec_audit_report_fail 67 "/etc/motd is missing or does not contain required banner content"
else
sec_audit_report_pass 67 "/etc/motd is configured"
fi

# RULE68:
if grep -Psi "(\\\v|\\\r|\\\m|\\\s|\b$(grep ^ID= /etc/os-release 2>/dev/null | cut -d= -f2 | sed -e 's/"//g')\b)" /etc/issue 2>/dev/null; then
sec_audit_report_fail 68 "/etc/issue is missing or does not contain required local login banner"
else
sec_audit_report_pass 68 "/etc/issue is configured"
fi

# RULE69:
if [ -f /etc/issue.net ]; then
if grep -Psi "(\\\v|\\\r|\\\m|\\\s|\b$(grep ^ID= /etc/os-release 2>/dev/null | cut -d= -f2 | sed -e 's/"//g')\b)" /etc/issue.net 2>/dev/null; then
    sec_audit_report_fail 69 "/etc/issue.net is missing or does not contain required remote login banner"
else
    sec_audit_report_pass 69 "/etc/issue.net is configured"
fi
else
sec_audit_report_pass 69 "/etc/issue.net is configured"
fi
}

sec_audit_run_gdm() {
# RULE70:
if [ -e /etc/motd ]; then
if stat -Lc '%a' /etc/motd 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' /etc/motd 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 70 "access to /etc/motd is configured"
    else
        sec_audit_report_fail 70 "File /etc/motd permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 70 "File /etc/motd permissions or ownership not correct"
fi
else
sec_audit_report_pass 70 "access to /etc/motd is configured (file not found)"
fi

# RULE71:
if stat -Lc '%a' /etc/issue 2>/dev/null | grep -qE '^[0-6]44$'; then
if stat -Lc '%U:%G' /etc/issue 2>/dev/null | grep -q '^root:root$'; then
    sec_audit_report_pass 71 "access to /etc/issue is configured"
else
    sec_audit_report_fail 71 "File /etc/issue permissions or ownership not correct"
fi
else
sec_audit_report_fail 71 "File /etc/issue permissions or ownership not correct"
fi

# RULE72:
if [ -e /etc/issue.net ]; then
if stat -Lc '%a' /etc/issue.net 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' /etc/issue.net 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 72 "access to /etc/issue.net is configured"
    else
        sec_audit_report_fail 72 "File /etc/issue.net permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 72 "File /etc/issue.net permissions or ownership not correct"
fi
else
sec_audit_report_pass 72 "access to /etc/issue.net is configured (file not found)"
fi

# RULE73:
if stat -Lc '%a' /etc/issue 2>/dev/null | grep -qE '^[0-6]44$'; then
if stat -Lc '%U:%G' /etc/issue 2>/dev/null | grep -q '^root:root$'; then
    sec_audit_report_pass 73 "access to /etc/issue is configured"
else
    sec_audit_report_fail 73 "File /etc/issue permissions or ownership not correct"
fi
else
sec_audit_report_fail 73 "File /etc/issue permissions or ownership not correct"
fi

# RULE74:
if [ -e /etc/issue.net ]; then
if stat -Lc '%a' /etc/issue.net 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' /etc/issue.net 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 74 "access to /etc/issue.net is configured"
    else
        sec_audit_report_fail 74 "File /etc/issue.net permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 74 "File /etc/issue.net permissions or ownership not correct"
fi
else
sec_audit_report_pass 74 "access to /etc/issue.net is configured (file not found)"
fi

if ! sec_audit_sshd_effective_usable; then
sec_audit_report_fail 75 "unable_to_evaluate: sshd -T produced no effective configuration"
else
# RULE75:
SSHD_BANNER=$(sec_audit_sshd_t_grep -i '^banner' 2>/dev/null | awk '{print $2}' | head -1)
if [ -n "$SSHD_BANNER" ] && [ "$SSHD_BANNER" != "none" ] && [ -f "$SSHD_BANNER" ]; then
if stat -Lc '%a' "$SSHD_BANNER" 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' "$SSHD_BANNER" 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 75 "access to sshd warning banner is configured ($SSHD_BANNER)"
    else
        sec_audit_report_fail 75 "sshd banner file $SSHD_BANNER has wrong ownership"
    fi
else
    sec_audit_report_fail 75 "sshd banner file $SSHD_BANNER has wrong permissions"
fi
elif [ -z "$SSHD_BANNER" ] || [ "$SSHD_BANNER" = "none" ]; then
sec_audit_report_fail 75 "sshd Banner is not configured (see sshd -T)"
else
sec_audit_report_fail 75 "sshd banner file $SSHD_BANNER not found"
fi

fi

# RULE76:
GDM_CONFIG="/etc/gdm/custom.conf"
if [ -f "$GDM_CONFIG" ]; then
if grep -Pzo "\[org/gnome/login-screen\][^\[]*banner-message-enable=true" "$GDM_CONFIG" 2>/dev/null | grep -q .; then
    sec_audit_report_pass 76 "GDM login banner is configured"
else
    sec_audit_report_fail 76 "GDM login banner is not configured in $GDM_CONFIG"
fi
else
sec_audit_report_fail 76 "GDM configuration file not found ($GDM_CONFIG)"
fi

# RULE77:
if rpm -q gdm &>/dev/null && grep -q "DisableUserList=true" /etc/gdm/custom.conf 2>/dev/null; then
sec_audit_report_pass 77 "GDM disable-user-list is configured"
elif ! rpm -q gdm &>/dev/null; then
sec_audit_report_pass 77 "GDM is not installed"
else
sec_audit_report_fail 77 "GDM disable-user-list is not configured"
fi

# RULE78:
if grep -q "idle-delay=uint32" /etc/dconf/db/gdm.d/* 2>/dev/null || \
   grep -q "lock-delay=uint32" /etc/dconf/db/gdm.d/* 2>/dev/null; then
sec_audit_report_pass 78 "GDM screen lock is configured"
else
sec_audit_report_fail 78 "GDM screen lock is not configured"
fi

# RULE79:
if grep -q "automount=false" /etc/dconf/db/gdm.d/* 2>/dev/null || \
   grep -q "automount-open=false" /etc/dconf/db/gdm.d/* 2>/dev/null; then
sec_audit_report_pass 79 "GDM automount is configured"
else
sec_audit_report_fail 79 "GDM automount is not configured"
fi

# RULE80:
if grep -q "autorun-never=true" /etc/dconf/db/gdm.d/* 2>/dev/null; then
sec_audit_report_pass 80 "GDM autorun-never is configured"
else
sec_audit_report_fail 80 "GDM autorun-never is not configured"
fi

# RULE81:
if grep -Psi '^\h*WaylandEnable=false' /etc/gdm/custom.conf 2>/dev/null; then
sec_audit_report_pass 81 "Xwayland is configured"
else
sec_audit_report_fail 81 "WaylandEnable=false (or equivalent) is not set in GDM custom.conf — Xwayland may remain enabled"
fi

# RULE82:
if grep -Psi '^\h*WaylandEnable=false' /etc/gdm/custom.conf 2>/dev/null | grep -q .; then
sec_audit_report_pass 82 "Xwayland is configured (WaylandEnable=false)"
elif ! rpm -q gdm &>/dev/null; then
sec_audit_report_pass 82 "Xwayland is configured (GDM not installed)"
else
sec_audit_report_fail 82 "WaylandEnable=false is not set in GDM custom.conf — Xwayland may remain enabled"
fi

# RULE83:
sec_audit_assert_service_unused 83 autofs "autofs services are not in use" "autofs services are installed and enabled or actively running" "autofs.service"
# RULE84:
sec_audit_assert_service_unused 84 avahi "avahi daemon services are not in use" "avahi daemon services are installed and enabled or actively running" "avahi-daemon.socket" "avahi-daemon.service"
# RULE85:
sec_audit_assert_service_unused 85 cockpit-ws "cockpit web services are not in use" "cockpit web services are installed and enabled or actively running" "cockpit.socket" "cockpit.service"
# RULE86:
sec_audit_assert_service_unused 86 dhcp-server "dhcp server services are not in use" "dhcp server services are installed and enabled or actively running" "dhcpd.service" "dhcpd6.service"
# RULE87:
sec_audit_assert_service_unused 87 bind "dns server services are not in use" "dns server services are installed and enabled or actively running" "named.service"
# RULE88:
sec_audit_assert_service_unused 88 dnsmasq "dnsmasq services are not in use" "dnsmasq services are installed and enabled or actively running" "dnsmasq.service"
# RULE89:
sec_audit_assert_service_unused 89 vsftpd "ftp server services are not in use" "ftp server services are installed and enabled or actively running" "vsftpd.service"
# RULE90:
if sec_audit_pkg_any_installed dovecot cyrus-imapd; then
if sec_audit_systemd_unit_enabled_or_active dovecot.socket dovecot.service cyrus-imapd.service; then
    sec_audit_report_fail 90 "message access server services are installed and enabled or actively running"
else
    sec_audit_report_pass 90 "message access server services are not in use (package present but units masked/disabled/inactive)"
fi
else
sec_audit_report_pass 90 "message access server services are not in use"
fi
# RULE91:
sec_audit_assert_service_unused 91 nfs-utils "network file system services are not in use" "network file system services are installed and enabled or actively running" "nfs-server.service"
# RULE92:
sec_audit_assert_service_unused 92 cups "print server services are not in use" "print server services are installed and enabled or actively running" "cups.socket" "cups.service"
# RULE93:
sec_audit_assert_service_unused 93 rpcbind "rpcbind services are not in use" "rpcbind services are installed and enabled or actively running" "rpcbind.socket" "rpcbind.service"
# RULE94:
sec_audit_assert_service_unused 94 rsync-daemon "rsync services are not in use" "rsync services are installed and enabled or actively running" "rsyncd.socket" "rsyncd.service"
# RULE95:
sec_audit_assert_service_unused 95 samba "samba file server services are not in use" "samba file server services are installed and enabled or actively running" "smb.service"
# RULE96:
sec_audit_assert_service_unused 96 net-snmp "snmp services are not in use" "snmp services are installed and enabled or actively running" "snmpd.service"
# RULE97:
sec_audit_assert_service_unused 97 telnet-server "telnet server services are not in use" "telnet server services are installed and enabled or actively running" "telnet.socket"
# RULE98:
sec_audit_assert_service_unused 98 tftp-server "tftp server services are not in use" "tftp server services are installed and enabled or actively running" "tftp.socket" "tftp.service"
# RULE99:
sec_audit_assert_service_unused 99 squid "web proxy server services are not in use" "web proxy server services are installed and enabled or actively running" "squid.service"
# RULE100:
if sec_audit_pkg_any_installed httpd nginx; then
if sec_audit_systemd_unit_enabled_or_active httpd.service nginx.service; then
    sec_audit_report_fail 100 "web server services are installed and enabled or actively running"
else
    sec_audit_report_pass 100 "web server services are not in use (package present but units masked/disabled/inactive)"
fi
else
sec_audit_report_pass 100 "web server services are not in use"
fi
# RULE101:
if rpm -q gdm &>/dev/null || systemctl is-enabled gdm 2>/dev/null | grep -q 'enabled' || systemctl is-active gdm 2>/dev/null | grep -q '^active'; then
sec_audit_report_fail 101 "GNOME Display Manager (gdm) package is still installed"
else
sec_audit_report_pass 101 "GNOME Display Manager is removed"
fi

# RULE102:
if rpm -q xorg-x11-server-Xwayland &>/dev/null; then
sec_audit_report_fail 102 "X window server services are installed and enabled or actively running"
else
sec_audit_report_pass 102 "X window server services are not in use"
fi

# RULE103:
if ss -lntu 2>/dev/null | grep -E ':25\b' | grep -qvE '127\.0\.0\.1:25|::1:25|\[::1\]:25'; then
sec_audit_report_fail 103 "mail transfer agent is listening on a non-loopback interface (port 25)"
elif ss -lntu 2>/dev/null | grep -qE ':25\b'; then
sec_audit_report_pass 103 "mail transfer agents are configured for local-only mode"
else
sec_audit_report_pass 103 "mail transfer agents are configured for local-only mode (no MTA listening)"
fi

# RULE104:
if rpm -q ftp &>/dev/null; then
sec_audit_report_fail 104 "ftp client package is installed"
else
sec_audit_report_pass 104 "ftp client is not installed"
fi

# RULE105:
if rpm -q openldap-clients &>/dev/null; then
sec_audit_report_fail 105 "ldap client package is installed"
else
sec_audit_report_pass 105 "ldap client is not installed"
fi

# RULE106:
if rpm -q telnet &>/dev/null; then
sec_audit_report_fail 106 "telnet client package is installed"
else
sec_audit_report_pass 106 "telnet client is not installed"
fi

# RULE107:
if rpm -q telnet &>/dev/null || dpkg -s telnet &>/dev/null; then
sec_audit_report_fail 107 "package telnet is installed"
else
sec_audit_report_pass 107 "package telnet is not installed"
fi

# RULE108:
if rpm -q tftp &>/dev/null; then
sec_audit_report_fail 108 "tftp client package is installed"
else
sec_audit_report_pass 108 "tftp client is not installed"
fi

# RULE109:
if rpm -q chrony &>/dev/null; then
if grep -Ps '^\h*(server|pool|peer)\h+\S' /etc/chrony.conf /etc/chrony.d/*.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 109 "chrony is configured"
else
    sec_audit_report_fail 109 "chrony is installed but no time servers configured"
fi
else
sec_audit_report_fail 109 "chrony package is not installed"
fi

# RULE110:
if systemctl is-enabled chronyd.service 2>/dev/null | grep -q 'enabled'; then
if systemctl is-active chronyd.service 2>/dev/null | grep -q '^active'; then
    sec_audit_report_pass 110 "chrony is enabled and running"
else
    sec_audit_report_fail 110 "chronyd service is enabled but not active"
fi
else
sec_audit_report_fail 110 "chronyd service is not enabled"
fi

# RULE111:
if systemctl is-enabled crond.service 2>/dev/null | grep -q 'enabled'; then
if systemctl is-active crond.service 2>/dev/null | grep -q 'active'; then
    sec_audit_report_pass 111 "cron daemon is enabled and active"
else
    sec_audit_report_fail 111 "crond service is not enabled or not active"
fi
else
sec_audit_report_fail 111 "crond service is not enabled or not active"
fi

# RULE112:
if stat -Lc '%a' /etc/crontab 2>/dev/null | grep -q '^[0-6]00$'; then
if stat -Lc '%U:%G' /etc/crontab 2>/dev/null | grep -q '^root:root$'; then
    sec_audit_report_pass 112 "access to /etc/crontab is configured"
else
    sec_audit_report_fail 112 "File /etc/crontab permissions or ownership not correct"
fi
else
sec_audit_report_fail 112 "File /etc/crontab permissions or ownership not correct"
fi

# RULE113:
if stat -Lc '%a' /etc/cron.hourly 2>/dev/null | grep -q '^700$'; then
if stat -Lc '%U:%G' /etc/cron.hourly 2>/dev/null | grep -q '^root:root$'; then
    sec_audit_report_pass 113 "access to /etc/cron.hourly is configured"
else
    sec_audit_report_fail 113 "File /etc/cron.hourly permissions or ownership not correct"
fi
else
sec_audit_report_fail 113 "File /etc/cron.hourly permissions or ownership not correct"
fi

# RULE114:
if stat -Lc '%a' /etc/cron.daily 2>/dev/null | grep -q '^700$'; then
if stat -Lc '%U:%G' /etc/cron.daily 2>/dev/null | grep -q '^root:root$'; then
    sec_audit_report_pass 114 "access to /etc/cron.daily is configured"
else
    sec_audit_report_fail 114 "File /etc/cron.daily permissions or ownership not correct"
fi
else
sec_audit_report_fail 114 "File /etc/cron.daily permissions or ownership not correct"
fi

# RULE115:
if stat -Lc '%a' /etc/cron.weekly 2>/dev/null | grep -q '^700$'; then
if stat -Lc '%U:%G' /etc/cron.weekly 2>/dev/null | grep -q '^root:root$'; then
    sec_audit_report_pass 115 "access to /etc/cron.weekly is configured"
else
    sec_audit_report_fail 115 "File /etc/cron.weekly permissions or ownership not correct"
fi
else
sec_audit_report_fail 115 "File /etc/cron.weekly permissions or ownership not correct"
fi

# RULE116:
if stat -Lc '%a' /etc/cron.monthly 2>/dev/null | grep -q '^700$'; then
if stat -Lc '%U:%G' /etc/cron.monthly 2>/dev/null | grep -q '^root:root$'; then
    sec_audit_report_pass 116 "access to /etc/cron.monthly is configured"
else
    sec_audit_report_fail 116 "File /etc/cron.monthly permissions or ownership not correct"
fi
else
sec_audit_report_fail 116 "File /etc/cron.monthly permissions or ownership not correct"
fi

# RULE117:
if stat -Lc '%a' /etc/cron.yearly 2>/dev/null | grep -q '^700$'; then
if stat -Lc '%U:%G' /etc/cron.yearly 2>/dev/null | grep -q '^root:root$'; then
    sec_audit_report_pass 117 "access to /etc/cron.yearly is configured"
else
    sec_audit_report_fail 117 "File /etc/cron.yearly permissions or ownership not correct"
fi
else
sec_audit_report_fail 117 "File /etc/cron.yearly permissions or ownership not correct"
fi

# RULE118:
if stat -Lc '%a' /etc/cron.d 2>/dev/null | grep -q '^700$'; then
if stat -Lc '%U:%G' /etc/cron.d 2>/dev/null | grep -q '^root:root$'; then
    sec_audit_report_pass 118 "access to /etc/cron.d is configured"
else
    sec_audit_report_fail 118 "File /etc/cron.d permissions or ownership not correct"
fi
else
sec_audit_report_fail 118 "File /etc/cron.d permissions or ownership not correct"
fi

# RULE119:
if [ -e /etc/cron.allow ]; then
if stat -Lc '%a' /etc/cron.allow 2>/dev/null | grep -qE '^640$'; then
    if stat -Lc '%U' /etc/cron.allow 2>/dev/null | grep -q 'root'; then
        if stat -Lc '%G' /etc/cron.allow 2>/dev/null | grep -qE 'root|crontab'; then
            sec_audit_report_pass 119 "access to crontab is configured"
        else
            sec_audit_report_fail 119 "File crontab permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 119 "File crontab permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 119 "File crontab permissions or ownership not correct"
fi
else
sec_audit_report_fail 119 "File crontab permissions or ownership not correct"
fi

# RULE120:
if [ -e /etc/at.allow ]; then
if stat -Lc '%a' /etc/at.allow 2>/dev/null | grep -qE '^640$'; then
    if stat -Lc '%U' /etc/at.allow 2>/dev/null | grep -q 'root'; then
        if stat -Lc '%G' /etc/at.allow 2>/dev/null | grep -qE 'daemon|root'; then
            sec_audit_report_pass 120 "access to at is configured"
        else
            sec_audit_report_fail 120 "File at permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 120 "File at permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 120 "File at permissions or ownership not correct"
fi
else
sec_audit_report_fail 120 "File at permissions or ownership not correct"
fi

# RULE121:
FAIL121=0
while IFS= read -r f; do
perm=$(stat -Lc '%a' "$f" 2>/dev/null)
owner=$(stat -Lc '%U:%G' "$f" 2>/dev/null)
if ! echo "$perm" | grep -qE '^[0-6]44$'; then FAIL121=1; break; fi
if ! echo "$owner" | grep -q '^root:root$'; then FAIL121=1; break; fi
done < <(find /etc/systemd/system/ /usr/lib/systemd/system/ -name "*.timer" 2>/dev/null)
if [ $FAIL121 -eq 0 ]; then
sec_audit_report_pass 121 "access to systemd timer unit files is configured"
else
sec_audit_report_fail 121 "systemd timer unit file has wrong permissions or ownership"
fi

# RULE122:
FAIL122=0
while IFS= read -r f; do
perm=$(stat -Lc '%a' "$f" 2>/dev/null)
owner=$(stat -Lc '%U:%G' "$f" 2>/dev/null)
if ! echo "$perm" | grep -qE '^[0-6]44$'; then FAIL122=1; break; fi
if ! echo "$owner" | grep -q '^root:root$'; then FAIL122=1; break; fi
done < <(find /etc/systemd/system/ /usr/lib/systemd/system/ -name "*.service" 2>/dev/null)
if [ $FAIL122 -eq 0 ]; then
sec_audit_report_pass 122 "access to systemd service unit files is configured"
else
sec_audit_report_fail 122 "systemd service unit file has wrong permissions or ownership"
fi

# RULE123:
FAIL123=0
while IFS= read -r d; do
perm=$(stat -Lc '%a' "$d" 2>/dev/null)
owner=$(stat -Lc '%U:%G' "$d" 2>/dev/null)
if ! echo "$perm" | grep -qE '^[0-7](55|50|00)$'; then FAIL123=1; break; fi
if ! echo "$owner" | grep -q '^root:root$'; then FAIL123=1; break; fi
done < <(find /etc/systemd/system/ /usr/lib/systemd/system/ -name "*.timer.d" -type d 2>/dev/null)
if [ $FAIL123 -eq 0 ]; then
sec_audit_report_pass 123 "access to systemd timer drop in directories is configured"
else
sec_audit_report_fail 123 "systemd timer drop-in directory has wrong permissions or ownership"
fi

# RULE124:
LINGER_FOUND=0
while IFS= read -r uid; do
if loginctl show-user "$uid" 2>/dev/null | grep -q 'Linger=yes'; then
    LINGER_FOUND=1; break
fi
done < <(loginctl list-users 2>/dev/null | awk 'NR>1 && $1~/^[0-9]+$/ {print $1}')
if [ $LINGER_FOUND -eq 0 ]; then
sec_audit_report_pass 124 "systemd user timers disable-linger is configured"
else
sec_audit_report_fail 124 "at least one user has linger enabled (systemd user timers may persist)"
fi

# RULE125:
if [ -f /proc/sys/net/ipv6/conf/all/disable_ipv6 ]; then
sec_audit_report_pass 125 "IPv6 status is identified"
else
sec_audit_report_fail 125 "IPv6 status is not identified"
fi

# RULE126:
if compgen -G "/sys/class/net/*/wireless" >/dev/null; then
sec_audit_report_fail 126 "Wireless interfaces are present under /sys/class/net"
else
sec_audit_report_pass 126 "wireless interfaces are not available"
fi

# RULE127:
sec_audit_assert_service_unused 127 bluez "bluetooth services are not in use" "bluetooth services are installed and enabled or actively running" "bluetooth.service"
# RULE128:
sec_audit_assert_kmod_disabled 128 "atm kernel module" atm atm.ko* "atm"
# RULE129:
sec_audit_assert_kmod_disabled 129 "can kernel module" can can.ko* "can"
# RULE130:
sec_audit_assert_kmod_disabled 130 "dccp kernel module" dccp dccp.ko* "dccp"
# RULE131:
sec_audit_assert_kmod_disabled 131 "tipc kernel module" tipc tipc.ko* "tipc"
# RULE132:
sec_audit_assert_kmod_disabled 132 "rds kernel module" rds rds.ko* "rds"
# RULE133:
sec_audit_assert_kmod_disabled 133 "sctp kernel module" sctp sctp.ko* "sctp"
# RULE134:
sec_audit_assert_sysctl_equals 134 net.ipv4.ip_forward 0

# RULE135:
sec_audit_assert_sysctl_equals 135 net.ipv4.conf.all.forwarding 0

# RULE136:
sec_audit_assert_sysctl_equals 136 net.ipv4.conf.default.forwarding 0

# RULE137:
sec_audit_assert_sysctl_equals 137 net.ipv4.conf.all.send_redirects 0

# RULE138:
sec_audit_assert_sysctl_equals 138 net.ipv4.conf.default.send_redirects 0

# RULE139:
sec_audit_assert_sysctl_equals 139 net.ipv4.icmp_ignore_bogus_error_responses 1

# RULE140:
sec_audit_assert_sysctl_equals 140 net.ipv4.icmp_echo_ignore_broadcasts 1

# RULE141:
sec_audit_assert_sysctl_equals 141 net.ipv4.conf.all.accept_redirects 0

# RULE142:
sec_audit_assert_sysctl_equals 142 net.ipv4.conf.default.accept_redirects 0

# RULE143:
sec_audit_assert_sysctl_equals 143 net.ipv4.conf.all.secure_redirects 0

# RULE144:
sec_audit_assert_sysctl_equals 144 net.ipv4.conf.default.secure_redirects 0

# RULE145:
sec_audit_assert_sysctl_equals 145 net.ipv4.conf.all.rp_filter 1

# RULE146:
sec_audit_assert_sysctl_equals 146 net.ipv4.conf.default.rp_filter 1

# RULE147:
sec_audit_assert_sysctl_equals 147 net.ipv4.conf.all.accept_source_route 0

# RULE148:
sec_audit_assert_sysctl_equals 148 net.ipv4.conf.default.accept_source_route 0

# RULE149:
sec_audit_assert_sysctl_equals 149 net.ipv4.conf.all.log_martians 1

# RULE150:
sec_audit_assert_sysctl_equals 150 net.ipv4.conf.default.log_martians 1

# RULE151:
sec_audit_assert_sysctl_equals 151 net.ipv4.tcp_syncookies 1

# RULE152:
sec_audit_assert_sysctl_equals 152 net.ipv4.conf.lo.route_localnet 0

# RULE153:
sec_audit_assert_sysctl_equals 153 net.ipv6.conf.all.forwarding 0

# RULE154:
sec_audit_assert_sysctl_equals 154 net.ipv6.conf.default.forwarding 0

# RULE155:
sec_audit_assert_sysctl_equals 155 net.ipv6.conf.all.accept_redirects 0

# RULE156:
sec_audit_assert_sysctl_equals 156 net.ipv6.conf.default.accept_redirects 0

# RULE157:
sec_audit_assert_sysctl_equals 157 net.ipv6.conf.all.accept_source_route 0

# RULE158:
sec_audit_assert_sysctl_equals 158 net.ipv6.conf.default.accept_source_route 0

# RULE159:
sec_audit_assert_sysctl_equals 159 net.ipv6.conf.all.accept_ra 0

# RULE160:
sec_audit_assert_sysctl_equals 160 net.ipv6.conf.default.accept_ra 0

# RULE161:
if rpm -q firewalld &>/dev/null; then
sec_audit_report_pass 161 "firewalld is installed"
else
sec_audit_report_fail 161 "firewalld package is not installed"
fi

# RULE162:
if grep -Psi 'FirewallBackend\h*=\h*nftables\b' /etc/firewalld/firewalld.conf 2>/dev/null; then
_fw140_be=""
if sec_audit_have_bin firewall-cmd && firewall-cmd --state 2>/dev/null | grep -qi running; then
    _fw140_be=$(firewall-cmd --get-backend 2>/dev/null)
    if [[ "$_fw140_be" == "nftables" ]]; then
        sec_audit_report_pass 162 "firewalld.conf uses nftables and runtime backend is nftables"
    else
        sec_audit_report_pass 162 "firewalld.conf uses nftables (runtime backend reports '${_fw140_be:-?}')"
    fi
else
    sec_audit_report_pass 162 "firewalld.conf uses nftables (firewalld not running; runtime backend not verified)"
fi
else
sec_audit_report_fail 162 "firewalld backend is not configured (FirewallBackend=nftables missing in firewalld.conf)"
fi

# RULE163:
if systemctl is-enabled firewalld.service 2>/dev/null | grep -q 'enabled'; then
if systemctl is-active firewalld.service 2>/dev/null | grep -q 'active'; then
    _fw141_nft=""
    if sec_audit_have_bin nft && nft list ruleset 2>/dev/null | grep -q .; then
        _fw141_nft="; nftables ruleset is non-empty"
    fi
    sec_audit_report_pass 163 "firewalld.service is enabled and active${_fw141_nft}"
else
    sec_audit_report_fail 163 "firewalld.service is not enabled or not active"
fi
else
sec_audit_report_fail 163 "firewalld.service is not enabled or not active"
fi

# RULE164:
if systemctl is-active firewalld &>/dev/null; then
ACTIVE_ZONE=$(firewall-cmd --get-default-zone 2>/dev/null)
ZONE_TARGET=$(firewall-cmd --zone="$ACTIVE_ZONE" --get-target 2>/dev/null)
_fw142_if=$(firewall-cmd --zone="$ACTIVE_ZONE" --list-interfaces 2>/dev/null | wc -w)
if [ "$ZONE_TARGET" = "DROP" ] || [ "$ZONE_TARGET" = "REJECT" ]; then
    sec_audit_report_pass 164 "firewalld default zone '$ACTIVE_ZONE' target is $ZONE_TARGET (${_fw142_if:-0} interface(s) assigned)"
else
    sec_audit_report_fail 164 "firewalld active zone target is not secure (current: $ZONE_TARGET)"
fi
else
sec_audit_report_fail 164 "firewalld is not active"
fi

# RULE165:
if systemctl is-active firewalld &>/dev/null; then
if firewall-cmd --list-rich-rules 2>/dev/null | grep -Eiq 'lo|loopback|127\.0\.0\.1|interface\s*=\s*\"lo\"|interface\s*=\s*lo\b'; then
    sec_audit_report_pass 165 "firewalld rich rules mention loopback / lo / localhost"
else
    sec_audit_report_fail 165 "firewalld loopback traffic is not configured"
fi
else
sec_audit_report_fail 165 "firewalld is not active"
fi

# RULE166:
if systemctl is-active firewalld &>/dev/null; then
if firewall-cmd --zone=trusted --list-sources 2>/dev/null | grep -qE '127\.0\.0\.1|::1'; then
    sec_audit_report_pass 166 "firewalld loopback source address traffic is configured"
elif firewall-cmd --list-rich-rules 2>/dev/null | grep -q 'source address="127\.0\.0\.0/8"'; then
    sec_audit_report_pass 166 "firewalld loopback source address traffic is configured via rich-rules"
else
    sec_audit_report_fail 166 "firewalld loopback zone source address not configured for 127.0.0.1/::1"
fi
else
sec_audit_report_fail 166 "firewalld is not active"
fi

# RULE167:
if systemctl is-active firewalld &>/dev/null; then
SERVICES=$(firewall-cmd --list-services 2>/dev/null | wc -w)
PORTS=$(firewall-cmd --list-ports 2>/dev/null | wc -w)
SERVICES_P=$(firewall-cmd --permanent --list-services 2>/dev/null | wc -w)
PORTS_P=$(firewall-cmd --permanent --list-ports 2>/dev/null | wc -w)
if [ "$SERVICES" -gt 0 ] || [ "$PORTS" -gt 0 ]; then
    sec_audit_report_pass 167 "firewalld exposes $SERVICES service(s) and $PORTS port(s) at runtime (permanent: $SERVICES_P / $PORTS_P)"
elif [ "$SERVICES_P" -gt 0 ] || [ "$PORTS_P" -gt 0 ]; then
    sec_audit_report_fail 167 "permanent firewalld rules exist ($SERVICES_P services, $PORTS_P ports) but runtime lists none — run firewall-cmd --reload"
else
    sec_audit_report_fail 167 "firewalld services and ports are not configured"
fi
else
sec_audit_report_fail 167 "firewalld is not active"
fi

# RULE168:
if stat -Lc '%a' /etc/ssh/sshd_config 2>/dev/null | grep -q '^600$'; then
if stat -Lc '%U:%G' /etc/ssh/sshd_config 2>/dev/null | grep -q '^root:root$'; then
    sec_audit_report_pass 168 "access to /etc/ssh/sshd_config is configured"
else
    sec_audit_report_fail 168 "File /etc/ssh/sshd_config permissions or ownership not correct"
fi
else
sec_audit_report_fail 168 "File /etc/ssh/sshd_config permissions or ownership not correct"
fi


if ! sec_audit_sshd_effective_usable; then
for _sshn in 169 170 171 172 173 174 175 176 177 178 179 180 181 182 183 184 185 186 187 188 189 190 191; do
    sec_audit_report_fail "$_sshn" "unable_to_evaluate: sshd -T produced no effective configuration"
done
else
# RULE169:
PRIV_KEYS=$(sec_audit_sshd_effective_dump | awk '$1=="hostkey" {print $2}')
FAIL169=0
for key in $PRIV_KEYS; do
if [ -f "$key" ]; then
    if ! stat -Lc '%a' "$key" 2>/dev/null | grep -q '^600$'; then
        FAIL169=1
    fi
    if ! stat -Lc '%U:%G' "$key" 2>/dev/null | grep -q '^root:root$'; then
        FAIL169=1
    fi
else
    FAIL169=1
fi
done
if [ $FAIL169 -eq 0 ]; then
sec_audit_report_pass 169 "access to SSH private host key files is configured"
else
sec_audit_report_fail 169 "File SSH private host key files permissions or ownership not correct"
fi

# RULE170:
PUB_KEYS=$(sec_audit_sshd_effective_dump | awk '$1=="hostkey" {print $2".pub"}')
FAIL170=0
for key in $PUB_KEYS; do
if [ -f "$key" ]; then
    if ! stat -Lc '%a' "$key" 2>/dev/null | grep -qE '^[0-6]44$'; then
        FAIL170=1
    fi
    if ! stat -Lc '%U:%G' "$key" 2>/dev/null | grep -q '^root:root$'; then
        FAIL170=1
    fi
else
    FAIL170=1
fi
done
if [ $FAIL170 -eq 0 ]; then
sec_audit_report_pass 170 "access to SSH public host key files is configured"
else
sec_audit_report_fail 170 "File SSH public host key files permissions or ownership not correct"
fi

# RULE171:
if sec_audit_sshd_t_grep -Piq '^\h*(allow|deny)(users|groups)\h+\H+'; then
sec_audit_report_pass 171 "sshd access is configured"
else
sec_audit_report_fail 171 "sshd access controls (AllowUsers/DenyUsers/AllowGroups/DenyGroups) are not set as required"
fi

# RULE172:
if sec_audit_sshd_t_grep -Piq '^banner\h+\/\H+'; then
sec_audit_report_pass 172 "sshd Banner is configured"
else
sec_audit_report_fail 172 "sshd Banner does not meet the required policy (see sshd -T)"
fi

# RULE173:
if sec_audit_sshd_t_grep -Piq '^ciphers\h+\"?([^#\n\r]+,)?((3des|blowfish|cast128|aes(128|192|256))-cbc|arcfour(128|256)?|rijndael-cbc@lysator\.liu\.se)\b'; then
sec_audit_report_fail 173 "sshd Ciphers allow weak or legacy algorithms (see sshd -T)"
else
sec_audit_report_pass 173 "sshd Ciphers are configured"
fi

# RULE174:
if sec_audit_sshd_t_grep -Piq 'clientaliveinterval\s+([1-9]|[1-9][0-9]+)'; then
if sec_audit_sshd_t_grep -Piq 'clientalivecountmax\s+([1-9]|[1-9][0-9]+)'; then
    sec_audit_report_pass 174 "sshd ClientAliveInterval and ClientAliveCountMax are configured"
else
    sec_audit_report_fail 174 "sshd ClientAliveInterval and ClientAliveCountMax are not configured as required (see sshd -T)"
fi
else
sec_audit_report_fail 174 "sshd ClientAliveInterval and ClientAliveCountMax are not configured as required (see sshd -T)"
fi

# RULE175:
if sec_audit_sshd_t_grep -iq 'disableforwarding yes'; then
sec_audit_report_pass 175 "sshd DisableForwarding is enabled"
else
sec_audit_report_fail 175 "sshd DisableForwarding is not enabled in effective sshd -T output"
fi

# RULE176:
if sec_audit_sshd_t_grep -iq 'gssapiauthentication no'; then
sec_audit_report_pass 176 "sshd GSSAPIAuthentication is disabled"
else
sec_audit_report_fail 176 "sshd GSSAPIAuthentication is not disabled in effective sshd -T output"
fi

# RULE177:
if sec_audit_sshd_t_grep -iq 'hostbasedauthentication no'; then
sec_audit_report_pass 177 "sshd HostbasedAuthentication is disabled"
else
sec_audit_report_fail 177 "sshd HostbasedAuthentication is not disabled in effective sshd -T output"
fi

# RULE178:
if sec_audit_sshd_t_grep -iq 'ignorerhosts yes'; then
sec_audit_report_pass 178 "sshd IgnoreRhosts is enabled"
else
sec_audit_report_fail 178 "sshd IgnoreRhosts is not enabled in effective sshd -T output"
fi

# RULE179:
if sec_audit_sshd_t_grep -Piq 'kexalgorithms\h+([^#\n\r]+,)?(diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1)\b'; then
sec_audit_report_fail 179 "sshd KexAlgorithms does not meet the required policy (see sshd -T)"
else
sec_audit_report_pass 179 "sshd KexAlgorithms is configured"
fi

# RULE180:
if sec_audit_sshd_t_grep -Piq 'logingracetime\s+([1-9]|[1-5][0-9]|60)\b'; then
sec_audit_report_pass 180 "sshd LoginGraceTime is configured"
else
sec_audit_report_fail 180 "sshd LoginGraceTime does not meet the required policy (see sshd -T)"
fi

# RULE181:
if sec_audit_sshd_t_grep -iq 'loglevel VERBOSE\|loglevel INFO'; then
sec_audit_report_pass 181 "sshd LogLevel is configured"
else
sec_audit_report_fail 181 "sshd LogLevel does not meet the required policy (see sshd -T)"
fi

# RULE182:
if sec_audit_sshd_t_grep -Piq 'macs\h+([^#\n\r]+,)?(hmac-md5|hmac-md5-96|hmac-ripemd160|hmac-sha1-96|umac-64@openssh\.com|hmac-md5-etm@openssh\.com|hmac-md5-96-etm@openssh\.com|hmac-ripemd160-etm@openssh\.com|hmac-sha1-96-etm@openssh\.com|umac-64-etm@openssh\.com|umac-128-etm@openssh\.com)\b'; then
sec_audit_report_fail 182 "sshd MACs allow weak or legacy algorithms (see sshd -T)"
else
sec_audit_report_pass 182 "sshd MACs are configured"
fi

# RULE183:
if sec_audit_sshd_t_grep -Piq 'maxauthtries\s+[1-4]\b'; then
sec_audit_report_pass 183 "sshd MaxAuthTries is configured"
else
sec_audit_report_fail 183 "sshd MaxAuthTries does not meet the required policy (see sshd -T)"
fi

# RULE184:
if sec_audit_sshd_t_awk '$1 ~ /^\s*maxstartups/{split($2, a, ":");{if(a[1] <= 10 && a[2] <= 30 && a[3] <= 60) print "ok"}}' | grep -q "ok"; then
sec_audit_report_pass 184 "sshd MaxStartups is configured"
else
sec_audit_report_fail 184 "sshd MaxStartups does not meet the required policy (see sshd -T)"
fi

# RULE185:
if sec_audit_sshd_t_grep -Piq 'maxsessions\s+([1-9]|10)\b'; then
sec_audit_report_pass 185 "sshd MaxSessions is configured"
else
sec_audit_report_fail 185 "sshd MaxSessions does not meet the required policy (see sshd -T)"
fi

# RULE186:
if sec_audit_sshd_t_grep -iq 'permitemptypasswords no'; then
sec_audit_report_pass 186 "sshd PermitEmptyPasswords is disabled"
else
sec_audit_report_fail 186 "sshd PermitEmptyPasswords is not disabled in effective sshd -T output"
fi

# RULE187:
if sec_audit_sshd_t_grep -iq 'permitrootlogin no'; then
sec_audit_report_pass 187 "sshd PermitRootLogin is disabled"
else
sec_audit_report_fail 187 "sshd PermitRootLogin is not disabled in effective sshd -T output"
fi

# RULE188:
if sec_audit_sshd_t_grep -iq 'permituserenvironment no'; then
sec_audit_report_pass 188 "sshd PermitUserEnvironment is disabled"
else
sec_audit_report_fail 188 "sshd PermitUserEnvironment is not disabled in effective sshd -T output"
fi

# RULE189:
if sec_audit_sshd_t_grep -iq 'usepam yes'; then
sec_audit_report_pass 189 "sshd UsePAM is enabled"
else
sec_audit_report_fail 189 "sshd UsePAM is not enabled in effective sshd -T output"
fi

# RULE190:
if sec_audit_sshd_t_grep -Piq 'kexalgorithms\h+([^#\n\r]+,)?mlkem768x25519-sha256\b' 2>/dev/null; then
sec_audit_report_pass 190 "sshd post-quantum cryptography key exchange algorithms are configured"
elif sec_audit_sshd_t_grep -Piq 'kexalgorithms\h+([^#\n\r]+,)?(sntrup761x25519-sha512|kyber-512r3-sha256-algid)\b' 2>/dev/null; then
sec_audit_report_pass 190 "sshd post-quantum cryptography key exchange algorithms are configured"
else
sec_audit_report_fail 190 "sshd post-quantum KexAlgorithm (mlkem768x25519-sha256 or equivalent) is not configured"
fi

# RULE191:
if sec_audit_sshd_t_grep -Piq '^\h*listenaddress\h+\S+' 2>/dev/null; then
sec_audit_report_pass 191 "sshd ListenAddress is configured"
else
sec_audit_report_fail 191 "sshd ListenAddress is not explicitly configured (see sshd -T)"
fi

fi

# RULE192:
if rpm -q sudo &>/dev/null; then
sec_audit_report_pass 192 "sudo is installed"
else
sec_audit_report_fail 192 "sudo package is not installed"
fi

# RULE193:
if grep -rPiq '^\h*Defaults\h+([^#\n\r]+,\h*)?use_pty\b' /etc/sudoers /etc/sudoers.d 2>/dev/null \
    && ! grep -rPiq '^\h*Defaults\h+([^#\n\r]+,\h*)?!use_pty\b' /etc/sudoers /etc/sudoers.d 2>/dev/null; then
sec_audit_report_pass 193 "sudo commands use pty"
else
sec_audit_report_fail 193 "sudo is not configured to require a pseudo-terminal (use_pty)"
fi

# RULE194:
if grep -rPsiq "^\h*Defaults\h+([^#]+,\h*)?logfile\h*=\h*(\"|\')?\H+(\"|\')?(,\h*\H+\h*)*\h*(#.*)?$" /etc/sudoers /etc/sudoers.d 2>/dev/null; then
sec_audit_report_pass 194 "sudo log file exists"
else
sec_audit_report_fail 194 "sudo log file is missing or not configured"
fi

# RULE195:
if grep -rE '^[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | grep -vE '^\s*#' | grep -q .; then
sec_audit_report_fail 195 "NOPASSWD or password-less sudo rules violate escalation policy"
else
sec_audit_report_pass 195 "users must provide password for escalation"
fi

# RULE196:
if grep -rPiq '^\h*Defaults\h+([^#\n\r]+,\h*)?!authenticate\b' /etc/sudoers /etc/sudoers.d 2>/dev/null; then
sec_audit_report_fail 196 "sudo re-authentication is globally disabled (!authenticate found in sudoers)"
else
sec_audit_report_pass 196 "re-authentication for privilege escalation is not disabled globally"
fi

# RULE197:
TIMEOUT=$(timeout 5 sudo -V 2>/dev/null | grep "Authentication timestamp timeout:" | awk '{print $4}')
TIMEOUT_INT=${TIMEOUT%%.*}
if [ -n "$TIMEOUT_INT" ]; then
if [ "$TIMEOUT_INT" -ge 0 ] && [ "$TIMEOUT_INT" -le 15 ]; then
    sec_audit_report_pass 197 "sudo timestamp_timeout is configured"
else
    sec_audit_report_fail 197 "sudo timestamp_timeout is not set within the required range"
fi
else
sec_audit_report_pass 197 "sudo timestamp_timeout is configured"
fi

# RULE198:
if grep -Pi '^\h*auth\h+(?:required|requisite)\h+pam_wheel\.so\h+(?:[^#\n\r]+\h+)?((?!\2)(use_uid\b|group=\H+\b))\h+(?:[^#\n\r]+\h+)?((?!\1)(use_uid\b|group=\H+\b))(\h+.*)?$' /etc/pam.d/su 2>/dev/null; then
GROUP=$(grep -Pi '^\h*auth\h+(?:required|requisite)\h+pam_wheel\.so\h+(?:[^#\n\r]+\h+)?((?!\2)(use_uid\b|group=\H+\b))\h+(?:[^#\n\r]+\h+)?((?!\1)(use_uid\b|group=\H+\b))(\h+.*)?$' /etc/pam.d/su 2>/dev/null | grep -oP 'group=\K\H+')
if [ -n "$GROUP" ]; then
    if ! grep "^$GROUP:" /etc/group 2>/dev/null | grep -q ":$GROUP:x:"; then
        sec_audit_report_pass 198 "access to the su command is restricted"
    else
        sec_audit_report_fail 198 "su is not restricted to the wheel group in PAM configuration"
    fi
else
    sec_audit_report_pass 198 "access to the su command is restricted"
fi
else
sec_audit_report_fail 198 "su is not restricted to the wheel group in PAM configuration"
fi

# RULE199:
ACTIVE_PROFILE=$(head -1 /etc/authselect/authselect.conf 2>/dev/null)
if [ -z "$ACTIVE_PROFILE" ]; then
sec_audit_report_fail 199 "active authselect profile does not include required pam modules"
elif sec_audit_have_bin authselect && ! authselect check &>/dev/null; then
sec_audit_report_fail 199 "authselect reports configuration drift (run authselect check / apply changes)"
elif grep -P -- '\b(pam_pwquality\.so|pam_pwhistory\.so|pam_faillock\.so|pam_unix\.so)\b' /etc/authselect/"$ACTIVE_PROFILE"/{system,password}-auth 2>/dev/null; then
sec_audit_report_pass 199 "active authselect profile includes pam modules (authselect check OK)"
else
sec_audit_report_fail 199 "active authselect profile does not include required pam modules"
fi

# RULE200:
if grep -Psi 'deny\h*=\h*[1-5]\b' /etc/security/faillock.conf 2>/dev/null; then
sec_audit_report_pass 200 "password failed attempts lockout is configured"
else
sec_audit_report_fail 200 "faillock deny threshold is not configured in /etc/security/faillock.conf"
fi

# RULE201:
if grep -Psi 'unlock_time\h*=\h*(0|9[0-9][0-9]|[1-9][0-9]{3,})\b' /etc/security/faillock.conf 2>/dev/null; then
sec_audit_report_pass 201 "password unlock time is configured"
else
sec_audit_report_fail 201 "faillock unlock_time is not set within the required range"
fi

# RULE202:
if grep -Psi '^\h*even_deny_root\b' /etc/security/faillock.conf 2>/dev/null | grep -q .; then
sec_audit_report_pass 202 "password failed attempts lockout includes root account"
else
sec_audit_report_fail 202 "faillock even_deny_root is not set in /etc/security/faillock.conf"
fi

# RULE203:
if ! grep -Psi '^\h*dictcheck\h*=\h*0\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null | grep -q .; then
sec_audit_report_pass 203 "password dictionary check is enabled"
else
sec_audit_report_fail 203 "pwquality dictcheck is disabled (dictcheck=0 found)"
fi

# RULE204:
if grep -Psi '^\h*minlen\h*=\h*(1[4-9]|[2-9][0-9]|[1-9][0-9]{2,})\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null; then
sec_audit_report_pass 204 "password length is configured"
else
sec_audit_report_fail 204 "pwquality minlen (or equivalent) is not set to at least 14"
fi

# RULE205:
if grep -Psi '^\h*(minclass|[dulo]credit)\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null; then
sec_audit_report_pass 205 "password complexity is configured"
else
sec_audit_report_fail 205 "pwquality complexity (minclass/credits) is not configured"
fi

# RULE206:
if grep -Psi '^\h*(minclass\h*=\h*[4-9]|[dulo]credit\h*=\h*-[1-9])' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null | grep -q .; then
sec_audit_report_pass 206 "password complexity is configured"
else
sec_audit_report_fail 206 "pwquality complexity (minclass>=4 or credits) not configured adequately"
fi
}

sec_audit_run_aide() {
# RULE207:
if grep -Psi '^\h*maxrepeat\h*=\h*[1-3]\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null | grep -q .; then
sec_audit_report_pass 207 "password same consecutive characters is configured"
else
sec_audit_report_fail 207 "pwquality maxrepeat (max consecutive chars) is not configured"
fi

# RULE208:
if ! grep -Psi '^\h*dictcheck\h*=\h*0\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null; then
sec_audit_report_pass 208 "password dictionary check is enabled"
else
sec_audit_report_fail 208 "pwquality dictcheck is disabled or weak"
fi
}

sec_audit_run_logging() {
# RULE209:
if grep -Psi '\h*enforce_for_root\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null; then
sec_audit_report_pass 209 "password quality is enforced for the root user"
else
sec_audit_report_fail 209 "pwquality enforce_for_root is not set"
fi

# RULE210:
if grep -Psi 'remember\h*=\h*(2[4-9]|[3-9][0-9]|[1-9][0-9]{2,})\b' /etc/security/pwhistory.conf 2>/dev/null; then
sec_audit_report_pass 210 "password history remember is configured"
elif sec_audit_pam_stacks_grep_Pi '^\h*password\h+([^#\n\r]+)\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?remember=[0-9]+'; then
_r=$(sec_audit_pam_stack_paths_password_system | while IFS= read -r _p; do
    [[ -f "$_p" ]] || continue
    grep -Po 'remember=\K[0-9]+' "$_p" 2>/dev/null | head -n1 && break
done)
if [[ "${_r:-0}" -ge 24 ]]; then
    sec_audit_report_pass 210 "password history remember is configured (authselect/PAM stack)"
else
    sec_audit_report_fail 210 "pwhistory remember value is below policy or not configured"
fi
else
sec_audit_report_fail 210 "pwhistory remember value is below policy or not configured"
fi
# RULE211:
if grep -Psi 'enforce_for_root\b' /etc/security/pwhistory.conf 2>/dev/null; then
sec_audit_report_pass 211 "password history is enforced for the root user"
else
sec_audit_report_fail 211 "pwhistory enforce_for_root is not set"
fi

# RULE212:
if sec_audit_pam_stacks_grep_P '^\h*password\h+([^#\n\r]+)\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?use_authtok\b'; then
sec_audit_report_pass 212 "pam_pwhistory includes use_authtok"
else
sec_audit_report_fail 212 "pam_pwhistory line lacks use_authtok on password-auth/system-auth stack"
fi
# RULE213:
if ! sec_audit_pam_auth_stacks_grep_Pi '^\h*auth\h+.*pam_unix\.so.*nullok'; then
sec_audit_report_pass 213 "pam_unix does not include nullok"
else
sec_audit_report_fail 213 "pam_unix still allows nullok in the auth stack"
fi
# RULE214:
if ! sec_audit_pam_stacks_grep_Pi '^\h*password\h+([^#\n\r]+)\h+pam_unix\.so.*remember='; then
sec_audit_report_pass 214 "pam_unix does not include remember"
else
sec_audit_report_fail 214 "pam_unix password line still uses remember="
fi
# RULE215:
if grep -P '^\h*password\h+([^#\n\r]+)\h+pam_unix\.so\b' /etc/pam.d/common-password 2>/dev/null | grep -Piq '(sha512|yescrypt|blowfish|gost_yescrypt|scrypt|bcrypt)\b'; then
sec_audit_report_pass 215 "pam_unix includes a strong password hashing algorithm"
else
sec_audit_report_fail 215 "pam_unix password line does not specify a strong hashing algorithm (sha512/yescrypt)"
fi

# RULE216:
if sec_audit_pam_stacks_grep_P '^\h*password\h+([^#\n\r]+)\h+pam_unix\.so\h+([^#\n\r]+\h+)?use_authtok\b'; then
sec_audit_report_pass 216 "pam_unix includes use_authtok"
else
sec_audit_report_fail 216 "pam_unix password line lacks use_authtok on password-auth/system-auth stack"
fi
# RULE217:
if grep -Psi '^\h*PASS_MAX_DAYS\h+(36[0-5]|3[0-5][0-9]|[1-2][0-9][0-9]|[1-9][0-9]|[1-9])\b' /etc/login.defs 2>/dev/null; then
if ! awk -F: '($2~/^\$.+\$/) {if($5 > 365 || $5 < 1)print}' /etc/shadow 2>/dev/null | grep -q '.'; then
    sec_audit_report_pass 217 "password expiration is configured"
else
    sec_audit_report_fail 217 "PASS_MAX_DAYS or per-user shadow MAX exceeds policy or is unset"
fi
else
sec_audit_report_fail 217 "PASS_MAX_DAYS or per-user shadow MAX exceeds policy or is unset"
fi

# RULE218:
if grep -q "^PASS_MIN_DAYS" /etc/login.defs 2>/dev/null; then
MIN_DAYS=$(grep "^PASS_MIN_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
if [ "$MIN_DAYS" -ge 7 ] 2>/dev/null; then
    sec_audit_report_pass 218 "Minimum password days is configured"
else
    sec_audit_report_fail 218 "Minimum password days is too low (recommended 7+)"
fi
else
sec_audit_report_fail 218 "Minimum password days is not configured"
fi

# RULE219:
if grep -Psi '^\h*PASS_WARN_AGE\h+([7-9]|[1-9][0-9]+)\b' /etc/login.defs 2>/dev/null; then
if ! awk -F: '($2~/^\$.+\$/) {if($6 < 7)print}' /etc/shadow 2>/dev/null | grep -q '.'; then
    sec_audit_report_pass 219 "password expiration warning days is configured"
else
    sec_audit_report_fail 219 "PASS_WARN_AGE is not set within policy in /etc/login.defs"
fi
else
sec_audit_report_fail 219 "PASS_WARN_AGE is not set within policy in /etc/login.defs"
fi

# RULE220:
if grep -Psi '^\h*ENCRYPT_METHOD\h+(SHA512|YESCRYPT)\b' /etc/login.defs 2>/dev/null; then
sec_audit_report_pass 220 "strong password hashing algorithm is configured"
else
sec_audit_report_fail 220 "ENCRYPT_METHOD in /etc/login.defs does not use a strong hashing algorithm"
fi

# RULE221:
if useradd -D 2>/dev/null | grep INACTIVE | cut -d= -f2 | grep -qE '^([1-9]|[1-4][0-9]|45)$'; then
if ! awk -F: '($2~/^\$.+\$/) {if($7 > 45 || $7 < 0)print}' /etc/shadow 2>/dev/null | grep -q '.'; then
    sec_audit_report_pass 221 "inactive password lock is configured"
else
    sec_audit_report_fail 221 "useradd INACTIVE or inactive lock policy is not configured"
fi
else
sec_audit_report_fail 221 "useradd INACTIVE or inactive lock policy is not configured"
fi

# RULE222:
FAIL222=0
while IFS=: read -r user pass last_change rest; do
if [ -n "$last_change" ] && [ "$last_change" -gt 0 ] 2>/dev/null; then
    current_date=$(date +%s)
    last_change_seconds=$((last_change * 86400))
    if [ "$last_change_seconds" -gt "$current_date" ]; then
        sec_audit_report_fail 222 "User $user has password change date in the future"
        FAIL222=1
    fi
fi
done < /etc/shadow 2>/dev/null
if [ $FAIL222 -eq 0 ]; then
sec_audit_report_pass 222 "All users last password change date is in the past"
fi

# RULE223:
if awk -F: '($3 == 0) { print $1 }' /etc/passwd 2>/dev/null | grep -qx "root"; then
if [ $(awk -F: '($3 == 0) { print $1 }' /etc/passwd 2>/dev/null | wc -l) -eq 1 ]; then
    sec_audit_report_pass 223 "root is the only UID 0 account"
else
    sec_audit_report_fail 223 "Multiple accounts with UID 0 exist in /etc/passwd"
fi
else
sec_audit_report_fail 223 "Multiple accounts with UID 0 exist in /etc/passwd"
fi

# RULE224:
if awk -F: '($1 !~ /^(sync|shutdown|halt|operator)/ && $4=="0") {print $1":"$4}' /etc/passwd 2>/dev/null | grep -q "root:0"; then
if [ $(awk -F: '($1 !~ /^(sync|shutdown|halt|operator)/ && $4=="0") {print}' /etc/passwd 2>/dev/null | wc -l) -eq 1 ]; then
    sec_audit_report_pass 224 "root is the only GID 0 account"
else
    sec_audit_report_fail 224 "Multiple users use GID 0 outside policy"
fi
else
sec_audit_report_fail 224 "Multiple users use GID 0 outside policy"
fi
}

sec_audit_run_auditd() {
# RULE225:
if awk -F: '$3=="0"{print $1":"$3}' /etc/group 2>/dev/null | grep -q "root:0"; then
if [ $(awk -F: '$3=="0"{print}' /etc/group 2>/dev/null | wc -l) -eq 1 ]; then
    sec_audit_report_pass 225 "group root is the only GID 0 group"
else
    sec_audit_report_fail 225 "Multiple groups share GID 0"
fi
else
sec_audit_report_fail 225 "Multiple groups share GID 0"
fi

# RULE226:
if passwd -S root 2>/dev/null | awk '$2 ~ /^(P|L)/' | grep -q "root"; then
sec_audit_report_pass 226 "root account access is controlled"
else
sec_audit_report_fail 226 "root SSH/console access restrictions are not configured as required"
fi

# RULE227:
FAIL227=0
ROOT_PATH=$(sudo -i echo "\$PATH" 2>/dev/null || echo "$PATH")
if echo "$ROOT_PATH" | grep -q "::"; then
sec_audit_report_fail 227 "Root PATH contains empty directory (::)"
FAIL227=1
fi
if echo "$ROOT_PATH" | grep -q "\.:"; then
sec_audit_report_fail 227 "Root PATH contains current directory (.)"
FAIL227=1
fi
if [ $FAIL227 -eq 0 ]; then
sec_audit_report_pass 227 "Root path integrity is maintained"
fi

# RULE228:
if ! grep -Psi '^\h*umask\h+((\d{1,2}(\d[^7]|[^2-7]\d)\b)|(u=[rwx]{1,3},)?(((g=[rx]?[rx]?w[rx]?[rx]?\b)(,o=[rwx]{1,3})?)|((g=[wrx]{1,3},)?o=[wrx]{1,3}\b)))' /root/.bash_profile /root/.bashrc 2>/dev/null; then
sec_audit_report_pass 228 "root user umask is configured"
else
sec_audit_report_fail 228 "root umask is not 027 (or stricter) in profile scripts"
fi

# RULE229:
VALID_SHELLS=$(awk -F\/ '$NF != "nologin" && $NF != "false" {print}' /etc/shells 2>/dev/null | sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' -)
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs 2>/dev/null)
if awk -v pat="^($VALID_SHELLS)$" -v uidmin="$UID_MIN" -F: '($1!~/^(root|halt|sync|shutdown|nfsnobody)$/ && ($3<uidmin || $3==65534) && $NF ~ pat) {print}' /etc/passwd 2>/dev/null | grep -q '.'; then
sec_audit_report_fail 229 "System accounts still have an interactive login shell"
else
sec_audit_report_pass 229 "system accounts do not have a valid login shell"
fi

# RULE230:
VALID_SHELLS=$(awk -F\/ '$NF != "nologin" && $NF != "false" {print}' /etc/shells 2>/dev/null | sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' -)
FAIL230=0
while IFS= read -r l_user; do
if passwd -S "$l_user" 2>/dev/null | awk '$2 !~ /^L/ {print "found"}' | grep -q "found"; then
    sec_audit_report_fail 230 "Accounts without a valid shell are not locked in /etc/shadow"
    FAIL230=1
    break
fi
done <<< "$(awk -v pat="^($VALID_SHELLS)$" -F: '($1 != "root" && $NF !~ pat) {print $1}' /etc/passwd 2>/dev/null)"
if [ $FAIL230 -eq 0 ]; then
sec_audit_report_pass 230 "accounts without a valid login shell are locked"
fi

# RULE231:
if grep -Ps '^\h*([^#\n\r]+)?\/nologin\b' /etc/shells 2>/dev/null; then
sec_audit_report_fail 231 "nologin appears in /etc/shells"
else
sec_audit_report_pass 231 "nologin is not listed in /etc/shells"
fi

# RULE232:
if grep -Psi '^([^#\n\r]+)?\bTMOUT=(9[0-9]{1,2}|[1-9][0-9]|[1-9])\b' /etc/*bashrc /etc/profile /etc/profile.d/*.sh 2>/dev/null; then
sec_audit_report_pass 232 "default user shell timeout is configured"
else
sec_audit_report_fail 232 "TMOUT is not set for interactive shells in /etc/profile or profile.d"
fi

# RULE233:
if grep -Psi '^\h*umask\h+0?(?:[0-7][2-7]7)\b' /etc/login.defs 2>/dev/null; then
if grep -Psi '^\h*umask\h+0?027\b' /etc/profile.d/*.sh 2>/dev/null; then
    sec_audit_report_pass 233 "default user umask is configured"
else
    sec_audit_report_fail 233 "Default user umask 027 is not set in /etc/profile or profile.d"
fi
else
sec_audit_report_fail 233 "Default user umask 027 is not set in /etc/profile or profile.d"
fi

# RULE234:
if grep -Psi '^\h*umask\h+(0?27|0?077)\b' /etc/profile.d/*.sh 2>/dev/null | grep -q .; then
sec_audit_report_pass 234 "default user umask in /etc/profile.d is configured"
else
sec_audit_report_fail 234 "default user umask (027 or stricter) is not set in /etc/profile.d/*.sh"
fi

# RULE235:
if systemctl is-active systemd-journald.service 2>/dev/null | grep -q '^active'; then
sec_audit_report_pass 235 "journald service is active"
else
sec_audit_report_fail 235 "systemd-journald service is not active"
fi

# RULE236:
if systemctl is-active systemd-journal-remote.service 2>/dev/null | grep -q '^active' || \
   systemctl is-enabled systemd-journal-remote.service 2>/dev/null | grep -q 'enabled'; then
sec_audit_report_fail 236 "systemd-journal-remote service is active or enabled"
else
sec_audit_report_pass 236 "systemd-journal-remote service is not in use"
fi

# RULE237:
if systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -Eq '^Compress=yes'; then
sec_audit_report_pass 237 "journald Compress is configured"
elif ! systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -Eq '^Compress=no'; then
sec_audit_report_pass 237 "journald Compress is configured (default is yes)"
else
sec_audit_report_fail 237 "journald Compress is explicitly set to no"
fi

# RULE238:
if systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -Eq '^Storage=persistent'; then
sec_audit_report_pass 238 "journald Storage is configured"
else
sec_audit_report_fail 238 "journald Storage=persistent is not set in merged config"
fi

# RULE239:
if systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -Eq '^ForwardToSyslog=yes'; then
sec_audit_report_pass 239 "journald is configured to send logs to rsyslog"
else
sec_audit_report_fail 239 "journald ForwardToSyslog=yes is not set"
fi

# RULE240:
if systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -Eq '^(SystemMaxUse|SystemMaxFileSize|MaxFileSec|MaxRetentionSec)='; then
sec_audit_report_pass 240 "journald log file rotation is configured"
else
sec_audit_report_fail 240 "journald log rotation settings (SystemMaxUse/SystemMaxFileSize etc.) are not configured"
fi

# RULE241:
if [ -d /var/log/journal ]; then
DIR_PERM=$(stat -c '%a' /var/log/journal 2>/dev/null)
if echo "$DIR_PERM" | grep -qE '^(755|750|700)$'; then
    sec_audit_report_pass 241 "journald log file access is configured (mode: $DIR_PERM)"
else
    sec_audit_report_fail 241 "journald log directory /var/log/journal has insecure permissions: $DIR_PERM"
fi
else
sec_audit_report_pass 241 "journald log file access is configured (persistent dir not present)"
fi

# RULE242:
if rpm -q rsyslog &>/dev/null; then
sec_audit_report_pass 242 "rsyslog is installed"
else
sec_audit_report_fail 242 "rsyslog package is not installed"
fi

# RULE243:
if systemctl is-enabled rsyslog.service 2>/dev/null | grep -q 'enabled'; then
if systemctl is-active rsyslog.service 2>/dev/null | grep -q '^active'; then
    sec_audit_report_pass 243 "rsyslog service is enabled and active"
else
    sec_audit_report_fail 243 "rsyslog service is enabled but not active"
fi
else
sec_audit_report_fail 243 "rsyslog service is not enabled"
fi

# RULE244:
if systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -Eq '^ForwardToSyslog=yes'; then
sec_audit_report_pass 244 "journald is configured to send logs to rsyslog"
else
sec_audit_report_fail 244 "journald ForwardToSyslog=yes is not set in journald.conf"
fi

# RULE245:
if grep -Ps '^\h*\$FileCreateMode\h+0[0246][0246]0\b' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -q .; then
sec_audit_report_pass 245 "rsyslog log file creation mode is configured"
else
sec_audit_report_fail 245 "rsyslog \$FileCreateMode does not meet policy in rsyslog.conf"
fi

# RULE246:
if [ -f /etc/rsyslog.conf ] && grep -v "^#" /etc/rsyslog.conf 2>/dev/null | grep -qE '^\*\.\*|^auth|^mail|^cron'; then
sec_audit_report_pass 246 "rsyslog logging is configured"
else
sec_audit_report_fail 246 "rsyslog logging is not properly configured in rsyslog.conf"
fi

# RULE247:
if grep -Ps '^\h*([^#\n\r]+)?(@@|action\s*\(\s*type\s*=\s*"omfwd")' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -q .; then
sec_audit_report_pass 247 "rsyslog is configured to send logs to a remote log host"
else
sec_audit_report_fail 247 "rsyslog remote forwarding (@@host or omfwd) is not configured"
fi

# RULE248:
if grep -Ps '^\h*(module\s*\(\s*load\s*=\s*"imtcp"|module\s*\(\s*load\s*=\s*"imudp"|\$ModLoad\s+imtcp|\$ModLoad\s+imudp|UDPServerRun|TCPServerRun)' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -q .; then
sec_audit_report_fail 248 "rsyslog is configured to receive remote logs (imtcp/imudp listener found)"
else
sec_audit_report_pass 248 "rsyslog is not configured to receive logs from a remote client"
fi

# RULE249:
if command -v logrotate &>/dev/null; then
if [ -f /etc/logrotate.conf ] && grep -qE '^(rotate|daily|weekly|monthly)' /etc/logrotate.conf 2>/dev/null; then
    sec_audit_report_pass 249 "logrotate is configured"
else
    sec_audit_report_fail 249 "logrotate is installed but /etc/logrotate.conf does not contain rotation settings"
fi
else
sec_audit_report_fail 249 "logrotate is not installed"
fi

# RULE250:
if rpm -q rsyslog-gnutls &>/dev/null; then
sec_audit_report_pass 250 "rsyslog-gnutls is installed"
else
sec_audit_report_fail 250 "rsyslog-gnutls package is not installed"
fi

# RULE251:
if grep -Ps '^\h*\$DefaultNetstreamDriver\h+gtls\b' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -q .; then
sec_audit_report_pass 251 "rsyslog forwarding uses gtls"
elif grep -Ps 'StreamDriver\s*=\s*"gtls"' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -q .; then
sec_audit_report_pass 251 "rsyslog forwarding uses gtls (RainerScript format)"
else
sec_audit_report_fail 251 "rsyslog gtls stream driver is not configured"
fi

# RULE252:
if grep -Ps '^\h*\$DefaultNetstreamDriverCAFile\h+\S+' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -q .; then
sec_audit_report_pass 252 "rsyslog CA certificates are configured"
elif grep -Ps 'caFile\s*=' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -q .; then
sec_audit_report_pass 252 "rsyslog CA certificates are configured (RainerScript format)"
else
sec_audit_report_fail 252 "rsyslog CA certificate (\$DefaultNetstreamDriverCAFile or caFile) is not configured"
fi

# RULE253:
FAIL253=0
while IFS= read -r logfile; do
PERM=$(stat -c '%a' "$logfile" 2>/dev/null)
OWNER=$(stat -c '%U' "$logfile" 2>/dev/null)
if [ "${PERM:-999}" -gt 640 ] 2>/dev/null || { [ "$OWNER" != "root" ] && [ "$OWNER" != "syslog" ]; }; then
    FAIL253=1; break
fi
done < <(find /var/log -maxdepth 1 -type f 2>/dev/null)
if [ $FAIL253 -eq 0 ]; then
sec_audit_report_pass 253 "access to all logfiles has been configured"
else
sec_audit_report_fail 253 "one or more logfiles in /var/log have insecure permissions or wrong owner"
fi

# RULE254:
if systemctl is-enabled systemd-journald.service 2>/dev/null | grep -q 'static'; then
if systemctl is-active systemd-journald.service 2>/dev/null | grep -q 'active'; then
    sec_audit_report_pass 254 "journald service is active"
else
    sec_audit_report_fail 254 "systemd-journald is not active or not in expected state"
fi
else
sec_audit_report_fail 254 "systemd-journald is not active or not in expected state"
fi

# RULE255:
if [ -d /var/log/journal ]; then
DIR_PERM=$(stat -c '%a' /var/log/journal 2>/dev/null)
if [ "$DIR_PERM" = "755" ] || [ "$DIR_PERM" = "750" ]; then
    sec_audit_report_pass 255 "journald log file access is configured (directory mode: $DIR_PERM)"
else
    sec_audit_report_fail 255 "journald log directory has insecure permissions: $DIR_PERM"
fi
else
sec_audit_report_pass 255 "journald log file access is configured (directory not found)"
fi
}

sec_audit_run_identity_files() {
# RULE256:
if grep -q "^SystemMaxUse\|^SystemMaxFileSize\|^MaxFileSec" /etc/systemd/journald.conf 2>/dev/null; then
sec_audit_report_pass 256 "journald log file rotation is configured"
else
sec_audit_report_skip 256 "journald log file rotation using defaults (may be acceptable)"
fi

# RULE257:
if ! sec_audit_have_bin systemctl; then
sec_audit_report_skip 257 "systemctl unavailable; logging stack not evaluated"
elif systemctl is-active --quiet rsyslog 2>/dev/null; then
if systemctl is-active --quiet systemd-journald 2>/dev/null; then
    sec_audit_report_fail 257 "more than one logging system is in use (both rsyslog and journald are active)"
else
    sec_audit_report_pass 257 "only one logging system is in use (rsyslog)"
fi
elif systemctl is-active --quiet systemd-journald 2>/dev/null; then
sec_audit_report_pass 257 "only one logging system is in use (journald)"
else
sec_audit_report_fail 257 "no logging system is active (neither rsyslog nor journald)"
fi

# RULE258:
if grep -Ps '^\h*max_log_file\h*=\h*[1-9][0-9]*\b' /etc/audit/auditd.conf 2>/dev/null | grep -q .; then
sec_audit_report_pass 258 "audit log storage size is configured"
else
sec_audit_report_fail 258 "auditd max_log_file is not configured in /etc/audit/auditd.conf"
fi

# RULE259:
if systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -E '^ForwardToSyslog=no' | head -1 | grep -q "ForwardToSyslog=no"; then
sec_audit_report_pass 259 "journald ForwardToSyslog is disabled"
elif systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -E '^ForwardToSyslog=yes' | head -1 | grep -q "ForwardToSyslog=yes"; then
sec_audit_report_fail 259 "journald ForwardToSyslog is disabled (should be no)"
else
sec_audit_report_pass 259 "journald ForwardToSyslog is disabled (default)"
fi

# RULE260:
if systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -E '^Compress=yes' | head -1 | grep -q "Compress=yes"; then
sec_audit_report_pass 260 "journald Compress is configured"
else
sec_audit_report_pass 260 "journald Compress is configured (default)"
fi

# RULE261:
if systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -E '^Storage=persistent' | head -1 | grep -q "Storage=persistent"; then
sec_audit_report_pass 261 "journald Storage is configured"
else
sec_audit_report_fail 261 "journald Storage=persistent (or required value) is not set in merged config"
fi

# RULE262:
if rpm -q rsyslog &>/dev/null; then
sec_audit_report_pass 262 "rsyslog is installed"
else
sec_audit_report_fail 262 "rsyslog package is not installed"
fi

# RULE263:
if systemctl is-enabled rsyslog 2>/dev/null | grep -q 'enabled'; then
if systemctl is-active rsyslog.service 2>/dev/null | grep -q 'active'; then
    sec_audit_report_pass 263 "rsyslog service is enabled and active"
else
    sec_audit_report_fail 263 "rsyslog is not enabled or not active"
fi
else
sec_audit_report_fail 263 "rsyslog is not enabled or not active"
fi
}

sec_audit_run_filesystem_integrity() {
# RULE264:
if systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -E '^ForwardToSyslog=yes' | head -1 | grep -q "ForwardToSyslog=yes"; then
sec_audit_report_pass 264 "journald is configured to send logs to rsyslog"
else
sec_audit_report_fail 264 "journald ForwardToSyslog or forwarding to rsyslog is not configured"
fi

# RULE265:
if grep -Ps '^\h*\$FileCreateMode\h+0[0,2,4,6][0,2,4]0\b' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null; then
sec_audit_report_pass 265 "rsyslog log file creation mode is configured"
else
sec_audit_report_fail 265 "rsyslog $FileCreateMode (or equivalent) does not meet policy"
fi

# RULE266:
if command -v rsyslogd &>/dev/null; then
if [ -f /etc/rsyslog.conf ] && grep -v "^#" /etc/rsyslog.conf 2>/dev/null | grep -q "^\*\.\*\|^auth\|^mail\|^cron"; then
    sec_audit_report_pass 266 "rsyslog logging is configured"
else
    sec_audit_report_fail 266 "rsyslog logging is not properly configured"
fi
else
sec_audit_report_pass 266 "rsyslog is not installed"
fi

# RULE267:
if auditctl -l 2>/dev/null | grep -q '/etc/issue' || grep -r '/etc/issue' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q '\-w'; then
sec_audit_report_pass 267 "events that modify /etc/issue and /etc/issue.net are collected"
else
sec_audit_report_fail 267 "auditd watch rules for /etc/issue and /etc/issue.net are not configured"
fi

# RULE268:
if auditctl -l 2>/dev/null | grep -q '/etc/hosts' || grep -r '/etc/hosts' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q '\-w'; then
sec_audit_report_pass 268 "events that modify /etc/hosts and /etc/hostname are collected"
else
sec_audit_report_fail 268 "auditd watch rules for /etc/hosts and /etc/hostname are not configured"
fi

# RULE269:
if command -v logrotate &>/dev/null; then
if [ -f /etc/logrotate.conf ] && grep -q "^rotate\|^daily\|^weekly\|^monthly" /etc/logrotate.conf 2>/dev/null; then
    sec_audit_report_pass 269 "rsyslog logrotate is configured"
else
    sec_audit_report_fail 269 "rsyslog logrotate is not properly configured"
fi
else
sec_audit_report_fail 269 "logrotate is not installed"
fi

# RULE270:
MISSING270=0
while IFS= read -r cmd; do
if ! auditctl -l 2>/dev/null | grep -qF "$cmd" && ! grep -rqF "$cmd" /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null; then
    MISSING270=1; break
fi
done < <(find /bin /sbin /usr/bin /usr/sbin -xdev -perm /6000 -type f 2>/dev/null | head -20)
if [ $MISSING270 -eq 0 ]; then
sec_audit_report_pass 270 "use of privileged commands are collected"
else
sec_audit_report_fail 270 "some privileged SUID/SGID commands are not covered by auditd rules"
fi

# RULE271:
if auditctl -l 2>/dev/null | grep -Pq '\-a\s+always,exit.*\-S\s+(open|truncate|ftruncate|creat|openat).*\-F\s+exit=-EACCES' || \
   grep -rPq '\-a\s+always,exit.*\-S\s+(open|truncate|ftruncate|creat|openat).*\-F\s+exit=-EACCES' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null; then
sec_audit_report_pass 271 "unsuccessful file access attempts are collected"
else
sec_audit_report_fail 271 "auditd rules for unsuccessful file access (EACCES/EPERM) are not configured"
fi

# RULE272:
if auditctl -l 2>/dev/null | grep -q '/etc/group' || grep -r '/etc/group' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q '\-w'; then
sec_audit_report_pass 272 "events that modify /etc/group information are collected"
else
sec_audit_report_fail 272 "auditd watch rules for /etc/group are not configured"
fi

# RULE273:
if auditctl -l 2>/dev/null | grep -q '/etc/passwd' || grep -r '/etc/passwd' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q '\-w'; then
sec_audit_report_pass 273 "events that modify /etc/passwd information are collected"
else
sec_audit_report_fail 273 "auditd watch rules for /etc/passwd are not configured"
fi

# RULE274:
if (auditctl -l 2>/dev/null | grep -q '/etc/shadow' || grep -r '/etc/shadow' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q '\-w') && \
   (auditctl -l 2>/dev/null | grep -q '/etc/gshadow' || grep -r '/etc/gshadow' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q '\-w'); then
sec_audit_report_pass 274 "events that modify /etc/shadow and /etc/gshadow are collected"
else
sec_audit_report_fail 274 "auditd watch rules for /etc/shadow or /etc/gshadow are not configured"
fi

# RULE275:
if auditctl -l 2>/dev/null | grep -q '/etc/security/opasswd' || grep -r '/etc/security/opasswd' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q '\-w'; then
sec_audit_report_pass 275 "events that modify /etc/security/opasswd are collected"
else
sec_audit_report_fail 275 "auditd watch rules for /etc/security/opasswd are not configured"
fi

# RULE276:
if auditctl -l 2>/dev/null | grep -q '/etc/pam.d' || grep -r '/etc/pam.d' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q '\-w'; then
sec_audit_report_pass 276 "events that modify /etc/pam.d/ information are collected"
else
sec_audit_report_fail 276 "auditd watch rules for /etc/pam.d/ are not configured"
fi

# RULE277:
if auditctl -l 2>/dev/null | grep -Pq '\-a\s+always,exit.*\-S\s+(chmod|fchmod|fchmodat|fchmodat2)' || \
   grep -rPq '\-a\s+always,exit.*\-S\s+(chmod|fchmod|fchmodat|fchmodat2)' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null; then
sec_audit_report_pass 277 "chmod/fchmod/fchmodat/fchmodat2 events are collected"
else
sec_audit_report_fail 277 "auditd rules for chmod/fchmod/fchmodat/fchmodat2 are not configured"
fi

# RULE278:
if auditctl -l 2>/dev/null | grep -Pq '\-a\s+always,exit.*\-S\s+(chown|fchown|lchown|fchownat)' || \
   grep -rPq '\-a\s+always,exit.*\-S\s+(chown|fchown|lchown|fchownat)' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null; then
sec_audit_report_pass 278 "chown/fchown/lchown/fchownat events are collected"
else
sec_audit_report_fail 278 "auditd rules for chown/fchown/lchown/fchownat are not configured"
fi

# RULE279:
if auditctl -l 2>/dev/null | grep -Pq '\-a\s+always,exit.*\-S\s+(setxattr|lsetxattr|fsetxattr|removexattr|lremovexattr|fremovexattr)' || \
   grep -rPq '\-a\s+always,exit.*\-S\s+(setxattr|lsetxattr|fsetxattr|removexattr|lremovexattr|fremovexattr)' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null; then
sec_audit_report_pass 279 "xattr modification/removal events are collected"
else
sec_audit_report_fail 279 "auditd rules for setxattr/removexattr syscalls are not configured"
fi

# RULE280:
if auditctl -l 2>/dev/null | grep -Pq '\-a\s+always,exit.*\-S\s+mount\b' || \
   grep -rPq '\-a\s+always,exit.*\-S\s+mount\b' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null; then
sec_audit_report_pass 280 "successful file system mounts are collected"
else
sec_audit_report_fail 280 "auditd rules for mount syscall are not configured"
fi

# RULE281:
if auditctl -l 2>/dev/null | grep -qE '/var/run/utmp|/var/log/wtmp|/var/log/btmp' || \
   grep -rE '/var/run/utmp|/var/log/wtmp|/var/log/btmp' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q '\-w'; then
sec_audit_report_pass 281 "session initiation information is collected"
else
sec_audit_report_fail 281 "auditd watch rules for utmp/wtmp/btmp are not configured"
fi

# RULE282:
if auditctl -l 2>/dev/null | grep -qE '/var/log/faillog|/var/log/lastlog' || \
   grep -rE 'faillog|lastlog' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q '\-w'; then
sec_audit_report_pass 282 "login and logout events are collected"
else
sec_audit_report_fail 282 "auditd watch rules for faillog/lastlog are not configured"
fi

# RULE283:
if auditctl -l 2>/dev/null | grep -Pq '\-a\s+always,exit.*\-S\s+unlink\b' || \
   grep -rPq '\-a\s+always,exit.*\-S\s+unlink\b' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null; then
sec_audit_report_pass 283 "unlink file deletion events by users are collected"
else
sec_audit_report_fail 283 "auditd rules for unlink syscall are not configured"
fi

# RULE284:
if auditctl -l 2>/dev/null | grep -Pq '\-a\s+always,exit.*\-S\s+rename\b' || \
   grep -rPq '\-a\s+always,exit.*\-S\s+rename\b' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null; then
sec_audit_report_pass 284 "rename file deletion events by users are collected"
else
sec_audit_report_fail 284 "auditd rules for rename syscall are not configured"
fi

# RULE285:
if auditctl -l 2>/dev/null | grep -qE '/etc/selinux|/usr/share/selinux|/etc/apparmor' || \
   grep -rE '/etc/selinux|/usr/share/selinux|/etc/apparmor' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q '\-w'; then
sec_audit_report_pass 285 "events that modify Mandatory Access Controls are collected"
else
sec_audit_report_fail 285 "auditd watch rules for MAC (SELinux/AppArmor) directories are not configured"
fi

# RULE286:
CHCON_PATH=$(command -v chcon 2>/dev/null)
if [ -n "$CHCON_PATH" ]; then
if auditctl -l 2>/dev/null | grep -qF "$CHCON_PATH" || grep -rqF "$CHCON_PATH" /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null; then
    sec_audit_report_pass 286 "attempts to use chcon command are collected"
else
    sec_audit_report_fail 286 "auditd rule for chcon command ($CHCON_PATH) is not configured"
fi
else
sec_audit_report_pass 286 "chcon not found; no rule needed"
fi

# RULE287:
SETFACL_PATH=$(command -v setfacl 2>/dev/null)
if [ -n "$SETFACL_PATH" ]; then
if auditctl -l 2>/dev/null | grep -qF "$SETFACL_PATH" || grep -rqF "$SETFACL_PATH" /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null; then
    sec_audit_report_pass 287 "attempts to use setfacl command are collected"
else
    sec_audit_report_fail 287 "auditd rule for setfacl command ($SETFACL_PATH) is not configured"
fi
else
sec_audit_report_pass 287 "setfacl not found; no rule needed"
fi

# RULE288:
CHACL_PATH=$(command -v chacl 2>/dev/null)
if [ -n "$CHACL_PATH" ]; then
if auditctl -l 2>/dev/null | grep -qF "$CHACL_PATH" || grep -rqF "$CHACL_PATH" /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null; then
    sec_audit_report_pass 288 "attempts to use chacl command are collected"
else
    sec_audit_report_fail 288 "auditd rule for chacl command ($CHACL_PATH) is not configured"
fi
else
sec_audit_report_pass 288 "chacl not found; no rule needed"
fi

# RULE289:
USERMOD_PATH=$(command -v usermod 2>/dev/null)
if [ -n "$USERMOD_PATH" ]; then
if auditctl -l 2>/dev/null | grep -qF "$USERMOD_PATH" || grep -rqF "$USERMOD_PATH" /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null; then
    sec_audit_report_pass 289 "attempts to use usermod command are collected"
else
    sec_audit_report_fail 289 "auditd rule for usermod command ($USERMOD_PATH) is not configured"
fi
else
sec_audit_report_fail 289 "usermod command not found"
fi

# RULE290:
if auditctl -l 2>/dev/null | grep -Pq '\-a\s+always,exit.*\-S\s+(init_module|finit_module|delete_module)' || \
   grep -rPq '\-a\s+always,exit.*\-S\s+(init_module|finit_module|delete_module)' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null || \
   auditctl -l 2>/dev/null | grep -qE '/sbin/insmod|/sbin/rmmod|/sbin/modprobe' || \
   grep -rE '/sbin/insmod|/sbin/rmmod|/sbin/modprobe' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q '\-w'; then
sec_audit_report_pass 290 "kernel module loading/unloading/modification is collected"
else
sec_audit_report_fail 290 "auditd rules for kernel module syscalls (init_module/finit_module/delete_module) are not configured"
fi

# RULE291:
if auditctl -l 2>/dev/null | grep -Pq '\-a\s+always,exit.*\-S\s+(init_module|finit_module)' || \
   grep -rPq '\-a\s+always,exit.*\-S\s+(init_module|finit_module)' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null; then
sec_audit_report_pass 291 "init_module and finit_module events are collected"
else
sec_audit_report_fail 291 "auditd rules for init_module and finit_module syscalls are not configured"
fi

# RULE292:
if auditctl -l 2>/dev/null | grep -Pq '\-a\s+always,exit.*\-S\s+delete_module\b' || \
   grep -rPq '\-a\s+always,exit.*\-S\s+delete_module\b' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null; then
sec_audit_report_pass 292 "delete_module events are collected"
else
sec_audit_report_fail 292 "auditd rules for delete_module syscall are not configured"
fi

# RULE293:
if auditctl -l 2>/dev/null | grep -Pq '\-a\s+always,exit.*\-S\s+(create_module|query_module)' || \
   grep -rPq '\-a\s+always,exit.*\-S\s+(create_module|query_module)' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null; then
sec_audit_report_pass 293 "create_module and query_module events are collected"
else
sec_audit_report_fail 293 "auditd rules for create_module and query_module syscalls are not configured"
fi

# RULE294:
if grep -Pq '^\h*-i\b' /etc/audit/rules.d/*.rules /etc/audit/audit.rules 2>/dev/null; then
sec_audit_report_pass 294 "audit configuration is loaded regardless of errors (-i flag present)"
else
sec_audit_report_fail 294 "audit rules do not include -i flag (continue loading on errors)"
fi

# RULE295:
if sec_audit_audit_rule_loaded_and_on_disk -- '-e 2'; then
sec_audit_report_pass 295 "the audit configuration is immutable (-e 2 loaded and on disk)"
elif sec_audit_audit_rules_files_grep -q -- '-e 2'; then
sec_audit_report_fail 295 "Immutable rule (-e 2) is on disk but not loaded (auditctl -l)"
elif sec_audit_auditctl_rules_grep -q -- '-e 2'; then
sec_audit_report_fail 295 "Immutable rule (-e 2) is loaded but missing from on-disk audit rules"
else
sec_audit_report_fail 295 "Immutable rule (-e 2) is missing from loaded and on-disk audit rules"
fi
# RULE296:
FAIL296=0
for logfile in /var/log/messages /var/log/secure /var/log/maillog /var/log/cron /var/log/boot.log; do
if [ -f "$logfile" ]; then
    PERM=$(stat -c '%a' "$logfile" 2>/dev/null)
    OWNER=$(stat -c '%U' "$logfile" 2>/dev/null)
    if [ "$PERM" -gt 640 ] 2>/dev/null || [ "$OWNER" != "root" ]; then
        sec_audit_report_fail 296 "$logfile has insecure permissions ($PERM) or owner ($OWNER)"
        FAIL296=1
    fi
fi
done
[ $FAIL296 -eq 0 ] && echo "RULE296= PASS: Access to all logfiles has been configured"

# RULE297:
AUDIT_LOG_DIR=$(grep -Ps '^\h*log_file\h*=' /etc/audit/auditd.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' | xargs dirname 2>/dev/null)
AUDIT_LOG_DIR="${AUDIT_LOG_DIR:-/var/log/audit}"
FAIL297=0
while IFS= read -r f; do
perm=$(stat -c '%a' "$f" 2>/dev/null)
if [ "${perm:-999}" -gt 600 ] 2>/dev/null; then FAIL297=1; break; fi
done < <(find "$AUDIT_LOG_DIR" -maxdepth 1 -type f -name "audit.log*" 2>/dev/null)
if [ $FAIL297 -eq 0 ]; then
sec_audit_report_pass 297 "audit log files mode is configured"
else
sec_audit_report_fail 297 "audit log files in $AUDIT_LOG_DIR have permissions > 600"
fi

# RULE298:
AUDIT_LOG_DIR2=$(grep -Ps '^\h*log_file\h*=' /etc/audit/auditd.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' | xargs dirname 2>/dev/null)
AUDIT_LOG_DIR2="${AUDIT_LOG_DIR2:-/var/log/audit}"
FAIL298=0
while IFS= read -r f; do
owner=$(stat -c '%U' "$f" 2>/dev/null)
if [ "$owner" != "root" ]; then FAIL298=1; break; fi
done < <(find "$AUDIT_LOG_DIR2" -maxdepth 1 -type f -name "audit.log*" 2>/dev/null)
if [ $FAIL298 -eq 0 ]; then
sec_audit_report_pass 298 "audit log files owner is configured"
else
sec_audit_report_fail 298 "audit log files in $AUDIT_LOG_DIR2 are not owned by root"
fi

# RULE299:
AUDIT_LOG_DIR3=$(grep -Ps '^\h*log_file\h*=' /etc/audit/auditd.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' | xargs dirname 2>/dev/null)
AUDIT_LOG_DIR3="${AUDIT_LOG_DIR3:-/var/log/audit}"
FAIL299=0
while IFS= read -r f; do
grp=$(stat -c '%G' "$f" 2>/dev/null)
if [ "$grp" != "root" ] && [ "$grp" != "adm" ]; then FAIL299=1; break; fi
done < <(find "$AUDIT_LOG_DIR3" -maxdepth 1 -type f -name "audit.log*" 2>/dev/null)
if [ $FAIL299 -eq 0 ]; then
sec_audit_report_pass 299 "audit log files group owner is configured"
else
sec_audit_report_fail 299 "audit log files in $AUDIT_LOG_DIR3 are not group-owned by root or adm"
fi

# RULE300:
FAIL300=0
while IFS= read -r f; do
perm=$(stat -c '%a' "$f" 2>/dev/null)
if [ "${perm:-999}" -gt 640 ] 2>/dev/null; then FAIL300=1; break; fi
done < <(find /etc/audit/ -maxdepth 2 -type f \( -name "*.conf" -o -name "*.rules" \) 2>/dev/null)
if [ $FAIL300 -eq 0 ]; then
sec_audit_report_pass 300 "audit configuration files mode is configured"
else
sec_audit_report_fail 300 "audit configuration files in /etc/audit/ have permissions > 640"
fi

# RULE301:
FAIL301=0
while IFS= read -r f; do
owner=$(stat -c '%U' "$f" 2>/dev/null)
if [ "$owner" != "root" ]; then FAIL301=1; break; fi
done < <(find /etc/audit/ -maxdepth 2 -type f \( -name "*.conf" -o -name "*.rules" \) 2>/dev/null)
if [ $FAIL301 -eq 0 ]; then
sec_audit_report_pass 301 "audit configuration files owner is configured"
else
sec_audit_report_fail 301 "audit configuration files in /etc/audit/ are not owned by root"
fi

# RULE302:
FAIL302=0
while IFS= read -r f; do
grp=$(stat -c '%G' "$f" 2>/dev/null)
if [ "$grp" != "root" ]; then FAIL302=1; break; fi
done < <(find /etc/audit/ -maxdepth 2 -type f \( -name "*.conf" -o -name "*.rules" \) 2>/dev/null)
if [ $FAIL302 -eq 0 ]; then
sec_audit_report_pass 302 "audit configuration files group owner is configured"
else
sec_audit_report_fail 302 "audit configuration files in /etc/audit/ are not group-owned by root"
fi

# RULE303:
FAIL303=0
for tool in /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules; do
[ -f "$tool" ] || continue
perm=$(stat -c '%a' "$tool" 2>/dev/null)
if [ "${perm:-999}" -gt 755 ] 2>/dev/null; then FAIL303=1; break; fi
done
if [ $FAIL303 -eq 0 ]; then
sec_audit_report_pass 303 "audit tools mode is configured"
else
sec_audit_report_fail 303 "one or more audit tools have permissions > 755"
fi

# RULE304:
FAIL304=0
for tool in /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules; do
[ -f "$tool" ] || continue
owner=$(stat -c '%U' "$tool" 2>/dev/null)
if [ "$owner" != "root" ]; then FAIL304=1; break; fi
done
if [ $FAIL304 -eq 0 ]; then
sec_audit_report_pass 304 "audit tools owner is configured"
else
sec_audit_report_fail 304 "one or more audit tools are not owned by root"
fi

# RULE305:
FAIL305=0
for tool in /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules; do
[ -f "$tool" ] || continue
grp=$(stat -c '%G' "$tool" 2>/dev/null)
if [ "$grp" != "root" ]; then FAIL305=1; break; fi
done
if [ $FAIL305 -eq 0 ]; then
sec_audit_report_pass 305 "audit tools group owner is configured"
else
sec_audit_report_fail 305 "one or more audit tools are not group-owned by root"
fi

# RULE306:
if rpm -q aide &>/dev/null; then
sec_audit_report_pass 306 "AIDE is installed"
else
sec_audit_report_fail 306 "aide package is not installed"
fi

# RULE307:
if systemctl is-enabled aidecheck.service 2>/dev/null | grep -q 'enabled' || \
   systemctl is-enabled aidecheck.timer 2>/dev/null | grep -q 'enabled' || \
   crontab -l -u root 2>/dev/null | grep -qi aide || \
   ls /etc/cron.d/aide /etc/cron.daily/aide /etc/cron.weekly/aide 2>/dev/null | grep -qi aide; then
sec_audit_report_pass 307 "filesystem integrity is regularly checked"
else
sec_audit_report_fail 307 "no aide cron job or systemd timer found for regular integrity checks"
fi

# RULE308:
if stat -Lc '%a' /etc/passwd 2>/dev/null | grep -qE '^[0-6]44$'; then
if stat -Lc '%U:%G' /etc/passwd 2>/dev/null | grep -q '^root:root$'; then
    sec_audit_report_pass 308 "access to /etc/passwd is configured"
else
    sec_audit_report_fail 308 "File /etc/passwd permissions or ownership not correct"
fi
else
sec_audit_report_fail 308 "File /etc/passwd permissions or ownership not correct"
fi

# RULE309:
if [ -e /etc/passwd- ]; then
if stat -Lc '%a' /etc/passwd- 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' /etc/passwd- 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 309 "access to /etc/passwd- is configured"
    else
        sec_audit_report_fail 309 "File /etc/passwd- permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 309 "File /etc/passwd- permissions or ownership not correct"
fi
else
sec_audit_report_pass 309 "/etc/passwd- is absent (optional file; permission check skipped)"
fi

# RULE310:
if stat -Lc '%a' /etc/group 2>/dev/null | grep -qE '^[0-6]44$'; then
if stat -Lc '%U:%G' /etc/group 2>/dev/null | grep -q '^root:root$'; then
    sec_audit_report_pass 310 "access to /etc/group is configured"
else
    sec_audit_report_fail 310 "File /etc/group permissions or ownership not correct"
fi
else
sec_audit_report_fail 310 "File /etc/group permissions or ownership not correct"
fi

# RULE311:
if [ -e /etc/group- ]; then
if stat -Lc '%a' /etc/group- 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' /etc/group- 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 311 "access to /etc/group- is configured"
    else
        sec_audit_report_fail 311 "File /etc/group- permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 311 "File /etc/group- permissions or ownership not correct"
fi
else
sec_audit_report_pass 311 "/etc/group- is absent (optional file; permission check skipped)"
fi

# RULE312:
if stat -Lc '%a' /etc/shadow 2>/dev/null | grep -qE '^[0-6]40$'; then
if stat -Lc '%U' /etc/shadow 2>/dev/null | grep -q 'root'; then
    if stat -Lc '%G' /etc/shadow 2>/dev/null | grep -qE 'root|shadow'; then
        sec_audit_report_pass 312 "access to /etc/shadow is configured"
    else
        sec_audit_report_fail 312 "File /etc/shadow permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 312 "File /etc/shadow permissions or ownership not correct"
fi
else
sec_audit_report_fail 312 "File /etc/shadow permissions or ownership not correct"
fi

# RULE313:
if [ -e /etc/shadow- ]; then
if stat -Lc '%a' /etc/shadow- 2>/dev/null | grep -qE '^[0-6]40$'; then
    if stat -Lc '%U' /etc/shadow- 2>/dev/null | grep -q 'root'; then
        if stat -Lc '%G' /etc/shadow- 2>/dev/null | grep -qE 'root|shadow'; then
            sec_audit_report_pass 313 "access to /etc/shadow- is configured"
        else
            sec_audit_report_fail 313 "File /etc/shadow- permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 313 "File /etc/shadow- permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 313 "File /etc/shadow- permissions or ownership not correct"
fi
else
sec_audit_report_pass 313 "/etc/shadow- is absent (optional file; permission check skipped)"
fi

# RULE314:
if [ -e /etc/gshadow ]; then
if stat -Lc '%a' /etc/gshadow 2>/dev/null | grep -qE '^[0-6]40$'; then
    if stat -Lc '%U' /etc/gshadow 2>/dev/null | grep -q 'root'; then
        if stat -Lc '%G' /etc/gshadow 2>/dev/null | grep -qE 'root|shadow'; then
            sec_audit_report_pass 314 "access to /etc/gshadow is configured"
        else
            sec_audit_report_fail 314 "File /etc/gshadow permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 314 "File /etc/gshadow permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 314 "File /etc/gshadow permissions or ownership not correct"
fi
else
sec_audit_report_pass 314 "/etc/gshadow is absent (optional file; permission check skipped)"
fi

# RULE315:
if [ -e /etc/gshadow- ]; then
if stat -Lc '%a' /etc/gshadow- 2>/dev/null | grep -qE '^[0-6]40$'; then
    if stat -Lc '%U' /etc/gshadow- 2>/dev/null | grep -q 'root'; then
        if stat -Lc '%G' /etc/gshadow- 2>/dev/null | grep -qE 'root|shadow'; then
            sec_audit_report_pass 315 "access to /etc/gshadow- is configured"
        else
            sec_audit_report_fail 315 "File /etc/gshadow- permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 315 "File /etc/gshadow- permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 315 "File /etc/gshadow- permissions or ownership not correct"
fi
else
sec_audit_report_pass 315 "/etc/gshadow- is absent (optional file; permission check skipped)"
fi

# RULE316:
if stat -Lc '%a' /etc/shells 2>/dev/null | grep -qE '^[0-6]44$'; then
if stat -Lc '%U:%G' /etc/shells 2>/dev/null | grep -q '^root:root$'; then
    sec_audit_report_pass 316 "access to /etc/shells is configured"
else
    sec_audit_report_fail 316 "File /etc/shells permissions or ownership not correct"
fi
else
sec_audit_report_fail 316 "File /etc/shells permissions or ownership not correct"
fi

# RULE317:
if [ -e /etc/security/opasswd ]; then
if stat -Lc '%a' /etc/security/opasswd 2>/dev/null | grep -q '^600$'; then
    if stat -Lc '%U:%G' /etc/security/opasswd 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 317 "access to /etc/security/opasswd is configured"
    else
        sec_audit_report_fail 317 "File /etc/security/opasswd permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 317 "File /etc/security/opasswd permissions or ownership not correct"
fi
else
sec_audit_report_pass 317 "/etc/security/opasswd is absent (optional file; permission check skipped)"
fi

# RULE318:
CRITICAL_PATHS="/bin /sbin /usr/bin /usr/sbin /etc /var /home"
if sec_audit_low_impact_find_timed_out sec_audit_low_impact_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type f -perm -0002 -print; then
sec_audit_report_fail 318 "incomplete_scan: world-writable file search timed out under critical paths"
elif sec_audit_low_impact_find_timed_out sec_audit_low_impact_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type d -perm -0002 -print; then
sec_audit_report_fail 318 "incomplete_scan: world-writable directory search timed out under critical paths"
else
WW_FILES=$(sec_audit_low_impact_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type f -perm -0002 -print 2>/dev/null | wc -l)
WW_DIRS=$(sec_audit_low_impact_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type d -perm -0002 -print 2>/dev/null | wc -l)
if [ "$WW_FILES" -eq 0 ] && [ "$WW_DIRS" -eq 0 ]; then
    sec_audit_report_pass 318 "No critical world writable files or directories found"
else
    sec_audit_report_fail 318 "Found potential world-writable items ($WW_FILES files, $WW_DIRS dirs)"
fi
fi
# RULE319:
UNOWNED=$(sec_audit_low_impact_find --timeout=60 / -xdev -ignore_readdir_race \( -nouser -o -nogroup \) -type f -print 2>/dev/null | wc -l)
if [ "${UNOWNED:-0}" -eq 0 ]; then
sec_audit_report_pass 319 "no files or directories without an owner and a group exist"
else
sec_audit_report_fail 319 "$UNOWNED file(s)/dir(s) found without a valid owner or group"
fi

# RULE320:
if awk -F: '($2 != "x" ) { print }' /etc/passwd 2>/dev/null | grep -q '.'; then
sec_audit_report_fail 320 "Non-shadow password field found in /etc/passwd (second field not "x")"
else
sec_audit_report_pass 320 "accounts in /etc/passwd use shadowed passwords"
fi

# RULE321:
if awk -F: '($2 == "" ) { print }' /etc/shadow 2>/dev/null | grep -q '.'; then
sec_audit_report_fail 321 "Empty password hash found in /etc/shadow"
else
sec_audit_report_pass 321 "/etc/shadow password fields are not empty"
fi

# RULE322:
FAIL322=0
while IFS=: read -r user pass uid gid rest; do
if ! grep -q "^.*:.*:$gid:" /etc/group 2>/dev/null; then
    sec_audit_report_fail 322 "User $user has primary group GID $gid which does not exist in /etc/group"
    FAIL322=1
fi
done < /etc/passwd 2>/dev/null
[ $FAIL322 -eq 0 ] && echo "RULE322= PASS: All groups in /etc/passwd exist in /etc/group"

# RULE323:
if cut -f3 -d":" /etc/passwd 2>/dev/null | sort -n | uniq -c | while read -r count uid; do [ "$count" -gt 1 ] && echo "found"; done | grep -q "found"; then
sec_audit_report_fail 323 "Duplicate UID entries exist in /etc/passwd"
else
sec_audit_report_pass 323 "no duplicate UIDs exist"
fi

# RULE324:
if cut -f3 -d":" /etc/group 2>/dev/null | sort -n | uniq -c | while read -r count gid; do [ "$count" -gt 1 ] && echo "found"; done | grep -q "found"; then
sec_audit_report_fail 324 "Duplicate GID entries exist in /etc/group"
else
sec_audit_report_pass 324 "no duplicate GIDs exist"
fi

# RULE325:
if cut -f1 -d":" /etc/passwd 2>/dev/null | sort -n | uniq -c | while read -r count user; do [ "$count" -gt 1 ] && echo "found"; done | grep -q "found"; then
sec_audit_report_fail 325 "Duplicate user names exist in /etc/passwd"
else
sec_audit_report_pass 325 "no duplicate user names exist"
fi

# RULE326:
if cut -f1 -d":" /etc/group 2>/dev/null | sort -n | uniq -c | while read -r count group; do [ "$count" -gt 1 ] && echo "found"; done | grep -q "found"; then
sec_audit_report_fail 326 "Duplicate group names exist in /etc/group"
else
sec_audit_report_pass 326 "no duplicate group names exist"
fi

# RULE327:
FAIL327=0
while IFS=: read -r user pass uid gid gecos home shell; do
[ "${uid:-0}" -lt 1000 ] 2>/dev/null && continue
[ "${uid:-0}" -ge 65534 ] 2>/dev/null && continue
case "$shell" in /sbin/nologin|/usr/sbin/nologin|/bin/false) continue ;; esac
if [ -d "$home" ]; then
    PERM=$(stat -Lc '%a' "$home" 2>/dev/null)
    OWNER=$(stat -Lc '%U' "$home" 2>/dev/null)
    if [ "$OWNER" != "$user" ]; then FAIL327=1; break; fi
    if echo "$PERM" | grep -qE '.[2-7][0-9]'; then FAIL327=1; break; fi
else
    FAIL327=1; break
fi
done < /etc/passwd 2>/dev/null
if [ $FAIL327 -eq 0 ]; then
sec_audit_report_pass 327 "local interactive user home directories are configured"
else
sec_audit_report_fail 327 "one or more user home directories have wrong ownership or permissions"
fi

# RULE328:
FAIL328=0
while IFS=: read -r user pass uid gid rest; do
if [ "$uid" -ge 1000 ] 2>/dev/null && [ "$uid" -lt 65534 ]; then
    home=$(echo "$rest" | cut -d: -f1)
    for dotfile in "$home/.bashrc" "$home/.bash_profile" "$home/.profile" "$home/.bash_logout"; do
        if [ -f "$dotfile" ]; then
            perm=$(stat -c '%a' "$dotfile" 2>/dev/null)
            if [ "${perm:2:1}" -gt 0 ] 2>/dev/null || [ "${perm:1:1}" -gt 0 ] 2>/dev/null; then
                sec_audit_report_fail 328 "User $user dot file $dotfile has world/group write permissions ($perm)"
                FAIL328=1
            fi
        fi
    done
fi
done < /etc/passwd 2>/dev/null
if [ "${FAIL328:-0}" -eq 0 ]; then sec_audit_report_pass 328 "Local interactive user dot files access is configured"; fi

# RULE329:
if awk -F: '($2 != "" && $2 != "x") {print}' /etc/group 2>/dev/null | grep -q .; then
sec_audit_report_fail 329 "/etc/group contains non-empty password field(s)"
else
sec_audit_report_pass 329 "no passwords are stored in /etc/group"
fi
}

sec_audit_main() {
    sec_audit_run_kernel_modules
    sec_audit_run_filesystem_partitions
    sec_audit_run_package_security
    sec_audit_run_selinux
    sec_audit_run_bootloader
    sec_audit_run_process_hardening
    sec_audit_run_crypto_policy
    sec_audit_run_banners
    sec_audit_run_gdm
    sec_audit_run_aide
    sec_audit_run_logging
    sec_audit_run_auditd
    sec_audit_run_identity_files
    sec_audit_run_filesystem_integrity
    exit 0
}

sec_audit_main "$@"
