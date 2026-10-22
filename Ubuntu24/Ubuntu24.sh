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

UB24_FIND_CAP="${UB24_FIND_CAP:-20}"
UB24_CMD_CAP="${UB24_CMD_CAP:-12}"
UB24_APT_CAP="${UB24_APT_CAP:-30}"
UB24_ALLOW_CONTAINER_KMOD="${UB24_ALLOW_CONTAINER_KMOD:-${UBUNTU_CRE_ALLOW_CONTAINER_MODULES:-0}}"

# --- bootstrap / reporting ---
sec_audit_report_pass() { printf 'RULE%s= PASS: %s\n' "$1" "$2"; }
sec_audit_report_fail() { printf 'RULE%s= FAIL: %s\n' "$1" "${3:-$2}"; }
sec_audit_report_skip() { printf 'RULE%s= SKIP: %s\n' "$1" "$2"; }
sec_audit_report_error() { printf 'RULE%s= ERROR: %s\n' "$1" "$2"; }

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

sec_audit_dpkg_any_installed() {
    local pkg
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

sec_audit_pkg_is_installed() {
    sec_audit_dpkg_any_installed "$@" && return 0
    sec_audit_rpm_any_installed "$@" && return 0
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

# --- dnf / repos ---
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
    n=$(sec_audit_exec_with_timeout "$UB24_DNF_CAP" dnf -q repolist enabled 2>/dev/null | awk '
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

# --- auditd cache ---
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
        sysctl -n "$key" 2>/dev/null | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
        return 0
    fi
    # Fallback for minimal containers without procps-ng/sysctl.
    proc_path="/proc/sys/${key//.//}"
    if [[ -r $proc_path ]]; then
        val=$(tr -d '\r' <"$proc_path" 2>/dev/null | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
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
    if [[ -z "$r" ]]; then
        if ! sec_audit_have_bin sysctl && [[ ! -e /proc/sys/${key//.//} ]]; then
            sec_audit_report_error "$num" "cannot evaluate ${key}: sysctl binary missing and /proc/sys path absent"
        else
            sec_audit_report_fail "$num" "kernel ${key} is unreadable or unsupported on this kernel; expected ${want}${hint}"
        fi
        return 0
    fi
    if ! sec_audit_sysctl_runtime_equals "$key" "$want"; then
        sec_audit_report_fail "$num" "kernel ${key} is '${r}', expected ${want}${hint}"
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
    if [[ -z "$disk" ]]; then
        sec_audit_report_fail "$num" "kernel ${key}=${want} but no durable on-disk sysctl assignment found${hint}"
        return 0
    fi
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
    local pattern="$1" cap="${2:-$UB24_FIND_CAP}" rc=0 out=""
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
            [[ "${UB24_ALLOW_CONTAINER_KMOD}" == "1" ]]
            ;;
        *) return 1 ;;
    esac
}

sec_audit_assert_kmod_disabled() {
    local num="$1" label="$2" mod="$3" ko_pattern="$4"
    shift 4
    local alias loaded=0 a
    if sec_audit_kmod_container_exception "$mod"; then
        sec_audit_report_pass "$num" "${label} (waived: UB24_ALLOW_CONTAINER_KMOD=1)"
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
    sec_audit_report_fail "$num" "${label} is available on disk and not blocked (need blacklist or install /bin/false|/bin/true via modprobe.d)"
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
    if ! sec_audit_rpm_any_installed "$pkg"; then
        sec_audit_report_pass "$num" "$pass_msg"
    elif sec_audit_systemd_unit_live "$@"; then
        sec_audit_report_fail "$num" "$fail_msg"
    else
        sec_audit_report_pass "$num" "$pass_msg (package present but units masked/disabled/inactive)"
    fi
}

# --- files ---
sec_audit_path_mode_octal() {
    local raw
    raw=$(stat -Lc '%a' "$1" 2>/dev/null) || return 1
    [[ "$raw" =~ ^[0-7]+$ ]] || return 1
    # Normalize display/compare form to at least 3 octal digits (e.g. 0 -> 000).
    printf '%03d' "$((10#$raw))"
}
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
    local mode own
    if [[ ! -e $path ]]; then
        if [[ "$missing_ok" == "1" ]]; then
            sec_audit_report_pass "$num" "${pass_msg} (path absent)"
        else
            sec_audit_report_fail "$num" "${path} is missing"
        fi
        return 0
    fi
    if ! sec_audit_have_bin stat; then
        sec_audit_report_error "$num" "stat is required to evaluate permissions on ${path}"
        return 0
    fi
    mode=$(sec_audit_path_mode_octal "$path")
    if [[ ! "$mode" =~ ^[0-7]+$ ]]; then
        sec_audit_report_error "$num" "unable to read octal mode for ${path}"
        return 0
    fi
    if ! sec_audit_mode_within_max "$path" "$maxmode"; then
        sec_audit_report_fail "$num" "${path} mode ${mode} is more permissive than ${maxmode}"
        return 0
    fi
    # Also reject any group/world write bits when maxmode forbids them.
    if (( (8#$mode & 8#0022) != 0 )) && (( (8#$maxmode & 8#0022) == 0 )); then
        sec_audit_report_fail "$num" "${path} has group/world write bits (mode ${mode}); max allowed ${maxmode}"
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
        own=$(sec_audit_path_owner_pair "$path")
        if [[ "$own" != "$owner" ]]; then
            sec_audit_report_fail "$num" "${path} owner is ${own}, expected ${owner}"
            return 0
        fi
    fi
    sec_audit_report_pass "$num" "$pass_msg (mode ${mode}, owner $(sec_audit_path_owner_pair "$path"))"
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

sec_audit_gdm_installed() { sec_audit_pkg_is_installed gdm3 gdm; }

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

# --- high-level assert wrappers ---
sec_audit_assert_isolated_mount() {
    local num="$1" mp="$2" pass_msg="$3" kind="${4:-separate}"
    local ok=1 detail=""
    if ! sec_audit_findmnt_available; then
        sec_audit_report_error "$num" "findmnt is required to evaluate isolation of ${mp}"
        return 0
    fi
    if [[ "$kind" == "tmp" ]]; then
        sec_audit_tmp_is_isolated || ok=0
        detail="fstype=$(sec_audit_mount_fstype /tmp), source=$(sec_audit_mount_source /tmp)"
    elif [[ "$kind" == "shm" ]]; then
        sec_audit_shm_is_isolated || ok=0
        detail="fstype=$(sec_audit_mount_fstype /dev/shm), source=$(sec_audit_mount_source /dev/shm)"
    else
        sec_audit_path_is_isolated_volume "$mp" || ok=0
        detail="fstype=$(sec_audit_mount_fstype "$mp"), source=$(sec_audit_mount_source "$mp"), target=$(sec_audit_mount_is_dedicated "$mp" && echo dedicated || echo shared)"
    fi
    if [ "$ok" -eq 1 ]; then
        if sec_audit_mount_is_persisted "$mp"; then
            sec_audit_report_pass "$num" "$pass_msg (${detail})"
        else
            sec_audit_report_fail "$num" "${mp} isolation is runtime-only (missing fstab or systemd .mount persistence); ${detail}"
        fi
    else
        sec_audit_report_fail "$num" "${mp} is not a dedicated tmpfs/separate partition (${detail})"
    fi
}

sec_audit_assert_mount_option() {
    local num="$1" mp="$2" flag="$3"
    if ! sec_audit_findmnt_available; then
        sec_audit_report_error "$num" "findmnt is required to evaluate mount option ${flag} on ${mp}"
        return 0
    fi
    if ! sec_audit_mount_resolves "$mp"; then
        sec_audit_report_fail "$num" "${flag} is not set on ${mp} (path not resolvable / not an explicit mount)"
        return 0
    fi
    if ! sec_audit_path_is_isolated_volume "$mp" && [[ "$mp" != /tmp && "$mp" != /dev/shm ]]; then
        # For dedicated partitions (/home, /var, …) options only count on a true separate mount.
        if ! sec_audit_mount_is_dedicated "$mp"; then
            sec_audit_report_fail "$num" "${flag} cannot be verified on ${mp} because it is not a dedicated mount (opts: $(sec_audit_mount_options "$mp"))"
            return 0
        fi
    fi
    if ! sec_audit_mount_has_option "$mp" "$flag"; then
        sec_audit_report_fail "$num" "${flag} is not set on runtime mount ${mp} (opts: $(sec_audit_mount_options "$mp"))"
        return 0
    fi
    if [[ -f /etc/fstab ]] && grep -Pqs "[[:space:]]${mp//\//\\/}[[:space:]]" /etc/fstab \
        && ! sec_audit_fstab_has_option "$mp" "$flag"; then
        sec_audit_report_fail "$num" "${flag} is set at runtime on ${mp} but missing from fstab (not reboot-safe)"
        return 0
    fi
    sec_audit_report_pass "$num" "${flag} option set on ${mp}$(sec_audit_persistence_suffix "$mp")"
}

sec_audit_assert_package_absent() {
    local num="$1" pkg="$2" pass_msg="$3" fail_msg="$4"
    if sec_audit_rpm_any_installed "$pkg"; then
        sec_audit_report_fail "$num" "$fail_msg"
    else
        sec_audit_report_pass "$num" "$pass_msg"
    fi
}

# =============================================================================
# Rule section runners (RULE1 .. RULE276)
# =============================================================================

# --- Ubuntu-specific helpers ---
sec_audit_is_package_installed() {
  local package_name="$1"
  dpkg-query -W -f='${Status}' "$package_name" 2>/dev/null | grep -q '^install ok installed$'
}

sec_audit_is_service_active() {
  local service_name="$1"
  systemctl is-active "$service_name" 2>/dev/null | grep -q '^active$'
}

sec_audit_is_service_enabled() {
  local service_name="$1"
  systemctl is-enabled "$service_name" 2>/dev/null | grep -qE '^(enabled|enabled-runtime)$'
}

sec_audit_service_not_in_use() {
  local pkg="$1" unit="${2:-$1}"
  if sec_audit_is_package_installed "$pkg" && sec_audit_is_service_active "$unit"; then
    return 1
  fi
  return 0
}

sec_audit_kernel_mod_in_modules_load() {
  local pat="" a
  for a in "$@"; do
    pat+="${pat:+|}${a}"
  done
  grep -rqE "^[[:space:]]*(${pat})([[:space:]]|$)" /etc/modules-load.d /usr/lib/modules-load.d /run/modules-load.d 2>/dev/null
}

sec_audit__modprobe_blocked() {
  local mod="$1"
  if sec_audit_have_bin modprobe && modprobe --showconfig 2>/dev/null | grep -Pq "^\h*(blacklist|install)\h+${mod//-/_}\b"; then
    return 0
  fi
  if sec_audit_have_bin modprobe && modprobe --showconfig 2>/dev/null | grep -Pq "^\h*(blacklist|install)\h+${mod}\b"; then
    return 0
  fi
  local modprobe_out
  modprobe_out="$(modprobe -n -v "$mod" 2>&1)"
  echo "$modprobe_out" | grep -qE 'install /bin/(true|false)|Module .* not found'
}

sec_audit_req_kernel_module_not_available() {
  local num="$1" mod="$2" ko_glob="${3:-${mod}.ko*}" lsmod_pat="${4:-${mod//-/_}}"
  if sec_audit_kernel_mod_in_modules_load "$mod" "${mod//-/_}"; then
    echo "RULE${num}= FAIL: ${mod} kernel module is listed in modules-load.d (auto-load at boot)"
    return
  fi
  if ! sec_audit_soft_find --timeout=20 /usr/lib/modules/ /lib/modules/ -xdev -ignore_readdir_race -type f -name "$ko_glob" 2>/dev/null | grep -q .; then
    echo "RULE${num}= PASS: ${mod} kernel module is not available (no module object in kernel tree)"
    return
  fi
  if ! lsmod | grep -q "$lsmod_pat" && sec_audit__modprobe_blocked "$mod"; then
    echo "RULE${num}= PASS: ${mod} kernel module is disabled and not loaded"
  else
    echo "RULE${num}= FAIL: ${mod} kernel module is available, loaded, or not effectively blocked (modprobe blacklist/install)"
  fi
}

sec_audit_sysctl_key_runtime_raw() {
  sec_audit_have_bin sysctl || return 1
  sysctl -n "$1" 2>/dev/null | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

sec_audit_sysctl_key_runtime() {
  builtin printf '%s' "$(sec_audit_sysctl_key_runtime_raw "$1")"
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

sec_audit_sysctl_runtime_and_persistent_equals() {
  local key="$1" expected="$2"
  sec_audit_sysctl_runtime_equals "$key" "$expected" || return 1
  local disk
  disk=$(sec_audit_sysctl_files_last_assignment_value "$key")
  [[ -n "$disk" ]] && [[ "$disk" == "$expected" ]]
}

sec_audit__req_sysctl_dual_check() {
  local num="$1" k1="$2" w1="$3" k2="$4" w2="$5"
  if sec_audit_sysctl_runtime_and_persistent_equals "$k1" "$w1" && sec_audit_sysctl_runtime_and_persistent_equals "$k2" "$w2"; then
    echo "RULE${num}= PASS: ${k1}=${w1} and ${k2}=${w2} in kernel and persistent config"
  else
    echo "RULE${num}= FAIL: ${k1} and/or ${k2} not set to expected values in kernel and persistent config$(sec_audit_sysctl_runtime_disk_hint "$k1" "$w1")$(sec_audit_sysctl_runtime_disk_hint "$k2" "$w2")"
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

sec_audit_grub_cmdline_param_present() {
  local pat="$1"
  grep -qE "$pat" /proc/cmdline 2>/dev/null && return 0
  grep -qE "$pat" /etc/default/grub 2>/dev/null
}

sec_audit_apparmor_bootloader_enabled() {
  sec_audit_grub_cmdline_param_present 'apparmor=1' && sec_audit_grub_cmdline_param_present 'security=apparmor'
}

sec_audit__sshd_t_ensure() {
  [ "$_SSHD_T_READY" -eq 1 ] && return 0
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

sec_audit__auditctl_l_ensure() {
  [ "$_AUDITCTL_L_READY" -eq 1 ] && return 0
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

sec_audit__audit_rules_files_ensure() {
  [ "$_audit_rules_files_ready" -eq 1 ] && return 0
  _audit_rules_files_ready=1
  shopt -s nullglob
  _audit_rules_files_cache=$(cat /etc/audit/rules.d/*.rules /etc/audit/audit.rules 2>/dev/null)
  shopt -u nullglob
}

sec_audit_audit_rules_files_grep() {
  sec_audit__audit_rules_files_ensure
  builtin printf '%s\n' "$_audit_rules_files_cache" | grep "$@"
}

sec_audit_audit_rule_on_disk() {
  sec_audit__audit_rules_files_ensure
  builtin printf '%s\n' "$_audit_rules_files_cache" | grep -q "$@"
}

sec_audit_audit_rule_loaded_and_on_disk() {
  sec_audit__audit_rules_files_ensure
  sec_audit__auditctl_l_ensure
  builtin printf '%s\n' "$_audit_rules_files_cache" | grep -q "$@" || return 1
  builtin printf '%s\n' "$_auditctl_l_cache" | grep -q "$@" || return 1
  return 0
}

sec_audit_pam_stack_paths_common() {
  local f p
  for f in /etc/pam.d/common-auth /etc/pam.d/common-account /etc/pam.d/common-password /etc/pam.d/common-session; do
    [[ -e $f ]] || continue
    if sec_audit_have_bin readlink; then
      p=$(readlink -f "$f" 2>/dev/null || echo "$f")
    else
      p=$f
    fi
    builtin printf '%s\n' "$p"
  done | sort -u
}

sec_audit_pam_common_password_has_module() {
  local mod="$1" p
  for p in /etc/pam.d/common-password; do
    [[ -f $p ]] || continue
    grep -qE "^[[:space:]]*password[[:space:]].*${mod}" "$p" 2>/dev/null && return 0
  done
  return 1
}

sec_audit_apparmor_status_output() {
  if sec_audit_have_bin aa-status; then
    aa-status 2>/dev/null
  elif sec_audit_have_bin apparmor_status; then
    apparmor_status 2>/dev/null
  fi
}

sec_audit_apparmor_profiles_enforce_or_complain_ok() {
  local out unconfined
  out=$(sec_audit_apparmor_status_output) || return 1
  echo "$out" | grep -q 'profiles are loaded' || return 1
  unconfined=$(echo "$out" | awk '/profiles are in unconfined mode/{print $1+0}')
  [[ "${unconfined:-0}" -eq 0 ]]
}

sec_audit_apparmor_profiles_all_enforcing_ok() {
  local out complain kill
  out=$(sec_audit_apparmor_status_output) || return 1
  complain=$(echo "$out" | awk '/profiles are in complain mode/{print $1+0}')
  kill=$(echo "$out" | awk '/profiles are in kill mode/{print $1+0}')
  [[ "${complain:-0}" -eq 0 && "${kill:-0}" -eq 0 ]] && echo "$out" | grep -qE '[1-9][0-9]* profiles are in enforce mode'
}


# --- Ubuntu body compatibility aliases ---
sec_audit_list_local_system_mounts() { sec_audit_local_fs_roots; }
sec_audit_findmnt_have() { sec_audit_findmnt_available; }
sec_audit_findmnt_path_resolvable() { sec_audit_mount_resolves "$@"; }
sec_audit_findmnt_is_explicit_mountpoint() { sec_audit_mount_is_dedicated "$@"; }
sec_audit_findmnt_source_for() { sec_audit_mount_source "$@"; }
sec_audit_findmnt_fstype_for() { sec_audit_mount_fstype "$@"; }
sec_audit_findmnt_options_raw() { sec_audit_mount_options "$@"; }
sec_audit_findmnt_has_mnt_option() { sec_audit_mount_has_option "$@"; }
sec_audit_findmnt_tmp_sec_ok() { sec_audit_tmp_is_isolated; }
sec_audit_findmnt_shm_sec_ok() { sec_audit_shm_is_isolated; }
sec_audit_findmnt_separate_partition_ok() { sec_audit_path_is_isolated_volume "$@"; }
sec_audit_is_package_installed() { sec_audit_pkg_is_installed "$@"; }

# =============================================================================
# Section runners (RULE1 .. RULE277)
# =============================================================================

sec_audit_run_kernel_modules() {
    # RULE1-8
    sec_audit_req_kernel_module_not_available 1 cramfs

    sec_audit_req_kernel_module_not_available 2 freevxfs

    sec_audit_req_kernel_module_not_available 3 hfs

    sec_audit_req_kernel_module_not_available 4 hfsplus

    sec_audit_req_kernel_module_not_available 5 jffs2

    sec_audit_req_kernel_module_not_available 6 overlay

    sec_audit_req_kernel_module_not_available 7 squashfs

    sec_audit_req_kernel_module_not_available 8 usb-storage

}

sec_audit_run_filesystem_partitions() {
    # RULE9-34
    if sec_audit_findmnt_tmp_sec_ok; then
      sec_audit_report_pass 9 "/tmp is tmpfs or a separate partition"
    else
      sec_audit_report_fail 9 "/tmp does not meet tmpfs or separate-partition requirement"
    fi

    if sec_audit_findmnt_path_resolvable /tmp && sec_audit_findmnt_has_mnt_option /tmp nodev; then
      sec_audit_report_pass 10 "nodev option is set on /tmp"
    else
      sec_audit_report_fail 10 "nodev option is missing on /tmp"
    fi

    if sec_audit_findmnt_path_resolvable /tmp && sec_audit_findmnt_has_mnt_option /tmp nosuid; then
      sec_audit_report_pass 11 "nosuid option is set on /tmp"
    else
      sec_audit_report_fail 11 "nosuid option is missing on /tmp"
    fi

    if sec_audit_findmnt_path_resolvable /tmp && sec_audit_findmnt_has_mnt_option /tmp noexec; then
      sec_audit_report_pass 12 "noexec option is set on /tmp"
    else
      sec_audit_report_fail 12 "noexec option is missing on /tmp"
    fi

    if sec_audit_findmnt_shm_sec_ok; then
      sec_audit_report_pass 13 "/dev/shm is tmpfs or a separate partition"
    else
      sec_audit_report_fail 13 "/dev/shm does not meet tmpfs or separate-partition requirement"
    fi

    if sec_audit_findmnt_path_resolvable /dev/shm && sec_audit_findmnt_has_mnt_option /dev/shm nodev; then
      sec_audit_report_pass 14 "nodev option is set on /dev/shm"
    else
      sec_audit_report_fail 14 "nodev option is missing on /dev/shm"
    fi

    if sec_audit_findmnt_path_resolvable /dev/shm && sec_audit_findmnt_has_mnt_option /dev/shm nosuid; then
      sec_audit_report_pass 15 "nosuid option is set on /dev/shm"
    else
      sec_audit_report_fail 15 "nosuid option is missing on /dev/shm"
    fi

    if sec_audit_findmnt_path_resolvable /dev/shm && sec_audit_findmnt_has_mnt_option /dev/shm noexec; then
      sec_audit_report_pass 16 "noexec option is set on /dev/shm"
    else
      sec_audit_report_fail 16 "noexec option is missing on /dev/shm"
    fi

    if sec_audit_findmnt_separate_partition_ok /home; then
      sec_audit_report_pass 17 "/home is mounted on a separate partition"
    else
      sec_audit_report_fail 17 "/home is not mounted on a separate partition (explicit mount with distinct source)"
    fi

    if sec_audit_findmnt_path_resolvable /home && sec_audit_findmnt_has_mnt_option /home nodev; then
      sec_audit_report_pass 18 "nodev option is set on /home"
    else
      sec_audit_report_fail 18 "nodev option is missing on /home"
    fi

    if sec_audit_findmnt_path_resolvable /home && sec_audit_findmnt_has_mnt_option /home nosuid; then
      sec_audit_report_pass 19 "nosuid option is set on /home"
    else
      sec_audit_report_fail 19 "nosuid option is missing on /home"
    fi

    if sec_audit_findmnt_separate_partition_ok /var; then
      sec_audit_report_pass 20 "/var is mounted on a separate partition"
    else
      sec_audit_report_fail 20 "/var is not mounted on a separate partition (explicit mount with distinct source)"
    fi

    if sec_audit_findmnt_path_resolvable /var && sec_audit_findmnt_has_mnt_option /var nodev; then
      sec_audit_report_pass 21 "nodev option is set on /var"
    else
      sec_audit_report_fail 21 "nodev option is missing on /var"
    fi

    if sec_audit_findmnt_path_resolvable /var && sec_audit_findmnt_has_mnt_option /var nosuid; then
      sec_audit_report_pass 22 "nosuid option is set on /var"
    else
      sec_audit_report_fail 22 "nosuid option is missing on /var"
    fi

    if sec_audit_findmnt_separate_partition_ok /var/tmp; then
      sec_audit_report_pass 23 "/var/tmp is mounted on a separate partition"
    else
      sec_audit_report_fail 23 "/var/tmp is not mounted on a separate partition (explicit mount with distinct source)"
    fi

    if sec_audit_findmnt_path_resolvable /var/tmp && sec_audit_findmnt_has_mnt_option /var/tmp nodev; then
      sec_audit_report_pass 24 "nodev option is set on /var/tmp"
    else
      sec_audit_report_fail 24 "nodev option is missing on /var/tmp"
    fi

    if sec_audit_findmnt_path_resolvable /var/tmp && sec_audit_findmnt_has_mnt_option /var/tmp nosuid; then
      sec_audit_report_pass 25 "nosuid option is set on /var/tmp"
    else
      sec_audit_report_fail 25 "nosuid option is missing on /var/tmp"
    fi

    if sec_audit_findmnt_path_resolvable /var/tmp && sec_audit_findmnt_has_mnt_option /var/tmp noexec; then
      sec_audit_report_pass 26 "noexec option is set on /var/tmp"
    else
      sec_audit_report_fail 26 "noexec option is missing on /var/tmp"
    fi

    if sec_audit_findmnt_separate_partition_ok /var/log; then
      sec_audit_report_pass 27 "/var/log is mounted on a separate partition"
    else
      sec_audit_report_fail 27 "/var/log is not mounted on a separate partition (explicit mount with distinct source)"
    fi

    if sec_audit_findmnt_path_resolvable /var/log && sec_audit_findmnt_has_mnt_option /var/log nodev; then
      sec_audit_report_pass 28 "nodev option is set on /var/log"
    else
      sec_audit_report_fail 28 "nodev option is missing on /var/log"
    fi

    if sec_audit_findmnt_path_resolvable /var/log && sec_audit_findmnt_has_mnt_option /var/log nosuid; then
      sec_audit_report_pass 29 "nosuid option is set on /var/log"
    else
      sec_audit_report_fail 29 "nosuid option is missing on /var/log"
    fi

    if sec_audit_findmnt_path_resolvable /var/log && sec_audit_findmnt_has_mnt_option /var/log noexec; then
      sec_audit_report_pass 30 "noexec option is set on /var/log"
    else
      sec_audit_report_fail 30 "noexec option is missing on /var/log"
    fi

    if sec_audit_findmnt_separate_partition_ok /var/log/audit; then
      sec_audit_report_pass 31 "/var/log/audit is mounted on a separate partition"
    else
      sec_audit_report_fail 31 "/var/log/audit is not mounted on a separate partition (explicit mount with distinct source)"
    fi

    if sec_audit_findmnt_path_resolvable /var/log/audit && sec_audit_findmnt_has_mnt_option /var/log/audit nodev; then
      sec_audit_report_pass 32 "nodev option is set on /var/log/audit"
    else
      sec_audit_report_fail 32 "nodev option is missing on /var/log/audit"
    fi

    if sec_audit_findmnt_path_resolvable /var/log/audit && sec_audit_findmnt_has_mnt_option /var/log/audit nosuid; then
      sec_audit_report_pass 33 "nosuid option is set on /var/log/audit"
    else
      sec_audit_report_fail 33 "nosuid option is missing on /var/log/audit"
    fi

    if sec_audit_findmnt_path_resolvable /var/log/audit && sec_audit_findmnt_has_mnt_option /var/log/audit noexec; then
      sec_audit_report_pass 34 "noexec option is set on /var/log/audit"
    else
      sec_audit_report_fail 34 "noexec option is missing on /var/log/audit"
    fi

}

sec_audit_run_apparmor() {
    # RULE35-38
    if sec_audit_is_package_installed apparmor; then
      sec_audit_report_pass 35 "AppArmor package is installed"
    else
      sec_audit_report_fail 35 "AppArmor package is not installed"
    fi

    if sec_audit_apparmor_bootloader_enabled; then
      sec_audit_report_pass 36 "AppArmor is enabled in bootloader (apparmor=1 security=apparmor in cmdline or grub defaults)"
    else
      sec_audit_report_fail 36 "AppArmor is not enabled in bootloader configuration"
    fi

    if sec_audit_apparmor_profiles_enforce_or_complain_ok; then
      sec_audit_report_pass 37 "all AppArmor profiles are in enforce or complain mode (no unconfined profiles)"
    else
      sec_audit_report_fail 37 "some AppArmor profiles are unconfined or AppArmor status is unavailable"
    fi

    if sec_audit_apparmor_profiles_all_enforcing_ok; then
      sec_audit_report_pass 38 "all AppArmor profiles are in enforce mode"
    else
      sec_audit_report_fail 38 "some AppArmor profiles are not in enforce mode (complain/kill/unconfined present)"
    fi

}

sec_audit_run_bootloader() {
    # RULE39-40
    if grep -qE '^\s*set\s+superusers=' /boot/grub/grub.cfg 2>/dev/null && \
       grep -qE '^\s*GRUB2_PASSWORD=grub\.pbkdf2\.sha512\.' /boot/grub/user.cfg 2>/dev/null; then
      sec_audit_report_pass 39 "bootloader superuser and hashed GRUB password are configured"
    else
      sec_audit_report_fail 39 "bootloader superuser or hashed password configuration is missing"
    fi

    if stat -Lc '%a %U %G' /boot/grub/grub.cfg 2>/dev/null | grep -qE '^600 root root$'; then
      sec_audit_report_pass 40 "grub.cfg permissions are 600 and owner/group are root"
    else
      sec_audit_report_fail 40 "grub.cfg permissions or ownership are incorrect"
    fi

}

sec_audit_run_process_hardening() {
    # RULE41-44
    if sec_audit_sysctl_runtime_and_persistent_equals "kernel.randomize_va_space" "2"; then
      sec_audit_report_pass 41 "ASLR is enabled kernel.randomize_va_space = 2"
    else
      sec_audit_report_fail 41 "ASLR is disabled or not fully enabled"
    fi

    if [ "$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null)" -ge 1 ] && \
       grep -RhsE '^[[:space:]]*kernel\.yama\.ptrace_scope[[:space:]]*=[[:space:]]*[1-3][[:space:]]*$' \
    /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf 2>/dev/null | grep -q .; then
      sec_audit_report_pass 42 "ptrace_scope is restricted value >= 1"
    else
      sec_audit_report_fail 42 "ptrace_scope is unrestricted"
    fi

    if sec_audit_sysctl_runtime_and_persistent_equals "fs.suid_dumpable" "0" && sec_audit_limits_core_zero_and_systemd_ok && \
       grep -rqE '^\*\s+hard\s+core\s+0(\s|$)' /etc/security/limits.conf /etc/security/limits.d/ 2>/dev/null; then
      sec_audit_report_pass 43 "core dumps are restricted fs.suid_dumpable = 0 and hard limit = 0"
    else
      sec_audit_report_fail 43 "core dumps are not properly restricted"
    fi

    if ! systemctl is-enabled apport 2>/dev/null | grep -q '^enabled' || grep -q 'enabled=0' /etc/default/apport 2>/dev/null; then
      sec_audit_report_pass 44 "Apport automatic error reporting is disabled"
    else
      sec_audit_report_fail 44 "Apport automatic error reporting is enabled"
    fi

}

sec_audit_run_banners() {
    # RULE45-50
    if ! grep -qEi '(\\v|\\r|\\m|\\s|ubuntu|debian)' /etc/motd 2>/dev/null; then
      sec_audit_report_pass 45 "/etc/motd does not contain OS information"
    else
      sec_audit_report_fail 45 "/etc/motd contains OS version or hostname information"
    fi

    if ! grep -qEi '(\\v|\\r|\\m|\\s|ubuntu|debian)' /etc/issue 2>/dev/null; then
      sec_audit_report_pass 46 "/etc/issue does not contain OS information"
    else
      sec_audit_report_fail 46 "/etc/issue contains OS version or hostname information"
    fi

    if ! grep -qEi '(\\v|\\r|\\m|\\s|ubuntu|debian)' /etc/issue.net 2>/dev/null; then
      sec_audit_report_pass 47 "/etc/issue.net does not contain OS information"
    else
      sec_audit_report_fail 47 "/etc/issue.net contains OS version or hostname information"
    fi

    if stat -Lc '%a %U %G' /etc/motd 2>/dev/null | grep -qE '^6[04][04] root root$|^[0-5][0-4][04] root root$'; then
      sec_audit_report_pass 48 "/etc/motd permissions are correctly set root-owned"
    else
      sec_audit_report_fail 48 "/etc/motd permissions or ownership are incorrect"
    fi

    if stat -Lc '%a %U %G' /etc/issue 2>/dev/null | grep -qE '^6[04][04] root root$|^[0-5][0-4][04] root root$'; then
      sec_audit_report_pass 49 "/etc/issue permissions are correctly set root-owned"
    else
      sec_audit_report_fail 49 "/etc/issue permissions or ownership are incorrect"
    fi

    if stat -Lc '%a %U %G' /etc/issue.net 2>/dev/null | grep -qE '^6[04][04] root root$|^[0-5][0-4][04] root root$'; then
      sec_audit_report_pass 50 "/etc/issue.net permissions are correctly set root-owned"
    else
      sec_audit_report_fail 50 "/etc/issue.net permissions or ownership are incorrect"
    fi

}

sec_audit_run_gdm() {
    # RULE51-55
    if ! dpkg-query -W -f='${Status}' gdm3 2>/dev/null | grep -q 'install ok installed'; then
      sec_audit_report_pass 51 "GDM gdm3 is not installed"
    else
      sec_audit_report_fail 51 "GDM gdm3 is installed"
    fi

    if ! dpkg-query -W -f='${Status}' gdm3 2>/dev/null | grep -q 'install ok installed' || grep -qr 'banner-message-enable=true' /etc/gdm3/ /etc/dconf/db/ 2>/dev/null; then
      sec_audit_report_pass 52 "GDM login banner message is enabled"
    else
      sec_audit_report_fail 52 "GDM login banner message is not configured"
    fi

    if ! dpkg-query -W -f='${Status}' gdm3 2>/dev/null | grep -q 'install ok installed' || grep -qr 'disable-user-list=true' /etc/gdm3/ /etc/dconf/db/ 2>/dev/null; then
      sec_audit_report_pass 53 "GDM user list is disabled on login screen"
    else
      sec_audit_report_fail 53 "GDM user list is visible on login screen"
    fi

    if ! dpkg-query -W -f='${Status}' gdm3 2>/dev/null | grep -q 'install ok installed' || grep -qr 'idle-delay=uint32 [1-9]' /etc/dconf/db/ 2>/dev/null; then
      sec_audit_report_pass 54 "GDM screen lock activates on idle"
    else
      sec_audit_report_fail 54 "GDM screen lock on idle is not configured"
    fi

    if ! dpkg-query -W -f='${Status}' gdm3 2>/dev/null | grep -q 'install ok installed' || grep -qr 'lock-delay\|idle-delay' /etc/dconf/db/local.d/locks/ 2>/dev/null; then
      sec_audit_report_pass 55 "GDM screen lock settings are locked cannot be overridden"
    else
      sec_audit_report_fail 55 "GDM screen lock settings can be overridden by users"
    fi

}

sec_audit_run_unused_services() {
    # RULE56-84
    if ! dpkg-query -W -f='${Status}' gdm3 2>/dev/null | grep -q 'install ok installed' || grep -qr 'automount=false' /etc/dconf/db/ 2>/dev/null; then
      sec_audit_report_pass 56 "GDM automatic mounting of removable media is disabled"
    else
      sec_audit_report_fail 56 "GDM automatic mounting of removable media is enabled"
    fi

    if ! dpkg-query -W -f='${Status}' gdm3 2>/dev/null | grep -q 'install ok installed' || grep -qr 'autorun-never=true' /etc/dconf/db/ 2>/dev/null; then
      sec_audit_report_pass 57 "GDM autorun-never is enabled"
    else
      sec_audit_report_fail 57 "GDM autorun-never is not configured"
    fi

    if ! dpkg-query -W -f='${Status}' gdm3 2>/dev/null | grep -q 'install ok installed' || grep -qr 'autorun-never' /etc/dconf/db/local.d/locks/ 2>/dev/null; then
      sec_audit_report_pass 58 "GDM autorun-never setting is locked cannot be overridden"
    else
      sec_audit_report_fail 58 "GDM autorun-never setting can be overridden by users"
    fi

    if ! grep -qE '^Enable=true' /etc/gdm3/custom.conf 2>/dev/null; then
      sec_audit_report_pass 59 "XDMCP is not enabled in GDM"
    else
      sec_audit_report_fail 59 "XDMCP is enabled in GDM configuration"
    fi

    if ! (sec_audit_is_package_installed autofs && sec_audit_is_service_active autofs); then
      sec_audit_report_pass 60 "autofs service is not installed or not running"
    else
      sec_audit_report_fail 60 "autofs service is installed and running"
    fi

    if ! (sec_audit_is_package_installed avahi-daemon && sec_audit_is_service_active avahi-daemon); then
      sec_audit_report_pass 61 "avahi-daemon service is not installed or not running"
    else
      sec_audit_report_fail 61 "avahi-daemon service is installed and running"
    fi

    if ! dpkg-query -W -f='${Status}' isc-dhcp-server 2>/dev/null | grep -q 'install ok installed'; then
      sec_audit_report_pass 62 "DHCP server isc-dhcp-server is not installed"
    else
      sec_audit_report_fail 62 "DHCP server is installed"
    fi

    if ! dpkg-query -W -f='${Status}' bind9 2>/dev/null | grep -q 'install ok installed'; then
      sec_audit_report_pass 63 "DNS server bind9 is not installed"
    else
      sec_audit_report_fail 63 "DNS server bind9 is installed"
    fi

    if ! (sec_audit_is_package_installed dnsmasq && sec_audit_is_service_active dnsmasq); then
      sec_audit_report_pass 64 "dnsmasq service is not installed or not running"
    else
      sec_audit_report_fail 64 "dnsmasq service is installed and running"
    fi

    if ! dpkg-query -W -f='${Status}' vsftpd 2>/dev/null | grep -q 'install ok installed' && ! dpkg-query -W -f='${Status}' proftpd-basic 2>/dev/null | grep -q 'install ok installed'; then
      sec_audit_report_pass 65 "FTP server vsftpd/proftpd is not installed"
    else
      sec_audit_report_fail 65 "FTP server is installed"
    fi

    if ! dpkg-query -W -f='${Status}' slapd 2>/dev/null | grep -q 'install ok installed'; then
      sec_audit_report_pass 66 "LDAP server slapd is not installed"
    else
      sec_audit_report_fail 66 "LDAP server slapd is installed"
    fi

    if ! dpkg-query -W -f='${Status}' dovecot-imapd 2>/dev/null | grep -q 'install ok installed' && ! dpkg-query -W -f='${Status}' dovecot-pop3d 2>/dev/null | grep -q 'install ok installed'; then
      sec_audit_report_pass 67 "IMAP/POP3 server dovecot is not installed"
    else
      sec_audit_report_fail 67 "IMAP/POP3 server dovecot is installed"
    fi

    if ! dpkg-query -W -f='${Status}' nfs-kernel-server 2>/dev/null | grep -q 'install ok installed'; then
      sec_audit_report_pass 68 "NFS server is not installed"
    else
      sec_audit_report_fail 68 "NFS server is installed"
    fi

    if ! dpkg-query -W -f='${Status}' nis 2>/dev/null | grep -q 'install ok installed'; then
      sec_audit_report_pass 69 "NIS server is not installed"
    else
      sec_audit_report_fail 69 "NIS server is installed"
    fi

    if ! (sec_audit_is_package_installed cups && sec_audit_is_service_active cups); then
      sec_audit_report_pass 70 "print server CUPS is not installed or not running"
    else
      sec_audit_report_fail 70 "print server CUPS is installed and running"
    fi

    if ! (sec_audit_is_package_installed rpcbind && sec_audit_is_service_active rpcbind); then
      sec_audit_report_pass 71 "rpcbind service is not installed or not running"
    else
      sec_audit_report_fail 71 "rpcbind service is installed and running"
    fi

    if ! (sec_audit_is_package_installed rsync && sec_audit_is_service_active rsync); then
      sec_audit_report_pass 72 "rsync daemon is not installed or not running"
    else
      sec_audit_report_fail 72 "rsync daemon is installed and running"
    fi

    if ! dpkg-query -W -f='${Status}' samba 2>/dev/null | grep -q 'install ok installed'; then
      sec_audit_report_pass 73 "Samba file server is not installed"
    else
      sec_audit_report_fail 73 "Samba file server is installed"
    fi

    if ! dpkg-query -W -f='${Status}' snmpd 2>/dev/null | grep -q 'install ok installed'; then
      sec_audit_report_pass 74 "SNMP daemon is not installed"
    else
      sec_audit_report_fail 74 "SNMP daemon is installed"
    fi

    if ! dpkg-query -W -f='${Status}' tftpd-hpa 2>/dev/null | grep -q 'install ok installed'; then
      sec_audit_report_pass 75 "TFTP server is not installed"
    else
      sec_audit_report_fail 75 "TFTP server is installed"
    fi

    if ! (sec_audit_is_package_installed squid && sec_audit_is_service_active squid); then
      sec_audit_report_pass 76 "web proxy squid is not installed or not running"
    else
      sec_audit_report_fail 76 "web proxy squid is installed and running"
    fi

    if ! dpkg-query -W -f='${Status}' apache2 2>/dev/null | grep -q 'install ok installed' && ! dpkg-query -W -f='${Status}' nginx 2>/dev/null | grep -q 'install ok installed'; then
      sec_audit_report_pass 77 "web server apache2/nginx is not installed"
    else
      sec_audit_report_fail 77 "web server apache2/nginx is installed"
    fi

    if ! dpkg-query -W -f='${Status}' xinetd 2>/dev/null | grep -q 'install ok installed'; then
      sec_audit_report_pass 78 "xinetd is not installed"
    else
      sec_audit_report_fail 78 "xinetd is installed"
    fi

    if ! dpkg-query -W -f='${Status}' xserver-xorg-core 2>/dev/null | grep -q 'install ok installed'; then
      sec_audit_report_pass 79 "X Window server is not installed"
    else
      sec_audit_report_fail 79 "X Window server is installed"
    fi

    if ! ss -lntu 2>/dev/null | awk '$1 ~ /^tcp/ && $5 ~ /:25$/ && $5 !~ /(127\.0\.0\.1:25|::1:25)$/ {found=1} END{exit found ? 0 : 1}'; then
      sec_audit_report_pass 80 "MTA is configured for local-only mode port 25 not exposed"
    else
      sec_audit_report_fail 80 "MTA is listening on external interfaces"
    fi

    if ! dpkg-query -W -f='${Status}' nis 2>/dev/null | grep -q 'install ok installed'; then
      sec_audit_report_pass 81 "NIS client is not installed"
    else
      sec_audit_report_fail 81 "NIS client is installed"
    fi

    if ! dpkg-query -W -f='${Status}' rsh-client 2>/dev/null | grep -q 'install ok installed'; then
      sec_audit_report_pass 82 "rsh client is not installed"
    else
      sec_audit_report_fail 82 "rsh client is installed"
    fi

    if ! dpkg-query -W -f='${Status}' talk 2>/dev/null | grep -q 'install ok installed'; then
      sec_audit_report_pass 83 "talk client is not installed"
    else
      sec_audit_report_fail 83 "talk client is installed"
    fi

    if ! dpkg-query -W -f='${Status}' telnet 2>/dev/null | grep -q 'install ok installed'; then
      sec_audit_report_pass 84 "telnet client is not installed"
    else
      sec_audit_report_fail 84 "telnet client is installed"
    fi

}

sec_audit_run_client_tools() {
    # RULE85-88
    if ! dpkg-query -W -f='${Status}' ldap-utils 2>/dev/null | grep -q 'install ok installed'; then
      sec_audit_report_pass 85 "LDAP client ldap-utils is not installed"
    else
      sec_audit_report_fail 85 "LDAP client ldap-utils is installed"
    fi

    if ! dpkg-query -W -f='${Status}' ftp 2>/dev/null | grep -q 'install ok installed'; then
      sec_audit_report_pass 86 "FTP client is not installed"
    else
      sec_audit_report_fail 86 "FTP client is installed"
    fi

    _chrony_active="$(systemctl is-active chrony 2>/dev/null)"
    _timesyncd_active="$(systemctl is-active systemd-timesyncd 2>/dev/null)"
    if [ "$(printf '%s\n' "$_chrony_active" "$_timesyncd_active" | grep -c '^active$')" -eq 1 ]; then
      sec_audit_report_pass 87 "exactly one time synchronization daemon is active"
    else
      sec_audit_report_fail 87 "zero or multiple time synchronization daemons are active"
    fi

    if grep -qE '^NTP=' /etc/systemd/timesyncd.conf 2>/dev/null || grep -rqE '^NTP=' /etc/systemd/timesyncd.conf.d/ 2>/dev/null; then
      sec_audit_report_pass 88 "systemd-timesyncd NTP server is configured"
    else
      sec_audit_report_fail 88 "systemd-timesyncd NTP server is not configured"
    fi

}

sec_audit_run_chrony() {
    # RULE89-92
    if systemctl is-active systemd-timesyncd 2>/dev/null | grep -q '^active' && systemctl is-enabled systemd-timesyncd 2>/dev/null | grep -q '^enabled'; then
      sec_audit_report_pass 89 "systemd-timesyncd is enabled and running"
    else
      sec_audit_report_fail 89 "systemd-timesyncd is not enabled or not running"
    fi

    if grep -qE '^(server|pool) ' /etc/chrony/chrony.conf 2>/dev/null; then
      sec_audit_report_pass 90 "chrony NTP server is configured"
    else
      sec_audit_report_fail 90 "chrony NTP server is not configured"
    fi

    if ps -u _chrony -o pid= 2>/dev/null | grep -q .; then
      sec_audit_report_pass 91 "chronyd is running as user _chrony"
    else
      sec_audit_report_fail 91 "chronyd is not running as user _chrony"
    fi

    if systemctl is-active chrony 2>/dev/null | grep -q '^active' && systemctl is-enabled chrony 2>/dev/null | grep -q '^enabled'; then
      sec_audit_report_pass 92 "chrony is enabled and running"
    else
      sec_audit_report_fail 92 "chrony is not enabled or not running"
    fi

}

sec_audit_run_cron_at() {
    # RULE93-105
    if systemctl is-active cron 2>/dev/null | grep -q '^active' && systemctl is-enabled cron 2>/dev/null | grep -q '^enabled'; then
      sec_audit_report_pass 93 "cron daemon is enabled and running"
    else
      sec_audit_report_fail 93 "cron daemon is not enabled or not running"
    fi

    if stat -Lc '%a %U %G' /etc/crontab 2>/dev/null | grep -qE '^[0-6]00 root root$'; then
      sec_audit_report_pass 94 "/etc/crontab is owned by root with permissions 600"
    else
      sec_audit_report_fail 94 "/etc/crontab permissions or ownership are incorrect"
    fi

    if stat -Lc '%a %U %G' /etc/cron.hourly 2>/dev/null | grep -qE '^[0-7]00 root root$'; then
      sec_audit_report_pass 95 "/etc/cron.hourly is owned by root with permissions 700"
    else
      sec_audit_report_fail 95 "/etc/cron.hourly permissions or ownership are incorrect"
    fi

    if stat -Lc '%a %U %G' /etc/cron.daily 2>/dev/null | grep -qE '^[0-7]00 root root$'; then
      sec_audit_report_pass 96 "/etc/cron.daily is owned by root with permissions 700"
    else
      sec_audit_report_fail 96 "/etc/cron.daily permissions or ownership are incorrect"
    fi

    if stat -Lc '%a %U %G' /etc/cron.weekly 2>/dev/null | grep -qE '^[0-7]00 root root$'; then
      sec_audit_report_pass 97 "/etc/cron.weekly is owned by root with permissions 700"
    else
      sec_audit_report_fail 97 "/etc/cron.weekly permissions or ownership are incorrect"
    fi

    if stat -Lc '%a %U %G' /etc/cron.monthly 2>/dev/null | grep -qE '^[0-7]00 root root$'; then
      sec_audit_report_pass 98 "/etc/cron.monthly is owned by root with permissions 700"
    else
      sec_audit_report_fail 98 "/etc/cron.monthly permissions or ownership are incorrect"
    fi

    if stat -Lc '%a %U %G' /etc/cron.d 2>/dev/null | grep -qE '^[0-7]00 root root$'; then
      sec_audit_report_pass 99 "/etc/cron.d is owned by root with permissions 700"
    else
      sec_audit_report_fail 99 "/etc/cron.d permissions or ownership are incorrect"
    fi

    if [ ! -f /etc/cron.deny ] && [ -f /etc/cron.allow ] && stat -Lc '%a %U %G' /etc/cron.allow 2>/dev/null | grep -qE '^[0-6][04][04] root root$'; then
      sec_audit_report_pass 100 "crontab access is restricted via /etc/cron.allow"
    else
      sec_audit_report_fail 100 "crontab access is not restricted cron.deny present or cron.allow missing"
    fi

    if [ ! -f /etc/at.deny ] && [ -f /etc/at.allow ] && stat -Lc '%a %U %G' /etc/at.allow 2>/dev/null | grep -qE '^[0-6][04][04] root root$'; then
      sec_audit_report_pass 101 "at access is restricted via /etc/at.allow"
    else
      sec_audit_report_fail 101 "at access is not restricted at.deny present or at.allow missing"
    fi

    if ! ip link show 2>/dev/null | grep -qiE 'wlan|wifi|wlp' || nmcli radio wifi 2>/dev/null | grep -q 'disabled'; then
      sec_audit_report_pass 102 "wireless interfaces are disabled"
    else
      sec_audit_report_fail 102 "wireless interfaces are active"
    fi

    if ! (dpkg-query -W -f='${Status}' bluez 2>/dev/null | grep -q 'install ok installed' && systemctl is-active bluetooth 2>/dev/null | grep -q '^active'); then
      sec_audit_report_pass 103 "Bluetooth service is not installed or not running"
    else
      sec_audit_report_fail 103 "Bluetooth service is installed and running"
    fi

    sec_audit_req_kernel_module_not_available 104 dccp

    sec_audit_req_kernel_module_not_available 105 tipc

}

sec_audit_run_network_stack() {
    # RULE106-119
    sec_audit_req_kernel_module_not_available 106 rds

    sec_audit_req_kernel_module_not_available 107 sctp

    if sec_audit_sysctl_runtime_and_persistent_equals "net.ipv4.ip_forward" "0" && \
       sec_audit_sysctl_runtime_and_persistent_equals "net.ipv6.conf.all.forwarding" "0"; then
      sec_audit_report_pass 108 "IP forwarding is disabled IPv4 and IPv6"
    else
      sec_audit_report_fail 108 "IP forwarding is enabled or not set persistently"
    fi

    if sec_audit_sysctl_runtime_and_persistent_equals "net.ipv4.conf.all.send_redirects" "0" && \
       sec_audit_sysctl_runtime_and_persistent_equals "net.ipv4.conf.default.send_redirects" "0"; then
      sec_audit_report_pass 109 "ICMP redirect sending is disabled on all interfaces"
    else
      sec_audit_report_fail 109 "ICMP redirect sending is enabled or not set persistently"
    fi

    if sec_audit_sysctl_runtime_and_persistent_equals "net.ipv4.icmp_ignore_bogus_error_responses" "1"; then
      sec_audit_report_pass 110 "bogus ICMP error responses are ignored"
    else
      sec_audit_report_fail 110 "bogus ICMP error responses are not ignored"
    fi

    if sec_audit_sysctl_runtime_and_persistent_equals "net.ipv4.icmp_echo_ignore_broadcasts" "1"; then
      sec_audit_report_pass 111 "broadcast ICMP requests are ignored"
    else
      sec_audit_report_fail 111 "broadcast ICMP requests are not ignored"
    fi

    if sec_audit_sysctl_runtime_and_persistent_equals "net.ipv4.conf.all.accept_redirects" "0" && \
       sec_audit_sysctl_runtime_and_persistent_equals "net.ipv4.conf.default.accept_redirects" "0"; then
      sec_audit_report_pass 112 "ICMP redirects are not accepted on all interfaces"
    else
      sec_audit_report_fail 112 "ICMP redirects are accepted or not set persistently"
    fi

    if sec_audit_sysctl_runtime_and_persistent_equals "net.ipv4.conf.all.secure_redirects" "0" && \
       sec_audit_sysctl_runtime_and_persistent_equals "net.ipv4.conf.default.secure_redirects" "0"; then
      sec_audit_report_pass 113 "secure ICMP redirects are not accepted on all interfaces"
    else
      sec_audit_report_fail 113 "secure ICMP redirects are accepted or not set persistently"
    fi

    if sec_audit_sysctl_runtime_and_persistent_equals "net.ipv4.conf.all.rp_filter" "1" && \
       sec_audit_sysctl_runtime_and_persistent_equals "net.ipv4.conf.default.rp_filter" "1"; then
      sec_audit_report_pass 114 "reverse path filtering is enabled on all interfaces"
    else
      sec_audit_report_fail 114 "reverse path filtering is not enabled on all interfaces"
    fi

    if sec_audit_sysctl_runtime_and_persistent_equals "net.ipv4.conf.all.accept_source_route" "0" && \
       sec_audit_sysctl_runtime_and_persistent_equals "net.ipv4.conf.default.accept_source_route" "0" && \
       sec_audit_sysctl_runtime_and_persistent_equals "net.ipv6.conf.all.accept_source_route" "0" && \
       sec_audit_sysctl_runtime_and_persistent_equals "net.ipv6.conf.default.accept_source_route" "0"; then
      sec_audit_report_pass 115 "source routed packets are not accepted on any interface"
    else
      sec_audit_report_fail 115 "source routed packets are accepted or not set persistently"
    fi

    if sec_audit_sysctl_runtime_and_persistent_equals "net.ipv4.conf.all.log_martians" "1" && \
       sec_audit_sysctl_runtime_and_persistent_equals "net.ipv4.conf.default.log_martians" "1"; then
      sec_audit_report_pass 116 "suspicious martian packets are logged on all interfaces"
    else
      sec_audit_report_fail 116 "suspicious packet logging is not enabled on all interfaces"
    fi

    if sec_audit_sysctl_runtime_and_persistent_equals "net.ipv4.tcp_syncookies" "1"; then
      sec_audit_report_pass 117 "TCP SYN cookies are enabled"
    else
      sec_audit_report_fail 117 "TCP SYN cookies are disabled"
    fi

    if sec_audit_sysctl_runtime_and_persistent_equals "net.ipv6.conf.all.accept_ra" "0" && \
       sec_audit_sysctl_runtime_and_persistent_equals "net.ipv6.conf.default.accept_ra" "0"; then
      sec_audit_report_pass 118 "IPv6 router advertisements are not accepted"
    else
      sec_audit_report_fail 118 "IPv6 router advertisements are accepted or not set persistently"
    fi

    if UFW=$(systemctl is-active ufw 2>/dev/null); NFT=$(systemctl is-active nftables 2>/dev/null); IPT=$(systemctl is-active iptables 2>/dev/null); [ $(printf '%s\n' "$UFW" "$NFT" "$IPT" | grep -c '^active') -eq 1 ]; then
      sec_audit_report_pass 119 "exactly one firewall utility is active"
    else
      sec_audit_report_fail 119 "zero or multiple firewall utilities are active simultaneously"
    fi

    _ufw_active=$(systemctl is-active ufw 2>/dev/null)
    _nft_active=$(systemctl is-active nftables 2>/dev/null)
    _ipt_active=$(systemctl is-active iptables 2>/dev/null)

}

sec_audit_run_firewall() {
    # RULE120-142
    if dpkg-query -W -f='${Status}' ufw 2>/dev/null | grep -q 'install ok installed'; then
      sec_audit_report_pass 120 "UFW is installed"
    else
      sec_audit_report_fail 120 "UFW is not installed"
    fi

    if ! dpkg-query -W -f='${Status}' iptables-persistent 2>/dev/null | grep -q 'install ok installed'; then
      sec_audit_report_pass 121 "iptables-persistent is not installed alongside UFW"
    else
      sec_audit_report_fail 121 "iptables-persistent is installed alongside UFW"
    fi

    if systemctl is-active ufw 2>/dev/null | grep -q '^active' && systemctl is-enabled ufw 2>/dev/null | grep -q '^enabled'; then
      sec_audit_report_pass 122 "UFW service is enabled and running"
    else
      sec_audit_report_fail 122 "UFW service is not enabled or not running"
    fi

    if ufw status verbose 2>/dev/null | grep -qE 'Anywhere on lo.*ALLOW IN' && ufw status verbose 2>/dev/null | grep -qE '127\.0\.0\.0/8.*DENY IN'; then
      sec_audit_report_pass 123 "UFW loopback traffic rules are correctly configured"
    else
      sec_audit_report_fail 123 "UFW loopback traffic rules are missing or incorrect"
    fi

    _open_ports=$(ss -4tuln 2>/dev/null | awk 'NR>1{split($5,a,":"); print a[length(a)]}' | sort -u | grep -v '^$')
    _ufw_ports=$(ufw status 2>/dev/null | grep -oE '^[0-9]+' | sort -u)
    if [ "$(comm -23 <(echo "$_open_ports") <(echo "$_ufw_ports") 2>/dev/null | wc -l)" -eq 0 ]; then
      sec_audit_report_pass 124 "UFW rules exist for all open ports"
    else
      sec_audit_report_fail 124 "one or more open ports are missing UFW rules"
    fi

    if ufw status verbose 2>/dev/null | grep -E '^Default:' | grep -q 'deny (incoming)'; then
      sec_audit_report_pass 125 "UFW default incoming policy is deny"
    else
      sec_audit_report_fail 125 "UFW default incoming policy is not deny"
    fi

    if dpkg-query -W -f='${Status}' nftables 2>/dev/null | grep -q 'install ok installed'; then
      sec_audit_report_pass 126 "nftables is installed"
    else
      sec_audit_report_fail 126 "nftables is not installed"
    fi

    if ! dpkg-query -W -f='${Status}' ufw 2>/dev/null | grep -q 'install ok installed' || ! systemctl is-active ufw 2>/dev/null | grep -q '^active'; then
      sec_audit_report_pass 127 "UFW is not active when nftables is in use"
    else
      sec_audit_report_fail 127 "UFW and nftables are both active"
    fi

    if [ "$_nft_active" = "active" ] && nft list tables 2>/dev/null | grep -q .; then
      sec_audit_report_pass 128 "at least one nftables table exists"
    else
      sec_audit_report_fail 128 "no nftables tables are configured"
    fi

    if [ "$_nft_active" = "active" ] && nft list ruleset 2>/dev/null | grep -qE 'type filter hook input' && nft list ruleset 2>/dev/null | grep -qE 'type filter hook forward' && nft list ruleset 2>/dev/null | grep -qE 'type filter hook output'; then
      sec_audit_report_pass 129 "nftables input, forward, and output base chains exist"
    else
      sec_audit_report_fail 129 "one or more nftables base chains are missing"
    fi

    if [ "$_nft_active" = "active" ] && nft list ruleset 2>/dev/null | grep -qE 'iif.*lo.*accept' && nft list ruleset 2>/dev/null | grep -qE 'ip saddr 127\.0\.0\.1.*drop'; then
      sec_audit_report_pass 130 "nftables loopback traffic is correctly configured"
    else
      sec_audit_report_fail 130 "nftables loopback traffic rules are missing or incorrect"
    fi

    if [ "$_nft_active" = "active" ] && nft list ruleset 2>/dev/null | grep -qE 'hook input.*policy drop' && nft list ruleset 2>/dev/null | grep -qE 'hook forward.*policy drop'; then
      sec_audit_report_pass 131 "nftables input and forward chains have default drop policy"
    else
      sec_audit_report_fail 131 "nftables chains do not have default drop policy"
    fi

    if [ "$_nft_active" = "active" ] && systemctl is-enabled nftables 2>/dev/null | grep -q '^enabled'; then
      sec_audit_report_pass 132 "nftables service is enabled and running"
    else
      sec_audit_report_fail 132 "nftables service is not enabled or not running"
    fi

    if [ "$_nft_active" = "active" ] && grep -qr 'include\|flush\|table' /etc/nftables.conf /etc/nftables.d/ 2>/dev/null; then
      sec_audit_report_pass 133 "nftables rules are saved permanently in /etc/nftables.conf"
    else
      sec_audit_report_fail 133 "nftables rules are not saved permanently"
    fi

    if dpkg-query -W -f='${Status}' iptables 2>/dev/null | grep -q 'install ok installed'; then
      sec_audit_report_pass 134 "iptables packages are installed"
    else
      sec_audit_report_fail 134 "iptables packages are not installed"
    fi

    if ! systemctl is-active nftables 2>/dev/null | grep -q '^active'; then
      sec_audit_report_pass 135 "nftables is not active when iptables is in use"
    else
      sec_audit_report_fail 135 "nftables and iptables are both active"
    fi

    if ! systemctl is-active ufw 2>/dev/null | grep -q '^active'; then
      sec_audit_report_pass 136 "UFW is not active when iptables is in use"
    else
      sec_audit_report_fail 136 "UFW and iptables are both active"
    fi

    if [ "$_ipt_active" = "active" ] && iptables -L INPUT --line-numbers 2>/dev/null | grep -q 'Chain INPUT.*DROP' && iptables -L FORWARD --line-numbers 2>/dev/null | grep -q 'Chain FORWARD.*DROP'; then
      sec_audit_report_pass 137 "iptables INPUT and FORWARD chains have default DROP policy"
    else
      sec_audit_report_fail 137 "iptables INPUT or FORWARD chains do not have default DROP policy"
    fi

    if [ "$_ipt_active" = "active" ] && iptables -L INPUT 2>/dev/null | grep -q 'ACCEPT.*lo' && iptables -L INPUT 2>/dev/null | grep -q 'DROP.*127\.0\.0\.0'; then
      sec_audit_report_pass 138 "iptables loopback traffic rules are correctly configured"
    else
      sec_audit_report_fail 138 "iptables loopback traffic rules are missing or incorrect"
    fi

    if [ "$_ipt_active" = "active" ] && iptables -L INPUT -v -n 2>/dev/null | grep -q 'ACCEPT' && iptables -L INPUT -v -n 2>/dev/null | grep -qE 'ACCEPT.*(ESTABLISHED|RELATED|state)'; then
      sec_audit_report_pass 139 "iptables ACCEPT rules exist for open ports"
    else
      sec_audit_report_fail 139 "no ACCEPT rules found for open ports in iptables"
    fi

    if [ "$_ipt_active" = "active" ] && ip6tables -L INPUT 2>/dev/null | grep -q 'Chain INPUT.*DROP' && ip6tables -L FORWARD 2>/dev/null | grep -q 'Chain FORWARD.*DROP'; then
      sec_audit_report_pass 140 "ip6tables INPUT and FORWARD chains have default DROP policy"
    else
      sec_audit_report_fail 140 "ip6tables INPUT or FORWARD chains do not have default DROP policy"
    fi

    if [ "$_ipt_active" = "active" ] && ip6tables -L INPUT 2>/dev/null | grep -q 'ACCEPT.*lo' && ip6tables -L INPUT 2>/dev/null | grep -q 'DROP.*::1'; then
      sec_audit_report_pass 141 "ip6tables loopback traffic rules are correctly configured"
    else
      sec_audit_report_fail 141 "ip6tables loopback traffic rules are missing or incorrect"
    fi

    if [ "$_ipt_active" = "active" ] && ip6tables -L INPUT -v -n 2>/dev/null | grep -q 'ACCEPT' && ip6tables -L INPUT -v -n 2>/dev/null | grep -qE 'ACCEPT.*(ESTABLISHED|RELATED|state)'; then
      sec_audit_report_pass 142 "ip6tables ACCEPT rules exist for open ports"
    else
      sec_audit_report_fail 142 "no ACCEPT rules found for open ports in ip6tables"
    fi

}

sec_audit_run_sshd() {
    # RULE143-164
    if stat -Lc '%a %U %G' /etc/ssh/sshd_config 2>/dev/null | grep -qE '^[0-6]00 root root$'; then
      sec_audit_report_pass 143 "sshd_config is owned by root with permissions 600"
    else
      sec_audit_report_fail 143 "sshd_config permissions or ownership are incorrect"
    fi

    if find /etc/ssh -name 'ssh_host_*_key' ! -name '*.pub' 2>/dev/null | grep -q . && [ "$(find /etc/ssh -name 'ssh_host_*_key' ! -name '*.pub' 2>/dev/null | xargs -I{} stat -Lc '%a %U %G' {} 2>/dev/null | grep -cvE '^[0-6]00 root (root|ssh_keys)$')" -eq 0 ]; then
      sec_audit_report_pass 144 "SSH private host keys have correct permissions 600, root-owned"
    else
      sec_audit_report_fail 144 "SSH private host key permissions or ownership are incorrect"
    fi

    if find /etc/ssh -name 'ssh_host_*_key.pub' 2>/dev/null | grep -q . && [ "$(find /etc/ssh -name 'ssh_host_*_key.pub' 2>/dev/null | xargs -I{} stat -Lc '%a %U %G' {} 2>/dev/null | grep -cvE '^[0-6][04][04] root root$')" -eq 0 ]; then
      sec_audit_report_pass 145 "SSH public host keys have correct permissions 644, root-owned"
    else
      sec_audit_report_fail 145 "SSH public host key permissions or ownership are incorrect"
    fi

    if sec_audit_sshd_effective_dump | grep -qiE '^(allowusers|allowgroups|denyusers|denygroups)[[:space:]]+\S+'; then
      sec_audit_report_pass 146 "SSH access is restricted via AllowUsers/AllowGroups/DenyUsers/DenyGroups"
    else
      sec_audit_report_fail 146 "SSH access is not restricted by user or group directives"
    fi

    if sec_audit_sshd_effective_dump | grep -i '^banner ' | grep -qv 'none'; then
      sec_audit_report_pass 147 "SSH banner is configured"
    else
      sec_audit_report_fail 147 "SSH banner is not configured"
    fi

    if sec_audit_sshd_effective_dump | grep -i '^ciphers ' >/dev/null && \
       ! sec_audit_sshd_effective_dump | grep -i '^ciphers ' | grep -qE 'arcfour|3des|blowfish|cast128|aes128-cbc|aes192-cbc|aes256-cbc'; then
      sec_audit_report_pass 148 "SSH is configured to use only strong ciphers"
    else
      sec_audit_report_fail 148 "SSH ciphers are weak or directive is not explicitly configured"
    fi

    if sec_audit_sshd_effective_dump | awk '
      /^clientaliveinterval / {i=$2}
      /^clientalivecountmax / {c=$2}
      END {exit !(i+0>0 && i+0<=900 && c+0>0 && c+0<=3)}
    '; then
      sec_audit_report_pass 149 "SSH ClientAliveInterval and ClientAliveCountMax are configured"
    else
     sec_audit_report_fail 149 "SSH idle timeout settings are missing or exceed limits"
    fi

    if sec_audit_sshd_effective_dump | grep -i '^disableforwarding' | grep -qi 'yes'; then
      sec_audit_report_pass 150 "SSH DisableForwarding is enabled"
    else
      sec_audit_report_fail 150 "SSH DisableForwarding is not enabled"
    fi

    if sec_audit_sshd_effective_dump | grep -i '^gssapiauthentication' | grep -qi 'no'; then
      sec_audit_report_pass 151 "SSH GSSAPIAuthentication is disabled"
    else
      sec_audit_report_fail 151 "SSH GSSAPIAuthentication is enabled"
    fi

    if sec_audit_sshd_effective_dump | grep -i '^hostbasedauthentication' | grep -qi 'no'; then
      sec_audit_report_pass 152 "SSH HostbasedAuthentication is disabled"
    else
      sec_audit_report_fail 152 "SSH HostbasedAuthentication is enabled"
    fi

    if sec_audit_sshd_effective_dump | grep -i '^ignorerhosts' | grep -qi 'yes'; then
      sec_audit_report_pass 153 "SSH IgnoreRhosts is enabled"
    else
      sec_audit_report_fail 153 "SSH IgnoreRhosts is disabled"
    fi

    if sec_audit_sshd_effective_dump | grep -i '^kexalgorithms ' >/dev/null && \
       ! sec_audit_sshd_effective_dump | grep -i '^kexalgorithms ' | grep -qE 'diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1'; then
      sec_audit_report_pass 154 "SSH KexAlgorithms contain only strong algorithms"
    else
      sec_audit_report_fail 154 "SSH KexAlgorithms include weak algorithms or directive is not explicitly configured"
    fi

    if sec_audit_sshd_effective_dump | grep -i '^logingracetime' | awk '{if($2+0>0 && $2+0<=60) exit 0; exit 1}'; then
      sec_audit_report_pass 155 "SSH LoginGraceTime is set to 60 seconds or less"
    else
      sec_audit_report_fail 155 "SSH LoginGraceTime is not configured or too long"
    fi

    if sec_audit_sshd_effective_dump | grep -i '^loglevel' | grep -qiE 'VERBOSE|INFO'; then
      sec_audit_report_pass 156 "SSH LogLevel is set to VERBOSE or INFO"
    else
      sec_audit_report_fail 156 "SSH LogLevel is not set to VERBOSE or INFO"
    fi

    if sec_audit_sshd_effective_dump | grep -i '^macs ' >/dev/null && \
       ! sec_audit_sshd_effective_dump | grep -i '^macs ' | grep -qE 'hmac-md5|hmac-sha1|hmac-ripemd|umac-64@|umac-64-etm@'; then
      sec_audit_report_pass 157 "SSH MACs contain only strong algorithms"
    else
      sec_audit_report_fail 157 "SSH MACs include weak algorithms or directive is not explicitly configured"
    fi

    if sec_audit_sshd_effective_dump | grep -i '^maxauthtries' | awk '{if($2+0>0 && $2+0<=4) exit 0; exit 1}'; then
      sec_audit_report_pass 158 "SSH MaxAuthTries is set to 4 or less"
    else
      sec_audit_report_fail 158 "SSH MaxAuthTries is not configured or set too high"
    fi

    if sec_audit_sshd_effective_dump | grep -i '^maxsessions' | awk '{print $2}' | awk '{if($1<=10) exit 0; else exit 1}'; then
      sec_audit_report_pass 159 "SSH MaxSessions is set to 10 or less"
    else
      sec_audit_report_fail 159 "SSH MaxSessions is not configured or set too high"
    fi

    if sec_audit_sshd_effective_dump | awk '
      /^maxstartups / {
    split($2,a,":");
    if (length(a)==3 && a[1]+0<=10 && a[2]+0<=30 && a[3]+0<=60) exit 0;
    exit 1
      }
      END {exit 1}
    '; then
      sec_audit_report_pass 160 "SSH MaxStartups is configured"
    else
      sec_audit_report_fail 160 "SSH MaxStartups is missing or too permissive"
    fi

    if sec_audit_sshd_effective_dump | grep -i '^permitemptypasswords' | grep -qi 'no'; then
      sec_audit_report_pass 161 "SSH PermitEmptyPasswords is disabled"
    else
      sec_audit_report_fail 161 "SSH PermitEmptyPasswords is enabled"
    fi

    if sec_audit_sshd_effective_dump | grep -i '^permitrootlogin' | grep -qi 'no'; then
      sec_audit_report_pass 162 "SSH PermitRootLogin is disabled"
    else
      sec_audit_report_fail 162 "SSH PermitRootLogin is enabled"
    fi

    if sec_audit_sshd_effective_dump | grep -i '^permituserenvironment' | grep -qi 'no'; then
      sec_audit_report_pass 163 "SSH PermitUserEnvironment is disabled"
    else
      sec_audit_report_fail 163 "SSH PermitUserEnvironment is enabled"
    fi

    if sec_audit_sshd_effective_dump | grep -i '^usepam' | grep -qi 'yes'; then
      sec_audit_report_pass 164 "SSH UsePAM is enabled"
    else
      sec_audit_report_fail 164 "SSH UsePAM is disabled"
    fi

}

sec_audit_run_sudo_su() {
    # RULE165-170
    if dpkg-query -W -f='${Status}' sudo 2>/dev/null | grep -q 'install ok installed'; then
      sec_audit_report_pass 165 "sudo is installed"
    else
      sec_audit_report_fail 165 "sudo is not installed"
    fi

    if grep -rqE '^[[:space:]]*Defaults([[:space:]]+[^#]*)?[[:space:]]+use_pty([[:space:]]|$)' /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
      sec_audit_report_pass 166 "sudo is configured to use pty use_pty in Defaults"
    else
      sec_audit_report_fail 166 "sudo is not configured to use pty"
    fi

    if grep -rqE '^[[:space:]]*Defaults([[:space:]]+[^#]*)?[[:space:]]+logfile="?/[^",[:space:]]+"?([[:space:]]|$)' /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
      sec_audit_report_pass 167 "sudo log file is configured logfile= in Defaults"
    else
      sec_audit_report_fail 167 "sudo log file is not configured"
    fi

    if ! grep -rqE '^[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
      sec_audit_report_pass 168 "no NOPASSWD entries exist in sudoers"
    else
      sec_audit_report_fail 168 "NOPASSWD entries found in sudoers"
    fi

    if ! grep -rqE '^Defaults.*!authenticate' /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
      sec_audit_report_pass 169 "re-authentication is not globally disabled in sudoers"
    else
      sec_audit_report_fail 169 "re-authentication is globally disabled in sudoers !authenticate"
    fi

    timeout_val="$(grep -rhoE '^[[:space:]]*Defaults[^#]*timestamp_timeout[[:space:]]*=[[:space:]]*-?[0-9]+' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -oE -- '-?[0-9]+' | awk 'NR==1{min=$1} $1<min{min=$1} END{if(NR>0) print min}')"
    if [ -n "$timeout_val" ] && [ "$timeout_val" -le 15 ] && [ "$timeout_val" -ge 0 ]; then
      sec_audit_report_pass 170 "sudo timestamp_timeout is configured and not unlimited"
    else
      sec_audit_report_fail 170 "sudo timestamp_timeout is not configured or set to unlimited"
    fi

}

sec_audit_run_pam_auth() {
    # RULE171-192
    if dpkg-query -W -f='${Status}' libpam-runtime 2>/dev/null | grep -q 'install ok installed'; then
      sec_audit_report_pass 171 "libpam-runtime PAM is installed"
    else
      sec_audit_report_fail 171 "libpam-runtime PAM is not installed"
    fi

    if dpkg-query -W -f='${Status}' libpam-modules 2>/dev/null | grep -q 'install ok installed'; then
      sec_audit_report_pass 172 "libpam-modules is installed"
    else
      sec_audit_report_fail 172 "libpam-modules is not installed"
    fi

    if dpkg-query -W -f='${Status}' libpam-pwquality 2>/dev/null | grep -q 'install ok installed'; then
      sec_audit_report_pass 173 "libpam-pwquality is installed"
    else
      sec_audit_report_fail 173 "libpam-pwquality is not installed"
    fi

    if grep -qE 'pam_unix\.so' /etc/pam.d/common-auth 2>/dev/null; then
      sec_audit_report_pass 174 "pam_unix module is present in /etc/pam.d/common-auth"
    else
      sec_audit_report_fail 174 "pam_unix module is missing from /etc/pam.d/common-auth"
    fi

    if grep -qE 'pam_faillock\.so' /etc/pam.d/common-auth 2>/dev/null; then
      sec_audit_report_pass 175 "pam_faillock module is present in /etc/pam.d/common-auth"
    else
      sec_audit_report_fail 175 "pam_faillock module is missing from /etc/pam.d/common-auth"
    fi

    if grep -qE 'pam_pwquality\.so' /etc/pam.d/common-password 2>/dev/null; then
      sec_audit_report_pass 176 "pam_pwquality module is present in /etc/pam.d/common-password"
    else
      sec_audit_report_fail 176 "pam_pwquality module is missing from /etc/pam.d/common-password"
    fi

    if grep -qE 'pam_pwhistory\.so' /etc/pam.d/common-password 2>/dev/null; then
      sec_audit_report_pass 177 "pam_pwhistory module is present in /etc/pam.d/common-password"
    else
      sec_audit_report_fail 177 "pam_pwhistory module is missing from /etc/pam.d/common-password"
    fi

    if grep -qE '^deny\s*=' /etc/security/faillock.conf 2>/dev/null && awk -F'[[:space:]]*=[[:space:]]*' '/^deny[[:space:]]*=/{if($2+0>0 && $2+0<=5) exit 0; exit 1}' /etc/security/faillock.conf; then
      sec_audit_report_pass 178 "faillock deny threshold is configured max 5 attempts"
    else
      sec_audit_report_fail 178 "faillock deny threshold is not configured or set too high"
    fi

    if grep -qE '^unlock_time\s*=' /etc/security/faillock.conf 2>/dev/null && awk -F'[[:space:]]*=[[:space:]]*' '/^unlock_time[[:space:]]*=/{if($2+0>=900) exit 0; exit 1}' /etc/security/faillock.conf; then
      sec_audit_report_pass 179 "faillock unlock_time is configured minimum 900 seconds"
    else
      sec_audit_report_fail 179 "faillock unlock_time is not configured or set too low"
    fi

    if grep -qE '^even_deny_root' /etc/security/faillock.conf 2>/dev/null; then
      sec_audit_report_pass 180 "faillock even_deny_root is enabled"
    else
      sec_audit_report_fail 180 "faillock even_deny_root is not enabled"
    fi

    if grep -qE '^difok\s*=' /etc/security/pwquality.conf 2>/dev/null && awk -F= '/^difok/{gsub(/ /,"",$2); if($2+0>=2) exit 0; exit 1}' /etc/security/pwquality.conf; then
      sec_audit_report_pass 181 "pwquality difok is configured minimum 2 changed characters"
    else
      sec_audit_report_fail 181 "pwquality difok is not configured or set too low"
    fi

    if grep -qE '^minlen\s*=' /etc/security/pwquality.conf 2>/dev/null && awk -F= '/^minlen/{gsub(/ /,"",$2); if($2+0>=14) exit 0; exit 1}' /etc/security/pwquality.conf; then
      sec_audit_report_pass 182 "pwquality minimum password length is set to 14 or more"
    else
      sec_audit_report_fail 182 "pwquality minimum password length is not set or too short"
    fi

    if grep -qE '^maxrepeat\s*=' /etc/security/pwquality.conf 2>/dev/null && awk -F= '/^maxrepeat/{gsub(/ /,"",$2); if($2+0>0 && $2+0<=3) exit 0; exit 1}' /etc/security/pwquality.conf; then
      sec_audit_report_pass 183 "pwquality maxrepeat is configured max 3 consecutive identical characters"
    else
      sec_audit_report_fail 183 "pwquality maxrepeat is not configured"
    fi

    if grep -qE '^maxsequence\s*=' /etc/security/pwquality.conf 2>/dev/null && awk -F= '/^maxsequence/{gsub(/ /,"",$2); if($2+0>0 && $2+0<=3) exit 0; exit 1}' /etc/security/pwquality.conf; then
      sec_audit_report_pass 184 "pwquality maxsequence is configured max 3 sequential characters"
    else
      sec_audit_report_fail 184 "pwquality maxsequence is not configured"
    fi

    if grep -qE '^dictcheck\s*=\s*[^0]' /etc/security/pwquality.conf 2>/dev/null; then
      sec_audit_report_pass 185 "pwquality dictionary check dictcheck is enabled"
    else
      sec_audit_report_fail 185 "pwquality dictionary check is disabled"
    fi

    if grep -qE 'pam_pwquality\.so.*enforce_for_root|enforce_for_root' /etc/pam.d/common-password 2>/dev/null || grep -qE '^enforce_for_root' /etc/security/pwquality.conf 2>/dev/null; then
      sec_audit_report_pass 186 "pwquality checking is enforced enforce_for_root or equivalent"
    else
      sec_audit_report_fail 186 "pwquality checking is not enforced"
    fi

    if grep -qE '^enforce_for_root' /etc/security/pwquality.conf 2>/dev/null; then
      sec_audit_report_pass 187 "pwquality is enforced for the root user"
    else
      sec_audit_report_fail 187 "pwquality is not enforced for the root user"
    fi

    if grep -qE 'remember=[0-9]' /etc/pam.d/common-password 2>/dev/null || grep -qE '^remember\s*=' /etc/security/pwhistory.conf 2>/dev/null; then
      sec_audit_report_pass 188 "password history remember is configured in PAM"
    else
      sec_audit_report_fail 188 "password history is not configured in PAM"
    fi

    if grep -qE '^enforce_for_root' /etc/security/pwhistory.conf 2>/dev/null; then
      sec_audit_report_pass 189 "pwhistory enforce_for_root is enabled"
    else
      sec_audit_report_fail 189 "pwhistory enforce_for_root is not enabled"
    fi

    if grep -qE 'pam_pwhistory\.so.*use_authtok' /etc/pam.d/common-password 2>/dev/null; then
      sec_audit_report_pass 190 "pam_pwhistory includes use_authtok"
    else
      sec_audit_report_fail 190 "pam_pwhistory is missing use_authtok"
    fi

    if ! grep -qE 'pam_unix\.so.*nullok' /etc/pam.d/common-auth /etc/pam.d/common-account /etc/pam.d/common-password /etc/pam.d/common-session 2>/dev/null; then
      sec_audit_report_pass 191 "pam_unix does not include nullok parameter"
    else
      sec_audit_report_fail 191 "pam_unix includes nullok parameter empty passwords permitted"
    fi

    if ! grep -qE 'pam_unix\.so.*remember' /etc/pam.d/common-password 2>/dev/null; then
      sec_audit_report_pass 192 "pam_unix does not include remember parameter"
    else
      sec_audit_report_fail 192 "pam_unix includes remember parameter deprecated"
    fi

}

sec_audit_run_accounts() {
    # RULE193-214
    if grep -qE 'pam_unix\.so.*(sha512|yescrypt|bcrypt)' /etc/pam.d/common-password 2>/dev/null; then
      sec_audit_report_pass 193 "pam_unix uses a strong hashing algorithm yescrypt/sha512/bcrypt"
    else
      sec_audit_report_fail 193 "pam_unix is not configured to use a strong hashing algorithm"
    fi

    if grep -qE 'pam_unix\.so.*use_authtok' /etc/pam.d/common-password 2>/dev/null; then
      sec_audit_report_pass 194 "pam_unix includes use_authtok"
    else
      sec_audit_report_fail 194 "pam_unix is missing use_authtok"
    fi

    if awk '($1=="PASS_MAX_DAYS"){if($2+0<=365 && $2+0>0) exit 0; exit 1}' /etc/login.defs 2>/dev/null; then
      sec_audit_report_pass 195 "PASS_MAX_DAYS is set to 365 or less in /etc/login.defs"
    else
      sec_audit_report_fail 195 "PASS_MAX_DAYS is not configured or exceeds 365 days"
    fi

    if awk '($1=="PASS_WARN_AGE"){if($2+0>=7) exit 0; exit 1}' /etc/login.defs 2>/dev/null; then
      sec_audit_report_pass 196 "PASS_WARN_AGE is set to 7 or more days in /etc/login.defs"
    else
      sec_audit_report_fail 196 "PASS_WARN_AGE is not configured or set below 7 days"
    fi

    if grep -qE '^ENCRYPT_METHOD\s+(SHA512|yescrypt)' /etc/login.defs 2>/dev/null; then
      sec_audit_report_pass 197 "ENCRYPT_METHOD is SHA512 or yescrypt in /etc/login.defs"
    else
      sec_audit_report_fail 197 "ENCRYPT_METHOD is not set to a strong algorithm"
    fi

    if useradd -D 2>/dev/null | grep -qE '^INACTIVE=[0-9]' && useradd -D 2>/dev/null | awk -F= '/INACTIVE/{if($2+0>0 && $2+0<=30) exit 0; exit 1}'; then
      sec_audit_report_pass 198 "INACTIVE password lock period is configured 1-30 days"
    else
      sec_audit_report_fail 198 "INACTIVE password lock period is not configured or out of range"
    fi

    if [ "$(awk -F: '($2~/^\$/ && $3!~/^!/ && $3+0>0){today=int(systime()/86400); if($3+0>today) print $1}' /etc/shadow 2>/dev/null | wc -l)" -eq 0 ]; then
      sec_audit_report_pass 199 "all user password change dates are in the past"
    else
      sec_audit_report_fail 199 "one or more users have a future password change date"
    fi

    if [ $(awk -F: '($3==0){print $1}' /etc/passwd | wc -l) -eq 1 ] && awk -F: '($3==0){print $1}' /etc/passwd | grep -q '^root$'; then
      sec_audit_report_pass 200 "root is the only account with UID 0"
    else
      sec_audit_report_fail 200 "one or more non-root accounts have UID 0"
    fi

    if [ $(awk -F: '($4==0){print $1}' /etc/passwd | grep -v '^root$' | wc -l) -eq 0 ]; then
      sec_audit_report_pass 201 "only root has GID 0 as primary group"
    else
      sec_audit_report_fail 201 "one or more non-root users have GID 0 as primary group"
    fi

    if [ $(awk -F: '($3==0){print $1}' /etc/group | wc -l) -eq 1 ] && awk -F: '($3==0){print $1}' /etc/group | grep -q '^root$'; then
      sec_audit_report_pass 202 "root is the only group with GID 0"
    else
      sec_audit_report_fail 202 "one or more non-root groups have GID 0"
    fi

    if passwd -S root 2>/dev/null | grep -qE '^root (L|LK) '; then
      sec_audit_report_pass 203 "root account is locked no direct password login"
    else
      sec_audit_report_fail 203 "root account is not locked"
    fi

    if ! echo "$PATH" | grep -qE '(^|:)(\.|:|$)' && ! find $(echo "$PATH" | tr ':' ' ') -maxdepth 0 \( -perm -o+w -o ! -user root \) 2>/dev/null | grep -q .; then
      sec_audit_report_pass 204 "root PATH does not contain dot or world-writable directories"
    else
      sec_audit_report_fail 204 "root PATH contains dot or world-writable directories"
    fi

    if grep -qE '^\s*umask\s+0[027]7' /root/.bash_profile /root/.bashrc 2>/dev/null; then
      sec_audit_report_pass 205 "root umask is set to 027 or stricter"
    else
      sec_audit_report_fail 205 "root umask is not configured or too permissive"
    fi

    if ! awk -F: '($1!~/^(root|sync|shutdown|halt|nfsnobody)$/ && $3<1000 && $7!~/(\/sbin\/nologin|\/bin\/false)$/){print $1}' /etc/passwd 2>/dev/null | grep -q .; then
      sec_audit_report_pass 206 "all system accounts UID < 1000 have nologin or false as shell"
    else
      sec_audit_report_fail 206 "one or more system accounts have a valid interactive shell"
    fi

    _rule207_fail=$(awk -F: '($7~/\/sbin\/nologin|\/bin\/false/){print $1}' /etc/passwd 2>/dev/null | while read u; do passwd -S "$u" 2>/dev/null | grep -qE '^'"$u"' (L|LK) ' || echo "UNLOCKED"; done | grep -c 'UNLOCKED' 2>/dev/null)
    if [ "${_rule207_fail:-0}" -eq 0 ]; then
      sec_audit_report_pass 207 "all accounts with nologin/false shell are locked"
    else
      sec_audit_report_fail 207 "one or more nologin/false-shell accounts are not locked"
    fi

    if ! grep -q 'nologin' /etc/shells 2>/dev/null; then
      sec_audit_report_pass 208 "nologin is not listed in /etc/shells"
    else
      sec_audit_report_fail 208 "nologin is listed in /etc/shells"
    fi

    if grep -rqE '(TMOUT|readonly TMOUT)=([1-9][0-9]{1,3}|[1-9])\b' /etc/profile /etc/profile.d/*.sh /etc/bash.bashrc 2>/dev/null && grep -rqE 'readonly TMOUT|export TMOUT' /etc/profile /etc/profile.d/*.sh /etc/bash.bashrc 2>/dev/null; then
      sec_audit_report_pass 209 "TMOUT shell timeout is configured and exported/readonly"
    else
      sec_audit_report_fail 209 "TMOUT shell timeout is not configured"
    fi

    if grep -rqE '^\s*umask\s+(0[027]7|[027]7)' /etc/profile /etc/profile.d/*.sh /etc/bash.bashrc /etc/login.defs 2>/dev/null; then
      sec_audit_report_pass 210 "default umask is set to 027 or stricter in system profiles"
    else
      sec_audit_report_fail 210 "default umask is not configured or too permissive"
    fi

    if systemctl is-active systemd-journald 2>/dev/null | grep -q '^active' && systemctl is-enabled systemd-journald 2>/dev/null | grep -qE '^(enabled|static)'; then
      sec_audit_report_pass 211 "systemd-journald is enabled and running"
    else
      sec_audit_report_fail 211 "systemd-journald is not enabled or not running"
    fi

    active_loggers=$(systemctl is-active rsyslog systemd-journald syslog-ng 2>/dev/null | grep -c '^active')
    if [ "$active_loggers" -eq 1 ]; then
      sec_audit_report_pass 212 "only one logging system is active not both rsyslog and journald"
    else
      sec_audit_report_fail 212 "multiple logging systems are active simultaneously"
    fi

    if dpkg-query -W -f='${Status}' systemd-journal-remote 2>/dev/null | grep -q 'install ok installed'; then
      sec_audit_report_pass 213 "systemd-journal-remote is installed"
    else
      sec_audit_report_fail 213 "systemd-journal-remote is not installed"
    fi

    if systemctl is-active systemd-journal-upload 2>/dev/null | grep -q '^active' && systemctl is-enabled systemd-journal-upload 2>/dev/null | grep -q '^enabled'; then
      sec_audit_report_pass 214 "systemd-journal-upload is enabled and running"
    else
      sec_audit_report_fail 214 "systemd-journal-upload is not enabled or not running"
    fi

}

sec_audit_run_logging() {
    # RULE215-228
    if ! systemctl is-active systemd-journal-remote.socket 2>/dev/null | grep -q '^active'; then
      sec_audit_report_pass 215 "systemd-journal-remote socket is not active"
    else
      sec_audit_report_fail 215 "systemd-journal-remote socket is active unexpected"
    fi

    if ! sec_audit_is_service_active rsyslog && \
       (grep -qE '^[[:space:]]*ForwardToSyslog[[:space:]]*=[[:space:]]*no[[:space:]]*$' /etc/systemd/journald.conf 2>/dev/null || \
    grep -rqE '^[[:space:]]*ForwardToSyslog[[:space:]]*=[[:space:]]*no[[:space:]]*$' /etc/systemd/journald.conf.d/ 2>/dev/null); then
      sec_audit_report_pass 216 "journald ForwardToSyslog is set to no"
    else
      sec_audit_report_fail 216 "journald ForwardToSyslog is not set to no"
    fi

    if grep -qE '^Compress=yes' /etc/systemd/journald.conf 2>/dev/null || grep -rqE '^Compress=yes' /etc/systemd/journald.conf.d/ 2>/dev/null; then
      sec_audit_report_pass 217 "journald Compress is set to yes"
    else
      sec_audit_report_fail 217 "journald Compress is not set to yes"
    fi

    if grep -qE '^Storage=persistent' /etc/systemd/journald.conf 2>/dev/null || grep -rqE '^Storage=persistent' /etc/systemd/journald.conf.d/ 2>/dev/null; then
      sec_audit_report_pass 218 "journald Storage is set to persistent"
    else
      sec_audit_report_fail 218 "journald Storage is not set to persistent"
    fi

    if dpkg-query -W -f='${Status}' rsyslog 2>/dev/null | grep -q 'install ok installed'; then
      sec_audit_report_pass 219 "rsyslog is installed"
    else
      sec_audit_report_fail 219 "rsyslog is not installed"
    fi

    if systemctl is-active rsyslog 2>/dev/null | grep -q '^active' && systemctl is-enabled rsyslog 2>/dev/null | grep -q '^enabled'; then
      sec_audit_report_pass 220 "rsyslog service is enabled and running"
    else
      sec_audit_report_fail 220 "rsyslog service is not enabled or not running"
    fi

    if sec_audit_is_service_active rsyslog && \
       (grep -qE '^[[:space:]]*ForwardToSyslog[[:space:]]*=[[:space:]]*yes[[:space:]]*$' /etc/systemd/journald.conf 2>/dev/null || \
    grep -rqE '^[[:space:]]*ForwardToSyslog[[:space:]]*=[[:space:]]*yes[[:space:]]*$' /etc/systemd/journald.conf.d/ 2>/dev/null); then
      sec_audit_report_pass 221 "journald ForwardToSyslog is set to yes forwarding to rsyslog"
    else
      sec_audit_report_fail 221 "journald ForwardToSyslog is not set to yes"
    fi

    if grep -qE '^\$FileCreateMode 06[024]0' /etc/rsyslog.conf 2>/dev/null || grep -rqE '^\$FileCreateMode 06[024]0' /etc/rsyslog.d/ 2>/dev/null; then
      sec_audit_report_pass 222 "rsyslog FileCreateMode is set to 0640 or stricter"
    else
      sec_audit_report_fail 222 "rsyslog FileCreateMode is not configured or too permissive"
    fi

    if ! grep -qE '^(module|input).*imtcp|^(module|input).*imudp' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null; then
      sec_audit_report_pass 223 "rsyslog is not configured to receive logs from remote clients"
    else
      sec_audit_report_fail 223 "rsyslog is configured to receive remote logs imtcp/imudp active"
    fi

    if ! find /var/log -type f -perm /037 2>/dev/null | grep -q . && ! find /var/log -type d -perm /026 2>/dev/null | grep -q .; then
      sec_audit_report_pass 224 "all files in /var/log have restricted permissions"
    else
      sec_audit_report_fail 224 "one or more log files have overly permissive access"
    fi

    if sec_audit_is_package_installed auditd; then
      sec_audit_report_pass 225 "auditd package is installed"
    else
      sec_audit_report_fail 225 "auditd package is not installed"
    fi

    if systemctl is-active auditd 2>/dev/null | grep -q '^active' && systemctl is-enabled auditd 2>/dev/null | grep -q '^enabled'; then
      sec_audit_report_pass 226 "auditd service is enabled and running"
    else
      sec_audit_report_fail 226 "auditd service is not enabled or not running"
    fi

    if grep -qE 'audit=1' /proc/cmdline; then
      sec_audit_report_pass 227 "audit=1 is present in kernel boot parameters"
    else
      sec_audit_report_fail 227 "audit=1 is missing from kernel boot parameters"
    fi

    if grep -qE 'audit_backlog_limit=[0-9]+' /proc/cmdline && grep -oE 'audit_backlog_limit=[0-9]+' /proc/cmdline | awk -F= '{if($2>=8192) exit 0; exit 1}'; then
      sec_audit_report_pass 228 "audit_backlog_limit is set to 8192 or higher"
    else
      sec_audit_report_fail 228 "audit_backlog_limit is not set or set too low"
    fi

}

sec_audit_run_auditd() {
    # RULE229-255
    if grep -qE '^max_log_file\s*=\s*[0-9]+' /etc/audit/auditd.conf 2>/dev/null; then
      sec_audit_report_pass 229 "auditd max_log_file size is configured"
    else
      sec_audit_report_fail 229 "auditd max_log_file is not configured"
    fi

    if grep -qE '^max_log_file_action\s*=\s*keep_logs' /etc/audit/auditd.conf 2>/dev/null; then
      sec_audit_report_pass 230 "auditd max_log_file_action is set to keep_logs"
    else
      sec_audit_report_fail 230 "auditd max_log_file_action is not set to keep_logs"
    fi

    if grep -qE '^space_left_action\s*=\s*(email|exec|single|halt)' /etc/audit/auditd.conf 2>/dev/null && grep -qE '^admin_space_left_action\s*=\s*(single|halt)' /etc/audit/auditd.conf 2>/dev/null; then
      sec_audit_report_pass 231 "auditd is configured to halt or notify when disk is full"
    else
      sec_audit_report_fail 231 "auditd is not configured to halt or notify when disk is full"
    fi

    if grep -qE '^space_left\s*=\s*[0-9]+' /etc/audit/auditd.conf 2>/dev/null && grep -qE '^space_left_action\s*=\s*email' /etc/audit/auditd.conf 2>/dev/null; then
      sec_audit_report_pass 232 "auditd space_left_action is set to email"
    else
      sec_audit_report_fail 232 "auditd space_left_action is not configured"
    fi

    if sec_audit_audit_rules_files_grep -E -- -w /etc/sudoers\b && sec_audit_audit_rules_files_grep -E -- -w /etc/sudoers.d; then
      sec_audit_report_pass 233 "audit rules monitor changes to /etc/sudoers and sudoers.d"
    else
      sec_audit_report_fail 233 "audit rules for /etc/sudoers changes are missing"
    fi

    if sec_audit_audit_rules_files_grep -E -- -a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve; then
      sec_audit_report_pass 234 "audit rules collect execve calls with UID change user emulation"
    else
      sec_audit_report_fail 234 "audit rules for actions as another user are missing"
    fi

    if sec_audit_audit_rules_files_grep -E -- -w.*sudo.log; then
      sec_audit_report_pass 235 "audit rules monitor modifications to the sudo log file"
    else
      sec_audit_report_fail 235 "audit rules for sudo log file modifications are missing"
    fi

    if sec_audit_audit_rules_files_grep -E -- -a always,exit -F arch=b64 -S adjtimex; then
      sec_audit_report_pass 236 "audit rules collect date and time modification syscalls"
    else
      sec_audit_report_fail 236 "audit rules for date/time modification are missing"
    fi

    if sec_audit_audit_rule_loaded_and_on_disk -E -- '-a always,exit -S execve -F euid=0' || sec_audit_audit_rule_loaded_and_on_disk -- '-a always,exit -S execve -F euid=0'; then
      sec_audit_report_pass 237 "audit rules collect usage of all privileged setuid/setgid commands"
    else
      sec_audit_report_fail 237 "audit rules for privileged commands are missing or incomplete"
    fi

    if sec_audit_audit_rules_files_grep -E -- -a always,exit -F arch=b64 -S creat.*-S open.*-F exit=-EACCES; then
      sec_audit_report_pass 238 "audit rules collect failed file access attempts EACCES/EPERM"
    else
      sec_audit_report_fail 238 "audit rules for failed file access attempts are missing"
    fi

    if sec_audit_audit_rules_files_grep -E -- -w /etc/passwd\b && sec_audit_audit_rules_files_grep -E -- -w /etc/group\b; then
      sec_audit_report_pass 239 "audit rules monitor changes to /etc/passwd, /etc/group, and shadow files"
    else
      sec_audit_report_fail 239 "audit rules for user/group information changes are missing"
    fi

    if sec_audit_audit_rules_files_grep -E -- -a always,exit -F arch=b64 -S mount; then
      sec_audit_report_pass 240 "audit rules collect successful filesystem mount events"
    else
      sec_audit_report_fail 240 "audit rules for filesystem mounts are missing"
    fi

    if sec_audit_audit_rules_files_grep -E -- -w /var/run/utmp\b && sec_audit_audit_rules_files_grep -E -- -w /var/log/wtmp\b; then
      sec_audit_report_pass 241 "audit rules monitor /var/run/utmp, /var/log/wtmp session files"
    else
      sec_audit_report_fail 241 "audit rules for session initiation files are missing"
    fi

    if sec_audit_audit_rules_files_grep -E -- -w /var/log/faillog\b && sec_audit_audit_rules_files_grep -E -- -w /var/log/lastlog\b; then
      sec_audit_report_pass 242 "audit rules monitor /var/log/faillog and lastlog for login events"
    else
      sec_audit_report_fail 242 "audit rules for login/logout events are missing"
    fi

    if sec_audit_audit_rules_files_grep -E -- -a always,exit -F arch=b64 -S unlink; then
      sec_audit_report_pass 243 "audit rules collect file deletion events unlink, rename"
    else
      sec_audit_report_fail 243 "audit rules for file deletion events are missing"
    fi

    if sec_audit_audit_rules_files_grep -E -- -a always,exit -F arch=b64 -S init_module && sec_audit_audit_rules_files_grep -E -- -w /sbin/insmod\b; then
      sec_audit_report_pass 244 "audit rules monitor kernel module load, unload, and modification"
    else
      sec_audit_report_fail 244 "audit rules for kernel module operations are missing"
    fi

    if sec_audit_audit_rules_files_grep -E -- '^-e[[:space:]]+2\b' && sec_audit_auditctl_rules_grep -E -- '^-e[[:space:]]+2\b'; then
      sec_audit_report_pass 245 "audit configuration is immutable (-e 2 on disk and loaded)"
    else
      sec_audit_report_fail 245 "audit configuration is not immutable (-e 2 missing on disk or in loaded rules)"
    fi

    _audit_log_dir="$(awk -F= '/^\s*log_file\s*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' /etc/audit/auditd.conf 2>/dev/null | xargs dirname 2>/dev/null)"
    [ -n "$_audit_log_dir" ] || _audit_log_dir="/var/log/audit"

    if ! find "$_audit_log_dir" -maxdepth 1 -type f -perm /137 2>/dev/null | grep -q .; then
      sec_audit_report_pass 246 "audit log files have permissions 600 or stricter"
    else
      sec_audit_report_fail 246 "audit log files have overly permissive access"
    fi

    if ! find "$_audit_log_dir" -maxdepth 1 -type f ! -user root 2>/dev/null | grep -q .; then
      sec_audit_report_pass 247 "audit log files are owned by root"
    else
      sec_audit_report_fail 247 "audit log files are not owned by root"
    fi

    if ! find "$_audit_log_dir" -maxdepth 1 -type f ! -group root 2>/dev/null | grep -q .; then
      sec_audit_report_pass 248 "audit log files belong to group root"
    else
      sec_audit_report_fail 248 "audit log files do not belong to group root"
    fi

    if stat -Lc '%a' "$_audit_log_dir" 2>/dev/null | grep -qE '^[0-7][0-5]0$'; then
      sec_audit_report_pass 249 "audit log directory has permissions 700 or 750"
    else
      sec_audit_report_fail 249 "audit log directory permissions are too permissive"
    fi

    if ! find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) 2>/dev/null | xargs stat -Lc '%a' 2>/dev/null | grep -qvE '^[0-6][04]0$'; then
      sec_audit_report_pass 250 "audit configuration files have permissions 640 or stricter"
    else
      sec_audit_report_fail 250 "audit configuration files have overly permissive access"
    fi

    if ! find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -user root 2>/dev/null | grep -q .; then
      sec_audit_report_pass 251 "audit configuration files are owned by root"
    else
      sec_audit_report_fail 251 "audit configuration files are not owned by root"
    fi

    if ! find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -group root 2>/dev/null | grep -q .; then
      sec_audit_report_pass 252 "audit configuration files belong to group root"
    else
      sec_audit_report_fail 252 "audit configuration files do not belong to group root"
    fi

    if ! stat -Lc '%a' /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules 2>/dev/null | grep -qvE '^[0-7][05]5$'; then
      sec_audit_report_pass 253 "audit tools have correct permissions 755 or stricter"
    else
      sec_audit_report_fail 253 "audit tools have overly permissive access"
    fi

    if ! stat -Lc '%U' /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules 2>/dev/null | grep -qv '^root$'; then
      sec_audit_report_pass 254 "audit tools are owned by root"
    else
      sec_audit_report_fail 254 "audit tools are not owned by root"
    fi

    if ! stat -Lc '%G' /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules 2>/dev/null | grep -qv '^root$'; then
      sec_audit_report_pass 255 "audit tools belong to group root"
    else
      sec_audit_report_fail 255 "audit tools do not belong to group root"
    fi

}

sec_audit_run_aide() {
    # RULE256-257
    if dpkg-query -W -f='${Status}' aide 2>/dev/null | grep -q 'install ok installed'; then
      sec_audit_report_pass 256 "AIDE is installed"
    else
      sec_audit_report_fail 256 "AIDE is not installed"
    fi

    if systemctl is-enabled aidecheck 2>/dev/null | grep -q '^enabled' || crontab -l 2>/dev/null | grep -q 'aide' || grep -rq 'aide' /etc/cron.* /var/spool/cron/ 2>/dev/null; then
      sec_audit_report_pass 257 "filesystem integrity check AIDE is scheduled in cron or systemd"
    else
      sec_audit_report_fail 257 "no scheduled filesystem integrity check found"
    fi

}

sec_audit_run_identity_files() {
    # RULE258-267
    if stat -Lc '%a %U %G' /etc/passwd 2>/dev/null | grep -qE '^644 root root$'; then
      sec_audit_report_pass 258 "/etc/passwd has permissions 644 and is owned by root"
    else
      sec_audit_report_fail 258 "/etc/passwd permissions or ownership are incorrect"
    fi

    if stat -Lc '%a %U %G' /etc/passwd- 2>/dev/null | grep -qE '^[0-6][04][04] root root$'; then
      sec_audit_report_pass 259 "/etc/passwd- has permissions 644 or stricter and is owned by root"
    else
      sec_audit_report_fail 259 "/etc/passwd- permissions or ownership are incorrect"
    fi

    if stat -Lc '%a %U %G' /etc/group 2>/dev/null | grep -qE '^644 root root$'; then
      sec_audit_report_pass 260 "/etc/group has permissions 644 and is owned by root"
    else
      sec_audit_report_fail 260 "/etc/group permissions or ownership are incorrect"
    fi

    if stat -Lc '%a %U %G' /etc/group- 2>/dev/null | grep -qE '^[0-6][04][04] root root$'; then
      sec_audit_report_pass 261 "/etc/group- has permissions 644 or stricter and is owned by root"
    else
      sec_audit_report_fail 261 "/etc/group- permissions or ownership are incorrect"
    fi

    if stat -Lc '%a %U %G' /etc/shadow 2>/dev/null | grep -qE '^[0-6]00 root (root|shadow)$'; then
      sec_audit_report_pass 262 "/etc/shadow has permissions 000 or 640 and is owned by root"
    else
      sec_audit_report_fail 262 "/etc/shadow permissions or ownership are incorrect"
    fi

    if stat -Lc '%a %U %G' /etc/shadow- 2>/dev/null | grep -qE '^[0-6]00 root (root|shadow)$'; then
      sec_audit_report_pass 263 "/etc/shadow- has permissions 000 or 640 and is owned by root"
    else
      sec_audit_report_fail 263 "/etc/shadow- permissions or ownership are incorrect"
    fi

    if stat -Lc '%a %U %G' /etc/gshadow 2>/dev/null | grep -qE '^[0-6]00 root (root|shadow)$'; then
      sec_audit_report_pass 264 "/etc/gshadow has permissions 000 or 640 and is owned by root"
    else
      sec_audit_report_fail 264 "/etc/gshadow permissions or ownership are incorrect"
    fi

    if stat -Lc '%a %U %G' /etc/gshadow- 2>/dev/null | grep -qE '^[0-6]00 root (root|shadow)$'; then
      sec_audit_report_pass 265 "/etc/gshadow- has permissions 000 or 640 and is owned by root"
    else
      sec_audit_report_fail 265 "/etc/gshadow- permissions or ownership are incorrect"
    fi

    if stat -Lc '%a %U %G' /etc/shells 2>/dev/null | grep -qE '^[0-6][04][04] root root$'; then
      sec_audit_report_pass 266 "/etc/shells has correct permissions and is owned by root"
    else
      sec_audit_report_fail 266 "/etc/shells permissions or ownership are incorrect"
    fi

    if [ ! -f /etc/security/opasswd ] || stat -Lc '%a %U %G' /etc/security/opasswd 2>/dev/null | grep -qE '^[0-6]00 root root$'; then
      sec_audit_report_pass 267 "/etc/security/opasswd has permissions 600 and is owned by root"
    else
      sec_audit_report_fail 267 "/etc/security/opasswd permissions or ownership are incorrect"
    fi

}

sec_audit_run_filesystem_integrity() {
    # RULE268-277
    if ! sec_audit_list_local_system_mounts | while IFS= read -r mp; do
      find "$mp" -xdev \( -type f -o -type d \) -perm -0002 -print -quit 2>/dev/null
    done | grep -q .; then
      sec_audit_report_pass 268 "no world-writable files or directories found on local filesystems"
    else
      sec_audit_report_fail 268 "world-writable files or directories exist on local filesystems"
    fi

    if ! sec_audit_list_local_system_mounts | while IFS= read -r mp; do
      find "$mp" -xdev \( -nouser -o -nogroup \) -print -quit 2>/dev/null
    done | grep -q .; then
      sec_audit_report_pass 269 "no unowned or ungrouped files found on local filesystems"
    else
      sec_audit_report_fail 269 "unowned or ungrouped files exist on local filesystems"
    fi

    if ! awk -F: '($2!="x"){print $1}' /etc/passwd 2>/dev/null | grep -q .; then
      sec_audit_report_pass 270 "all accounts in /etc/passwd use shadowed passwords field = x"
    else
      sec_audit_report_fail 270 "one or more accounts store passwords directly in /etc/passwd"
    fi

    if ! awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null | grep -q .; then
      sec_audit_report_pass 271 "no accounts in /etc/shadow have an empty password field"
    else
      sec_audit_report_fail 271 "one or more accounts have an empty password field in /etc/shadow"
    fi

    if [ $(awk -F: '{print $3}' /etc/passwd 2>/dev/null | sort | uniq -d | wc -l) -eq 0 ]; then
      sec_audit_report_pass 272 "no duplicate UIDs exist in /etc/passwd"
    else
      sec_audit_report_fail 272 "duplicate UIDs found in /etc/passwd"
    fi

    if [ $(awk -F: '{print $3}' /etc/group 2>/dev/null | sort | uniq -d | wc -l) -eq 0 ]; then
      sec_audit_report_pass 273 "no duplicate GIDs exist in /etc/group"
    else
      sec_audit_report_fail 273 "duplicate GIDs found in /etc/group"
    fi

    if [ $(awk -F: '{print $1}' /etc/passwd 2>/dev/null | sort | uniq -d | wc -l) -eq 0 ]; then
      sec_audit_report_pass 274 "no duplicate usernames exist in /etc/passwd"
    else
      sec_audit_report_fail 274 "duplicate usernames found in /etc/passwd"
    fi

    if [ $(awk -F: '{print $1}' /etc/group 2>/dev/null | sort | uniq -d | wc -l) -eq 0 ]; then
      sec_audit_report_pass 275 "no duplicate group names exist in /etc/group"
    else
      sec_audit_report_fail 275 "duplicate group names found in /etc/group"
    fi

    if ! awk -F: '($1!~/^(halt|sync|shutdown|nfsnobody)$/ && $7!~/(\/sbin\/nologin|\/bin\/false)$/ && $3>=1000){if(system("test -d " $6 " >/dev/null 2>&1")!=0) print $1}' /etc/passwd 2>/dev/null | grep -q .; then
      sec_audit_report_pass 276 "all interactive user home directories exist"
    else
      sec_audit_report_fail 276 "one or more interactive users are missing a home directory"
    fi

    if ! awk -F: '($7!~/(\/sbin\/nologin|\/bin\/false)$/ && $3>=1000){print $6}' /etc/passwd 2>/dev/null | xargs -I{} find {} -maxdepth 1 -name '.*' -perm /022 2>/dev/null | grep -q .; then
      sec_audit_report_pass 277 "no world- or group-writable dot files found in user home directories"
    else
      sec_audit_report_fail 277 "world- or group-writable dot files found in user home directories"
    fi

}

sec_audit_main() {
    sec_audit_run_kernel_modules
    sec_audit_run_filesystem_partitions
    sec_audit_run_apparmor
    sec_audit_run_bootloader
    sec_audit_run_process_hardening
    sec_audit_run_banners
    sec_audit_run_gdm
    sec_audit_run_unused_services
    sec_audit_run_client_tools
    sec_audit_run_chrony
    sec_audit_run_cron_at
    sec_audit_run_network_stack
    sec_audit_run_firewall
    sec_audit_run_sshd
    sec_audit_run_sudo_su
    sec_audit_run_pam_auth
    sec_audit_run_accounts
    sec_audit_run_logging
    sec_audit_run_auditd
    sec_audit_run_aide
    sec_audit_run_identity_files
    sec_audit_run_filesystem_integrity
    exit 0
}

sec_audit_main "$@"
