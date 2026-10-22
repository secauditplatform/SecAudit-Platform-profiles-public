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

AL10_FIND_CAP="${AL10_FIND_CAP:-${CRE_FIND_CAP:-20}}"
AL10_CMD_CAP="${AL10_CMD_CAP:-${CRE_CMD_CAP:-12}}"
AL10_DNF_CAP="${AL10_DNF_CAP:-${CRE_DNF_CAP:-30}}"
AL10_ALLOW_CONTAINER_KMOD="${AL10_ALLOW_CONTAINER_KMOD:-${CRE_ALLOW_CONTAINER_KMOD:-${LINUX_CRE_ALLOW_CONTAINER_MODULES:-${ALMA_CRE_ALLOW_CONTAINER_MODULES:-0}}}}"
CRE_FIND_CAP="$AL10_FIND_CAP"
CRE_CMD_CAP="$AL10_CMD_CAP"
CRE_DNF_CAP="$AL10_DNF_CAP"
CRE_ALLOW_CONTAINER_KMOD="$AL10_ALLOW_CONTAINER_KMOD"

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
    n=$(sec_audit_exec_with_timeout "$AL10_DNF_CAP" dnf -q repolist enabled 2>/dev/null | awk '
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
    local pattern="$1" cap="${2:-$AL10_FIND_CAP}" rc=0 out=""
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
            [[ "${AL10_ALLOW_CONTAINER_KMOD}" == "1" ]]
            ;;
        *) return 1 ;;
    esac
}

sec_audit_assert_kmod_disabled() {
    local num="$1" label="$2" mod="$3" ko_pattern="$4"
    shift 4
    local alias loaded=0 a
    if sec_audit_kmod_container_exception "$mod"; then
        sec_audit_report_pass "$num" "${label} (waived: AL10_ALLOW_CONTAINER_KMOD=1)"
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

# --- compatibility aliases used by preserved RHEL rule bodies ---
sec_audit_low_impact_find() { sec_audit_soft_find "$@"; }
sec_audit_low_impact_find_timed_out() { sec_audit_find_hit_timeout "$@"; }
sec_audit_safe_find_roots() { sec_audit_local_fs_roots; }
sec_audit_pkg_is_installed() { sec_audit_rpm_any_installed "$@"; }
sec_audit_pkg_installed() { sec_audit_rpm_any_installed "$@"; }
sec_audit_mount_persisted() { sec_audit_mount_is_persisted "$@"; }
sec_audit_findmnt_have() { sec_audit_findmnt_available; }
sec_audit_findmnt_path_resolvable() { sec_audit_mount_resolves "$@"; }
sec_audit_findmnt_is_explicit_mountpoint() { sec_audit_mount_is_dedicated "$@"; }
sec_audit_findmnt_source_for() { sec_audit_mount_source "$@"; }
sec_audit_findmnt_fstype_for() { sec_audit_mount_fstype "$@"; }
sec_audit_findmnt_options_raw() { sec_audit_mount_options "$@"; }
sec_audit_findmnt_has_mnt_option() { sec_audit_mount_has_option "$@"; }
sec_audit_findmnt_separate_partition_ok() { sec_audit_path_is_isolated_volume "$@"; }
sec_audit_kernel_mod_in_modules_load() { sec_audit_kmod_autoload_listed "$@"; }
sec_audit_kernel_mod_lsmod_name_loaded() { sec_audit_kmod_is_loaded "$@"; }
sec_audit_kernel_mod_ko_scan() { sec_audit_kmod_object_exists "$@"; }
sec_audit_kernel_mod_refuses_load() { sec_audit_kmod_is_blocked "$@"; }
sec_audit_kernel_mod_cre_waiver() { sec_audit_kmod_container_exception "$@"; }
sec_audit_systemd_unit_enabled_or_active() { sec_audit_systemd_unit_live "$@"; }
sec_audit_findmnt_tmp_sec_ok() { sec_audit_tmp_is_isolated; }
sec_audit_findmnt_shm_sec_ok() { sec_audit_shm_is_isolated; }

# =============================================================================
# Rule section runners (RULE1 .. RULE328)
# =============================================================================

sec_audit_run_kernel_modules() {
    sec_audit_assert_kmod_disabled 1 "cramfs kernel module" cramfs cramfs.ko* "cramfs"
    sec_audit_assert_kmod_disabled 2 "freevxfs kernel module" freevxfs freevxfs.ko* "freevxfs"
    sec_audit_assert_kmod_disabled 3 "hfs kernel module" hfs hfs.ko* "hfs"
    sec_audit_assert_kmod_disabled 4 "hfsplus kernel module" hfsplus hfsplus.ko* "hfsplus"
    sec_audit_assert_kmod_disabled 5 "jffs2 kernel module" jffs2 jffs2.ko* "jffs2"
    sec_audit_assert_kmod_disabled 6 "overlay kernel module" overlay overlay.ko* "overlay"
    sec_audit_assert_kmod_disabled 7 "squashfs kernel module" squashfs squashfs.ko* "squashfs"
    sec_audit_assert_kmod_disabled 8 "udf kernel module" udf udf.ko* "udf"
    sec_audit_assert_kmod_disabled 9 "firewire-core kernel module" firewire_core firewire-core.ko* "firewire_core" "firewire-core"
    sec_audit_assert_kmod_disabled 10 "usb-storage kernel module" usb_storage usb-storage.ko* "usb_storage" "usb-storage"
    # RULE11:
    unused_fail=0
    unused_detail=""
    if lsmod 2>/dev/null | grep -q "\bceph\b"; then unused_fail=1; unused_detail="${unused_detail} ceph:loaded"; fi
    if modprobe --showconfig 2>/dev/null | grep -Pq "^\h*(blacklist|install)\h+ceph\b"; then :; else if modprobe -n -v ceph 2>/dev/null | grep -q .; then unused_fail=1; unused_detail="${unused_detail} ceph:available"; fi; fi
    if lsmod 2>/dev/null | grep -q "\bcifs\b"; then unused_fail=1; unused_detail="${unused_detail} cifs:loaded"; fi
    if modprobe --showconfig 2>/dev/null | grep -Pq "^\h*(blacklist|install)\h+cifs\b"; then :; else if modprobe -n -v cifs 2>/dev/null | grep -q .; then unused_fail=1; unused_detail="${unused_detail} cifs:available"; fi; fi
    if lsmod 2>/dev/null | grep -q "\bexfat\b"; then unused_fail=1; unused_detail="${unused_detail} exfat:loaded"; fi
    if modprobe --showconfig 2>/dev/null | grep -Pq "^\h*(blacklist|install)\h+exfat\b"; then :; else if modprobe -n -v exfat 2>/dev/null | grep -q .; then unused_fail=1; unused_detail="${unused_detail} exfat:available"; fi; fi
    if lsmod 2>/dev/null | grep -q "\bext\b"; then unused_fail=1; unused_detail="${unused_detail} ext:loaded"; fi
    if modprobe --showconfig 2>/dev/null | grep -Pq "^\h*(blacklist|install)\h+ext\b"; then :; else if modprobe -n -v ext 2>/dev/null | grep -q .; then unused_fail=1; unused_detail="${unused_detail} ext:available"; fi; fi
    if lsmod 2>/dev/null | grep -q "\bfat\b"; then unused_fail=1; unused_detail="${unused_detail} fat:loaded"; fi
    if modprobe --showconfig 2>/dev/null | grep -Pq "^\h*(blacklist|install)\h+fat\b"; then :; else if modprobe -n -v fat 2>/dev/null | grep -q .; then unused_fail=1; unused_detail="${unused_detail} fat:available"; fi; fi
    if lsmod 2>/dev/null | grep -q "\bfscache\b"; then unused_fail=1; unused_detail="${unused_detail} fscache:loaded"; fi
    if modprobe --showconfig 2>/dev/null | grep -Pq "^\h*(blacklist|install)\h+fscache\b"; then :; else if modprobe -n -v fscache 2>/dev/null | grep -q .; then unused_fail=1; unused_detail="${unused_detail} fscache:available"; fi; fi
    if lsmod 2>/dev/null | grep -q "\bfuse\b"; then unused_fail=1; unused_detail="${unused_detail} fuse:loaded"; fi
    if modprobe --showconfig 2>/dev/null | grep -Pq "^\h*(blacklist|install)\h+fuse\b"; then :; else if modprobe -n -v fuse 2>/dev/null | grep -q .; then unused_fail=1; unused_detail="${unused_detail} fuse:available"; fi; fi
    if lsmod 2>/dev/null | grep -q "\bgfs2\b"; then unused_fail=1; unused_detail="${unused_detail} gfs2:loaded"; fi
    if modprobe --showconfig 2>/dev/null | grep -Pq "^\h*(blacklist|install)\h+gfs2\b"; then :; else if modprobe -n -v gfs2 2>/dev/null | grep -q .; then unused_fail=1; unused_detail="${unused_detail} gfs2:available"; fi; fi
    if lsmod 2>/dev/null | grep -q "\bnfs_common\b"; then unused_fail=1; unused_detail="${unused_detail} nfs_common:loaded"; fi
    if modprobe --showconfig 2>/dev/null | grep -Pq "^\h*(blacklist|install)\h+nfs_common\b"; then :; else if modprobe -n -v nfs_common 2>/dev/null | grep -q .; then unused_fail=1; unused_detail="${unused_detail} nfs_common:available"; fi; fi
    if lsmod 2>/dev/null | grep -q "\bnfsd\b"; then unused_fail=1; unused_detail="${unused_detail} nfsd:loaded"; fi
    if modprobe --showconfig 2>/dev/null | grep -Pq "^\h*(blacklist|install)\h+nfsd\b"; then :; else if modprobe -n -v nfsd 2>/dev/null | grep -q .; then unused_fail=1; unused_detail="${unused_detail} nfsd:available"; fi; fi
    if lsmod 2>/dev/null | grep -q "\bsmbfs_common\b"; then unused_fail=1; unused_detail="${unused_detail} smbfs_common:loaded"; fi
    if modprobe --showconfig 2>/dev/null | grep -Pq "^\h*(blacklist|install)\h+smbfs_common\b"; then :; else if modprobe -n -v smbfs_common 2>/dev/null | grep -q .; then unused_fail=1; unused_detail="${unused_detail} smbfs_common:available"; fi; fi
    if [ "${unused_fail:-0}" -eq 0 ]; then
    sec_audit_report_pass 11 "Unused filesystem kernel modules are not loaded and not available"
    else
    sec_audit_report_fail 11 "Unused filesystem module issue(s):${unused_detail}"
    fi
}

sec_audit_run_filesystem_partitions() {
    sec_audit_assert_isolated_mount 12 /tmp "/tmp is tmpfs or a separate partition" tmp
    sec_audit_assert_mount_option 13 /tmp nodev
    sec_audit_assert_mount_option 14 /tmp nosuid
    sec_audit_assert_mount_option 15 /tmp noexec
    sec_audit_assert_isolated_mount 16 /dev/shm "/dev/shm is tmpfs or a separate partition" shm
    sec_audit_assert_mount_option 17 /dev/shm nodev
    sec_audit_assert_mount_option 18 /dev/shm nosuid
    sec_audit_assert_mount_option 19 /dev/shm noexec
    sec_audit_assert_isolated_mount 20 /home "separate partition exists for /home"
    sec_audit_assert_mount_option 21 /home nodev
    sec_audit_assert_mount_option 22 /home nosuid
    sec_audit_assert_isolated_mount 23 /var "separate partition exists for /var"
    sec_audit_assert_mount_option 24 /var nodev
    sec_audit_assert_mount_option 25 /var nosuid
    sec_audit_assert_isolated_mount 26 /var/tmp "separate partition exists for /var/tmp"
    sec_audit_assert_mount_option 27 /var/tmp nodev
    sec_audit_assert_mount_option 28 /var/tmp nosuid
    sec_audit_assert_mount_option 29 /var/tmp noexec
    sec_audit_assert_isolated_mount 30 /var/log "separate partition exists for /var/log"
    sec_audit_assert_mount_option 31 /var/log nodev
    sec_audit_assert_mount_option 32 /var/log nosuid
    sec_audit_assert_mount_option 33 /var/log noexec
    sec_audit_assert_isolated_mount 34 /var/log/audit "separate partition exists for /var/log/audit"
    sec_audit_assert_mount_option 35 /var/log/audit nodev
    sec_audit_assert_mount_option 36 /var/log/audit nosuid
    sec_audit_assert_mount_option 37 /var/log/audit noexec
}

sec_audit_run_package_security() {
    # RULE38:
    _rule37_k=$(sec_audit_rpm_gpg_pubkey_pkg_count)
    _rule37_sample=""
    if sec_audit_have_bin rpm && [ "${_rule37_k:-0}" -gt 0 ]; then
    _rule37_sample=$(
        rpm -qa 'gpg-pubkey*' --qf '%{VERSION}\n' 2>/dev/null | awk 'NF && NR <= 6 { s = (s ? s "," : s) $1 } END { print s }'
    )
    fi
    if ! sec_audit_have_bin rpm; then
    sec_audit_report_fail 38 "rpm not available; cannot verify gpg-pubkey packages in the RPM database"
    elif [ "${_rule37_k:-0}" -eq 0 ]; then
    sec_audit_report_fail 38 "no gpg-pubkey packages in the RPM database (import distribution or repository signing keys)"
    else
    sec_audit_report_pass 38 "${_rule37_k} gpg-pubkey package(s) in RPM DB (sample key VERSION ids: ${_rule37_sample:-n/a})"
    fi

    # RULE39:
    _rule38_main=$(sec_audit_dnf_main_last_value gpgcheck)
    _rule38_repo=$(sec_audit__yum_repo_list_explicit_gpgcheck0 | head -n1)
    if sec_audit_dnf_val_is_false "$_rule38_main"; then
    sec_audit_report_fail 39 "merged [main] gpgcheck is disabled (effective value: ${_rule38_main})"
    elif [ -n "$_rule38_repo" ]; then
    sec_audit_report_fail 39 "enabled repository section explicitly sets gpgcheck=0 (${_rule38_repo//|/ -> })"
    else
    sec_audit_report_pass 39 "[main] gpgcheck is not false and no enabled .repo section forces gpgcheck=0"
    fi

    # RULE40:
    _rule39_main=$(sec_audit_dnf_main_last_value repo_gpgcheck)
    _rule39_repo=$(sec_audit__yum_repo_list_explicit_repo_gpgcheck0 | head -n1)
    if sec_audit_dnf_val_is_false "$_rule39_main"; then
    sec_audit_report_fail 40 "merged [main] repo_gpgcheck is disabled (effective value: ${_rule39_main})"
    elif [ -z "$_rule39_main" ]; then
    sec_audit_report_fail 40 "repo_gpgcheck not explicitly enabled in merged [main] (dnf defaults to false when unset)"
    elif ! sec_audit_dnf_val_is_true "$_rule39_main"; then
    sec_audit_report_fail 40 "repo_gpgcheck in [main] is not a true value (expected 1/true/yes/on; got: ${_rule39_main})"
    elif [ -n "$_rule39_repo" ]; then
    sec_audit_report_fail 40 "enabled repository section explicitly sets repo_gpgcheck=0 (${_rule39_repo//|/ -> })"
    else
    sec_audit_report_pass 40 "repo_gpgcheck enabled in [main] and no enabled .repo section forces repo_gpgcheck=0"
    fi

    # RULE41:
    _rule40_dnf_n=$(sec_audit_dnf_repolist_enabled_count)
    if [ ! -d /etc/yum.repos.d ]; then
    sec_audit_report_fail 41 "/etc/yum.repos.d is missing"
    else
    _rule40_nrepo=0
    shopt -s nullglob
    for _rf in /etc/yum.repos.d/*.repo; do
        [ -f "$_rf" ] && _rule40_nrepo=$((_rule40_nrepo + 1))
    done
    shopt -u nullglob
    if [ "${_rule40_nrepo:-0}" -eq 0 ]; then
        sec_audit_report_fail 41 "no .repo files under /etc/yum.repos.d"
    elif ! sec_audit__yum_repo_any_enabled_has_uris; then
        sec_audit_report_fail 41 "no enabled repository section defines a non-empty baseurl, mirrorlist, or metalink"
    elif sec_audit_have_bin dnf && [ "${_rule40_dnf_n:-0}" -eq 0 ]; then
        sec_audit_report_fail 41 ".repo files define URIs but dnf repolist enabled reports 0 repos (metadata, plugin, or config error)"
    else
        if sec_audit_have_bin dnf && [ "${_rule40_dnf_n:-0}" -gt 0 ]; then
            sec_audit_report_pass 41 "${_rule40_nrepo} .repo file(s); dnf reports ${_rule40_dnf_n} enabled repo(s); enabled sections include package URIs"
        else
            sec_audit_report_pass 41 "${_rule40_nrepo} .repo file(s); enabled sections include baseurl/mirrorlist/metalink (dnf not used for count)"
        fi
    fi
    fi

    # RULE42:
    _rule41_iwd=$(sec_audit_dnf_main_last_value install_weak_deps)
    if sec_audit_dnf_val_is_false "$_rule41_iwd"; then
    sec_audit_report_pass 42 "install_weak_deps is false in merged [main] (weak dependencies not installed by default)"
    elif [ -z "$_rule41_iwd" ]; then
    sec_audit_report_fail 42 "install_weak_deps not set to 0/false/no/off in [main] (dnf default enables weak dependencies)"
    else
    sec_audit_report_fail 42 "install_weak_deps is not false in merged [main] (effective: ${_rule41_iwd})"
    fi

    # RULE43:
    if sec_audit_have_bin dnf; then
    if dnf check-update --security 2>/dev/null | grep -qiE '^(Last metadata|Security:.*nothing to do|No security updates)'; then
        sec_audit_report_pass 43 "no pending security updates reported by dnf check-update --security"
    elif dnf check-update --security 2>/dev/null | tail -n +2 | grep -qE '^[[:alnum:]]'; then
        sec_audit_report_fail 43 "security updates are available (dnf check-update --security lists packages)"
    else
        sec_audit_report_pass 43 "dnf security update check completed with no pending packages"
    fi
    elif sec_audit_have_bin yum; then
    if yum check-update --security 2>/dev/null | grep -q 'No packages needed for security'; then
        sec_audit_report_pass 43 "no security updates pending"
    else
        sec_audit_report_fail 43 "security updates may be available (yum check-update --security)"
    fi
    else
    sec_audit_report_fail 43 "no supported package manager (dnf/yum) for update verification"
    fi

}

sec_audit_run_selinux() {
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
    if grep -Psi '^\h*SELINUXTYPE\h*=\h*(targeted|mls)\b' /etc/selinux/config 2>/dev/null; then
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
    if rpm -q mcstrans &>/dev/null; then
    sec_audit_report_fail 50 "mcstrans is installed"
    else
    sec_audit_report_pass 50 "mcstrans is not installed"
    fi

    # RULE51:
    if rpm -q setroubleshoot &>/dev/null; then
    sec_audit_report_fail 51 "SETroubleshoot package is installed"
    else
    sec_audit_report_pass 51 "SETroubleshoot is not installed"
    fi

}

sec_audit_run_bootloader() {
    # RULE52:
    if sec_audit_grub_cfg_grep '^[[:space:]]*set superusers' && sec_audit_grub_cfg_grep 'password_pbkdf2'; then
    sec_audit_report_pass 52 "bootloader password is set (grub.cfg under /boot/grub2 or EFI)"
    else
    sec_audit_report_fail 52 "GRUB bootloader superuser/password_pbkdf2 is not configured as required in grub.cfg"
    fi

    # RULE53:
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
    if [ "${_fail50:-0}" -eq 0 ]; then
    sec_audit_report_pass 53 "access to bootloader config is configured"
    else
    sec_audit_report_fail 53 "/boot/grub2/grub.cfg (or EFI grub.cfg) owner/mode is not root:root with mode 600"
    fi

}

sec_audit_run_process_hardening() {
    # RULE54:
    if sec_audit_limits_core_zero_and_systemd_ok; then
    sec_audit_report_pass 54 "limits * hard core 0 present and systemd DefaultLimitCORE does not allow unlimited core dumps"
    elif grep -Psi '^\*\s+hard\s+core\s+0\b' /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null; then
    sec_audit_report_fail 54 "limits.conf sets hard core 0 but systemd DefaultLimitCORE contradicts (check system.conf / user.conf drop-ins)"
    else
    sec_audit_report_fail 54 "core file size limits are not configured (limits * hard core 0 not found)"
    fi

    # RULE55:
    sec_audit_assert_sysctl_equals 55 fs.protected_hardlinks 1

    # RULE56:
    sec_audit_assert_sysctl_equals 56 fs.protected_symlinks 1

    # RULE57:
    sec_audit_assert_sysctl_equals 57 fs.suid_dumpable 0

    # RULE58:
    sec_audit_assert_sysctl_equals 58 kernel.dmesg_restrict 1

    # RULE59:
    sec_audit_assert_sysctl_equals 59 kernel.kptr_restrict 2

    # RULE60:
    sec_audit_assert_sysctl_equals 60 kernel.yama.ptrace_scope 1

    # RULE61:
    sec_audit_assert_sysctl_equals 61 kernel.randomize_va_space 2

    # RULE62:
    _rule59_cat=$(systemd-analyze cat-config systemd/coredump.conf 2>/dev/null)
    _rule59_corep=$(sec_audit_sysctl_key_runtime kernel.core_pattern)
    if builtin printf '%s\n' "$_rule59_cat" | grep -Pq '^\h*ProcessSizeMax=\h*0\b'; then
    if [[ "$_rule59_corep" == *systemd-coredump* ]] || [[ "$_rule59_corep" == *coredump* ]]; then
        sec_audit_report_pass 62 "merged coredump.conf sets ProcessSizeMax=0; kernel.core_pattern uses systemd-coredump"
    else
        sec_audit_report_pass 62 "merged coredump.conf sets ProcessSizeMax=0 (kernel.core_pattern='${_rule59_corep:-?}' may omit systemd-coredump text)"
    fi
    else
    sec_audit_report_fail 62 "merged systemd/coredump.conf does not set ProcessSizeMax=0"
    fi

    # RULE63:
    _rule60_cat=$(systemd-analyze cat-config systemd/coredump.conf 2>/dev/null)
    if builtin printf '%s\n' "$_rule60_cat" | grep -Pq '^\h*Storage=\h*none\b'; then
    sec_audit_report_pass 63 "merged systemd/coredump.conf sets Storage=none"
    else
    sec_audit_report_fail 63 "merged systemd/coredump.conf does not set Storage=none"
    fi

}

sec_audit_run_crypto_policy() {
    # RULE64:
    if grep -Pi '^\h*LEGACY\b' /etc/crypto-policies/config 2>/dev/null; then
    sec_audit_report_fail 64 "System-wide crypto policy is LEGACY in /etc/crypto-policies/config"
    else
    sec_audit_report_pass 64 "system wide crypto policy is not set to legacy"
    fi

    # RULE65:
    FAIL65=0
    if awk -F= '($1~/(hash|sign)/ && $2~/SHA1/ && $2!~/^\s*\- \s*([^#\n\r]+)?SHA1/){found=1; exit} END{exit !found}' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null; then
    FAIL65=1
    fi
    if ! grep -qPsi '^\h*sha1_in_certs\h*=\h*0\b' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null; then
    FAIL65=1
    fi
    if [ "${FAIL65:-0}" -eq 0 ]; then
    sec_audit_report_pass 65 "system wide crypto policy disables sha1 hash and signature support"
    else
    sec_audit_report_fail 65 "SHA1 hash/signature support or sha1_in_certs is not disabled in CURRENT.pol"
    fi

    # RULE66:
    if grep -Pi '(^\h*mac\h*=\h*([^#\n\r]+)?-128|hmac-sha1)' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null; then
    sec_audit_report_fail 66 "Weak MAC algorithms still present in /etc/crypto-policies/state/CURRENT.pol"
    else
    sec_audit_report_pass 66 "system wide crypto policy macs are configured"
    fi

    # RULE67:
    if grep -Piq '^\h*cipher@(lib|open)ssh(-server|-client)?\h*=\h*([^#\n\r]+)?-CBC\b' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null; then
    sec_audit_report_pass 67 "system wide crypto policy disables cbc for ssh"
    elif grep -Piq '^\h*cipher\h*=\h*([^#\n\r]+)?-CBC\b' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null; then
    sec_audit_report_pass 67 "system wide crypto policy disables cbc for ssh"
    else
    sec_audit_report_fail 67 "CBC ciphers for SSH are still allowed by crypto policy (CURRENT.pol)"
    fi

}

sec_audit_run_banners() {
    # RULE68:
    if grep -Psi "(\\\v|\\\r|\\\m|\\\s|\b$(grep ^ID= /etc/os-release 2>/dev/null | cut -d= -f2 | sed -e 's/"//g')\b)" /etc/motd 2>/dev/null; then
    sec_audit_report_fail 68 "/etc/motd is missing or does not contain required banner content"
    else
    sec_audit_report_pass 68 "/etc/motd is configured"
    fi

    # RULE69:
    if grep -Psi "(\\\v|\\\r|\\\m|\\\s|\b$(grep ^ID= /etc/os-release 2>/dev/null | cut -d= -f2 | sed -e 's/"//g')\b)" /etc/issue 2>/dev/null; then
    sec_audit_report_fail 69 "/etc/issue is missing or does not contain required local login banner"
    else
    sec_audit_report_pass 69 "/etc/issue is configured"
    fi

    # RULE70:
    if [ -f /etc/issue.net ]; then
    if grep -Psi "(\\\v|\\\r|\\\m|\\\s|\b$(grep ^ID= /etc/os-release 2>/dev/null | cut -d= -f2 | sed -e 's/"//g')\b)" /etc/issue.net 2>/dev/null; then
        sec_audit_report_fail 70 "/etc/issue.net is missing or does not contain required remote login banner"
    else
        sec_audit_report_pass 70 "/etc/issue.net is configured"
    fi
    else
    sec_audit_report_pass 70 "/etc/issue.net is configured"
    fi

    # RULE71:
    if [ -e /etc/motd ]; then
    if stat -Lc '%a' /etc/motd 2>/dev/null | grep -qE '^[0-6]44$'; then
        if stat -Lc '%U:%G' /etc/motd 2>/dev/null | grep -q '^root:root$'; then
            sec_audit_report_pass 71 "access to /etc/motd is configured"
        else
            sec_audit_report_fail 71 "File /etc/motd permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 71 "File /etc/motd permissions or ownership not correct"
    fi
    else
    sec_audit_report_pass 71 "access to /etc/motd is configured (file not found)"
    fi

    # RULE72:
    if stat -Lc '%a' /etc/issue 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' /etc/issue 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 72 "access to /etc/issue is configured"
    else
        sec_audit_report_fail 72 "File /etc/issue permissions or ownership not correct"
    fi
    else
    sec_audit_report_fail 72 "File /etc/issue permissions or ownership not correct"
    fi

    # RULE73:
    if [ -e /etc/issue.net ]; then
    if stat -Lc '%a' /etc/issue.net 2>/dev/null | grep -qE '^[0-6]44$'; then
        if stat -Lc '%U:%G' /etc/issue.net 2>/dev/null | grep -q '^root:root$'; then
            sec_audit_report_pass 73 "access to /etc/issue.net is configured"
        else
            sec_audit_report_fail 73 "File /etc/issue.net permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 73 "File /etc/issue.net permissions or ownership not correct"
    fi
    else
    sec_audit_report_pass 73 "access to /etc/issue.net is configured (file not found)"
    fi

}

sec_audit_run_gdm() {
    # RULE74:
    GDM_CONFIG="/etc/gdm/custom.conf"
    if [ -f "$GDM_CONFIG" ]; then
    if grep -Pzo "\[org/gnome/login-screen\][^\[]*banner-message-enable=true" "$GDM_CONFIG" 2>/dev/null | grep -q .; then
        sec_audit_report_pass 74 "GDM login banner is configured"
    else
        sec_audit_report_fail 74 "GDM login banner is not configured in $GDM_CONFIG"
    fi
    else
    sec_audit_report_fail 74 "GDM configuration file not found ($GDM_CONFIG)"
    fi

    # RULE75:
    if rpm -q gdm &>/dev/null && grep -q "DisableUserList=true" /etc/gdm/custom.conf 2>/dev/null; then
    sec_audit_report_pass 75 "GDM disable-user-list is configured"
    elif ! rpm -q gdm &>/dev/null; then
    sec_audit_report_pass 75 "GDM is not installed"
    else
    sec_audit_report_fail 75 "GDM disable-user-list is not configured"
    fi

    # RULE76:
    if grep -q "idle-delay=uint32" /etc/dconf/db/gdm.d/* 2>/dev/null || \
       grep -q "lock-delay=uint32" /etc/dconf/db/gdm.d/* 2>/dev/null; then
    sec_audit_report_pass 76 "GDM screen lock is configured"
    else
    sec_audit_report_fail 76 "GDM screen lock is not configured"
    fi

    # RULE77:
    if grep -q "automount=false" /etc/dconf/db/gdm.d/* 2>/dev/null || \
       grep -q "automount-open=false" /etc/dconf/db/gdm.d/* 2>/dev/null; then
    sec_audit_report_pass 77 "GDM automount is configured"
    else
    sec_audit_report_fail 77 "GDM automount is not configured"
    fi

    # RULE78:
    if grep -q "autorun-never=true" /etc/dconf/db/gdm.d/* 2>/dev/null; then
    sec_audit_report_pass 78 "GDM autorun-never is configured"
    else
    sec_audit_report_fail 78 "GDM autorun-never is not configured"
    fi

    # RULE79:
    if grep -Psi '^\h*WaylandEnable=false' /etc/gdm/custom.conf 2>/dev/null; then
    sec_audit_report_pass 79 "Xwayland is configured"
    else
    sec_audit_report_fail 79 "WaylandEnable=false (or equivalent) is not set in GDM custom.conf — Xwayland may remain enabled"
    fi

}

sec_audit_run_unused_services() {
    # RULE80:
    sec_audit_assert_service_unused 80 autofs "autofs services are not in use" "autofs services are installed and enabled or actively running" "autofs.service"

    # RULE81:
    sec_audit_assert_service_unused 81 avahi "avahi daemon services are not in use" "avahi daemon services are installed and enabled or actively running" "avahi-daemon.socket" "avahi-daemon.service"

    # RULE82:
    sec_audit_assert_service_unused 82 cockpit-ws "cockpit web services are not in use" "cockpit web services are installed and enabled or actively running" "cockpit.socket" "cockpit.service"

    # RULE83:
    sec_audit_assert_service_unused 83 dhcp-server "dhcp server services are not in use" "dhcp server services are installed and enabled or actively running" "dhcpd.service" "dhcpd6.service"

    # RULE84:
    sec_audit_assert_service_unused 84 bind "dns server services are not in use" "dns server services are installed and enabled or actively running" "named.service"

    # RULE85:
    sec_audit_assert_service_unused 85 dnsmasq "dnsmasq services are not in use" "dnsmasq services are installed and enabled or actively running" "dnsmasq.service"

    # RULE86:
    sec_audit_assert_service_unused 86 vsftpd "ftp server services are not in use" "ftp server services are installed and enabled or actively running" "vsftpd.service"

    # RULE87:
    if sec_audit_pkg_any_installed dovecot cyrus-imapd; then
    if sec_audit_systemd_unit_enabled_or_active dovecot.socket dovecot.service cyrus-imapd.service; then
        sec_audit_report_fail 87 "message access server services are installed and enabled or actively running"
    else
        sec_audit_report_pass 87 "message access server services are not in use (package present but units masked/disabled/inactive)"
    fi
    else
    sec_audit_report_pass 87 "message access server services are not in use"
    fi

    # RULE88:
    sec_audit_assert_service_unused 88 nfs-utils "network file system services are not in use" "network file system services are installed and enabled or actively running" "nfs-server.service"

    # RULE89:
    sec_audit_assert_service_unused 89 cups "print server services are not in use" "print server services are installed and enabled or actively running" "cups.socket" "cups.service"

    # RULE90:
    sec_audit_assert_service_unused 90 rpcbind "rpcbind services are not in use" "rpcbind services are installed and enabled or actively running" "rpcbind.socket" "rpcbind.service"

    # RULE91:
    sec_audit_assert_service_unused 91 rsync-daemon "rsync services are not in use" "rsync services are installed and enabled or actively running" "rsyncd.socket" "rsyncd.service"

    # RULE92:
    sec_audit_assert_service_unused 92 samba "samba file server services are not in use" "samba file server services are installed and enabled or actively running" "smb.service"

    # RULE93:
    sec_audit_assert_service_unused 93 net-snmp "snmp services are not in use" "snmp services are installed and enabled or actively running" "snmpd.service"

    # RULE94:
    sec_audit_assert_service_unused 94 telnet-server "telnet server services are not in use" "telnet server services are installed and enabled or actively running" "telnet.socket"

    # RULE95:
    sec_audit_assert_service_unused 95 tftp-server "tftp server services are not in use" "tftp server services are installed and enabled or actively running" "tftp.socket" "tftp.service"

    # RULE96:
    sec_audit_assert_service_unused 96 squid "web proxy server services are not in use" "web proxy server services are installed and enabled or actively running" "squid.service"

    # RULE97:
    if sec_audit_pkg_any_installed httpd nginx; then
    if sec_audit_systemd_unit_enabled_or_active httpd.service nginx.service; then
        sec_audit_report_fail 97 "web server services are installed and enabled or actively running"
    else
        sec_audit_report_pass 97 "web server services are not in use (package present but units masked/disabled/inactive)"
    fi
    else
    sec_audit_report_pass 97 "web server services are not in use"
    fi

    # RULE98:
    if rpm -q gdm &>/dev/null || systemctl is-enabled gdm 2>/dev/null | grep -q 'enabled' || systemctl is-active gdm 2>/dev/null | grep -q '^active'; then
    sec_audit_report_fail 98 "GNOME Display Manager (gdm) package is still installed"
    else
    sec_audit_report_pass 98 "GNOME Display Manager is removed"
    fi

    # RULE99:
    if rpm -q xorg-x11-server-Xwayland &>/dev/null; then
    sec_audit_report_fail 99 "X window server services are installed and enabled or actively running"
    else
    sec_audit_report_pass 99 "X window server services are not in use"
    fi

    # RULE100:
    if sec_audit_have_bin ss && ss -lntu 2>/dev/null | grep -E ':25\b' | grep -qvE '127\.0\.0\.1:25|::1:25|\[::1\]:25'; then
    sec_audit_report_fail 100 "MTA is listening on non-loopback interfaces"
    elif sec_audit_have_bin ss && ss -lntu 2>/dev/null | grep -qE ':25\b'; then
    sec_audit_report_pass 100 "MTA is configured for local-only mode"
    else
    sec_audit_report_pass 100 "MTA is configured for local-only mode (no MTA listening on port 25)"
    fi

    # RULE101:
    if sec_audit_have_bin ss; then
    LISTENERS=$(ss -H -tulpn 2>/dev/null | awk '
        $1 ~ /^tcp/ || $1 ~ /^udp/ {
            split($4, a, ":")
            host = a[1]
            gsub(/^[[]|[]]$/, "", host)
            if (host != "127.0.0.1" && host != "::1" && host != "*" && host != "0.0.0.0" && host != "[::]") print
        }
    ' | sort -u | head -40)
    if [ -z "$LISTENERS" ]; then
        sec_audit_report_pass 101 "No non-loopback listening services detected"
    else
        sec_audit_report_skip 101 "Non-loopback listeners require manual approval: ${LISTENERS}"
    fi
    else
    sec_audit_report_skip 101 "ss unavailable; manually verify only approved services listen on network interfaces"
    fi

}

sec_audit_run_client_tools() {
    # RULE102:
    if rpm -q ftp &>/dev/null; then
    sec_audit_report_fail 102 "ftp client package is installed"
    else
    sec_audit_report_pass 102 "ftp client is not installed"
    fi

    # RULE103:
    if rpm -q openldap-clients &>/dev/null; then
    sec_audit_report_fail 103 "ldap client package is installed"
    else
    sec_audit_report_pass 103 "ldap client is not installed"
    fi

    # RULE104:
    if rpm -q telnet &>/dev/null; then
    sec_audit_report_fail 104 "telnet client package is installed"
    else
    sec_audit_report_pass 104 "telnet client is not installed"
    fi

    # RULE105:
    if rpm -q tftp &>/dev/null; then
    sec_audit_report_fail 105 "tftp client package is installed"
    else
    sec_audit_report_pass 105 "tftp client is not installed"
    fi

}

sec_audit_run_chrony() {
    # RULE106:
    if rpm -q chrony &>/dev/null; then
    if systemctl is-active chronyd.service &>/dev/null; then
        sec_audit_report_pass 106 "chrony is installed and chronyd.service is active"
    else
        sec_audit_report_fail 106 "chrony is installed but chronyd.service is not active"
    fi
    else
    sec_audit_report_fail 106 "time synchronization is not in use (chrony not installed)"
    fi

    # RULE107:
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
    sec_audit_report_pass 107 "chrony has ${_ch101_src:-0} server/pool line(s) in conf or chrony.d${_ch101_track}"
    else
    sec_audit_report_fail 107 "chrony is not configured with time sources (no server/pool in chrony.conf or chrony.d)"
    fi

    # RULE108:
    if grep -Psi -- '^\h*OPTIONS=\"?\h*([^#\n\r]+\h+)?-u\h+root\b' /etc/sysconfig/chronyd 2>/dev/null; then
    sec_audit_report_fail 108 "chronyd is configured to run as root (OPTIONS in /etc/sysconfig/chronyd)"
    else
    sec_audit_report_pass 108 "chrony is not run as the root user"
    fi

}

sec_audit_run_cron_at() {
    # RULE109:
    if systemctl is-enabled crond.service 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active crond.service 2>/dev/null | grep -q 'active'; then
        sec_audit_report_pass 109 "cron daemon is enabled and active"
    else
        sec_audit_report_fail 109 "crond service is not enabled or not active"
    fi
    else
    sec_audit_report_fail 109 "crond service is not enabled or not active"
    fi

    # RULE110:
    if stat -Lc '%a' /etc/crontab 2>/dev/null | grep -q '^[0-6]00$'; then
    if stat -Lc '%U:%G' /etc/crontab 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 110 "access to /etc/crontab is configured"
    else
        sec_audit_report_fail 110 "File /etc/crontab permissions or ownership not correct"
    fi
    else
    sec_audit_report_fail 110 "File /etc/crontab permissions or ownership not correct"
    fi

    # RULE111:
    if stat -Lc '%a' /etc/cron.hourly 2>/dev/null | grep -q '^700$'; then
    if stat -Lc '%U:%G' /etc/cron.hourly 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 111 "access to /etc/cron.hourly is configured"
    else
        sec_audit_report_fail 111 "File /etc/cron.hourly permissions or ownership not correct"
    fi
    else
    sec_audit_report_fail 111 "File /etc/cron.hourly permissions or ownership not correct"
    fi

    # RULE112:
    if stat -Lc '%a' /etc/cron.daily 2>/dev/null | grep -q '^700$'; then
    if stat -Lc '%U:%G' /etc/cron.daily 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 112 "access to /etc/cron.daily is configured"
    else
        sec_audit_report_fail 112 "File /etc/cron.daily permissions or ownership not correct"
    fi
    else
    sec_audit_report_fail 112 "File /etc/cron.daily permissions or ownership not correct"
    fi

    # RULE113:
    if stat -Lc '%a' /etc/cron.weekly 2>/dev/null | grep -q '^700$'; then
    if stat -Lc '%U:%G' /etc/cron.weekly 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 113 "access to /etc/cron.weekly is configured"
    else
        sec_audit_report_fail 113 "File /etc/cron.weekly permissions or ownership not correct"
    fi
    else
    sec_audit_report_fail 113 "File /etc/cron.weekly permissions or ownership not correct"
    fi

    # RULE114:
    if stat -Lc '%a' /etc/cron.monthly 2>/dev/null | grep -q '^700$'; then
    if stat -Lc '%U:%G' /etc/cron.monthly 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 114 "access to /etc/cron.monthly is configured"
    else
        sec_audit_report_fail 114 "File /etc/cron.monthly permissions or ownership not correct"
    fi
    else
    sec_audit_report_fail 114 "File /etc/cron.monthly permissions or ownership not correct"
    fi

    # RULE115:
    if stat -Lc '%a' /etc/cron.yearly 2>/dev/null | grep -q '^700$'; then
    if stat -Lc '%U:%G' /etc/cron.yearly 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 115 "access to /etc/cron.yearly is configured"
    else
        sec_audit_report_fail 115 "File /etc/cron.yearly permissions or ownership not correct"
    fi
    else
    sec_audit_report_fail 115 "File /etc/cron.yearly permissions or ownership not correct"
    fi

    # RULE116:
    if stat -Lc '%a' /etc/cron.d 2>/dev/null | grep -q '^700$'; then
    if stat -Lc '%U:%G' /etc/cron.d 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 116 "access to /etc/cron.d is configured"
    else
        sec_audit_report_fail 116 "File /etc/cron.d permissions or ownership not correct"
    fi
    else
    sec_audit_report_fail 116 "File /etc/cron.d permissions or ownership not correct"
    fi

    # RULE117:
    if [ -e /etc/cron.allow ]; then
    if stat -Lc '%a' /etc/cron.allow 2>/dev/null | grep -qE '^640$'; then
        if stat -Lc '%U' /etc/cron.allow 2>/dev/null | grep -q 'root'; then
            if stat -Lc '%G' /etc/cron.allow 2>/dev/null | grep -qE 'root|crontab'; then
                sec_audit_report_pass 117 "access to crontab is configured"
            else
                sec_audit_report_fail 117 "File crontab permissions or ownership not correct"
            fi
        else
            sec_audit_report_fail 117 "File crontab permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 117 "File crontab permissions or ownership not correct"
    fi
    else
    sec_audit_report_fail 117 "File crontab permissions or ownership not correct"
    fi

    # RULE118:
    if [ -e /etc/at.allow ]; then
    if stat -Lc '%a' /etc/at.allow 2>/dev/null | grep -qE '^640$'; then
        if stat -Lc '%U' /etc/at.allow 2>/dev/null | grep -q 'root'; then
            if stat -Lc '%G' /etc/at.allow 2>/dev/null | grep -qE 'daemon|root'; then
                sec_audit_report_pass 118 "access to at is configured"
            else
                sec_audit_report_fail 118 "File at permissions or ownership not correct"
            fi
        else
            sec_audit_report_fail 118 "File at permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 118 "File at permissions or ownership not correct"
    fi
    else
    sec_audit_report_fail 118 "File at permissions or ownership not correct"
    fi

}

sec_audit_run_network_stack() {
    # RULE119:
    if [ -f /proc/sys/net/ipv6/conf/all/disable_ipv6 ]; then
    sec_audit_report_pass 119 "IPv6 status is identified"
    else
    sec_audit_report_fail 119 "IPv6 status is not identified"
    fi

    # RULE120:
    if compgen -G "/sys/class/net/*/wireless" >/dev/null; then
    sec_audit_report_fail 120 "Wireless interfaces are present under /sys/class/net"
    else
    sec_audit_report_pass 120 "wireless interfaces are not available"
    fi

    # RULE121:
    sec_audit_assert_service_unused 121 bluez "bluetooth services are not in use" "bluetooth services are installed and enabled or actively running" "bluetooth.service"

    # RULE122:
    sec_audit_assert_kmod_disabled 122 "atm kernel module" atm atm.ko* "atm"

    # RULE123:
    sec_audit_assert_kmod_disabled 123 "can kernel module" can can.ko* "can"

    # RULE124:
    sec_audit_assert_kmod_disabled 124 "dccp kernel module" dccp dccp.ko* "dccp"

    # RULE125:
    sec_audit_assert_kmod_disabled 125 "tipc kernel module" tipc tipc.ko* "tipc"

    # RULE126:
    sec_audit_assert_kmod_disabled 126 "rds kernel module" rds rds.ko* "rds"

    # RULE127:
    sec_audit_assert_kmod_disabled 127 "sctp kernel module" sctp sctp.ko* "sctp"

    # RULE128:
    sec_audit_assert_sysctl_equals 128 net.ipv4.ip_forward 0

    # RULE129:
    sec_audit_assert_sysctl_equals 129 net.ipv4.conf.all.forwarding 0

    # RULE130:
    sec_audit_assert_sysctl_equals 130 net.ipv4.conf.default.forwarding 0

    # RULE131:
    sec_audit_assert_sysctl_equals 131 net.ipv4.conf.all.send_redirects 0

    # RULE132:
    sec_audit_assert_sysctl_equals 132 net.ipv4.conf.default.send_redirects 0

    # RULE133:
    sec_audit_assert_sysctl_equals 133 net.ipv4.icmp_ignore_bogus_error_responses 1

    # RULE134:
    sec_audit_assert_sysctl_equals 134 net.ipv4.icmp_echo_ignore_broadcasts 1

    # RULE135:
    sec_audit_assert_sysctl_equals 135 net.ipv4.conf.all.accept_redirects 0

    # RULE136:
    sec_audit_assert_sysctl_equals 136 net.ipv4.conf.default.accept_redirects 0

    # RULE137:
    sec_audit_assert_sysctl_equals 137 net.ipv4.conf.all.secure_redirects 0

    # RULE138:
    sec_audit_assert_sysctl_equals 138 net.ipv4.conf.default.secure_redirects 0

    # RULE139:
    sec_audit_assert_sysctl_equals 139 net.ipv4.conf.all.rp_filter 1

    # RULE140:
    sec_audit_assert_sysctl_equals 140 net.ipv4.conf.default.rp_filter 1

    # RULE141:
    sec_audit_assert_sysctl_equals 141 net.ipv4.conf.all.accept_source_route 0

    # RULE142:
    sec_audit_assert_sysctl_equals 142 net.ipv4.conf.default.accept_source_route 0

    # RULE143:
    sec_audit_assert_sysctl_equals 143 net.ipv4.conf.all.log_martians 1

    # RULE144:
    sec_audit_assert_sysctl_equals 144 net.ipv4.conf.default.log_martians 1

    # RULE145:
    sec_audit_assert_sysctl_equals 145 net.ipv4.tcp_syncookies 1

    # RULE146:
    sec_audit_assert_sysctl_equals 146 net.ipv6.conf.all.forwarding 0

    # RULE147:
    sec_audit_assert_sysctl_equals 147 net.ipv6.conf.default.forwarding 0

    # RULE148:
    sec_audit_assert_sysctl_equals 148 net.ipv6.conf.all.accept_redirects 0

    # RULE149:
    sec_audit_assert_sysctl_equals 149 net.ipv6.conf.default.accept_redirects 0

    # RULE150:
    sec_audit_assert_sysctl_equals 150 net.ipv6.conf.all.accept_source_route 0

    # RULE151:
    sec_audit_assert_sysctl_equals 151 net.ipv6.conf.default.accept_source_route 0

    # RULE152:
    sec_audit_assert_sysctl_equals 152 net.ipv6.conf.all.accept_ra 0

    # RULE153:
    sec_audit_assert_sysctl_equals 153 net.ipv6.conf.default.accept_ra 0

}

sec_audit_run_firewalld() {
    # RULE154:
    if rpm -q firewalld &>/dev/null; then
    sec_audit_report_pass 154 "firewalld is installed"
    else
    sec_audit_report_fail 154 "firewalld package is not installed"
    fi

    # RULE155:
    if grep -Psi 'FirewallBackend\h*=\h*nftables\b' /etc/firewalld/firewalld.conf 2>/dev/null; then
    _fw140_be=""
    if sec_audit_have_bin firewall-cmd && firewall-cmd --state 2>/dev/null | grep -qi running; then
        _fw140_be=$(firewall-cmd --get-backend 2>/dev/null)
        if [[ "$_fw140_be" == "nftables" ]]; then
            sec_audit_report_pass 155 "firewalld.conf uses nftables and runtime backend is nftables"
        else
            sec_audit_report_pass 155 "firewalld.conf uses nftables (runtime backend reports '${_fw140_be:-?}')"
        fi
    else
        sec_audit_report_pass 155 "firewalld.conf uses nftables (firewalld not running; runtime backend not verified)"
    fi
    else
    sec_audit_report_fail 155 "firewalld backend is not configured (FirewallBackend=nftables missing in firewalld.conf)"
    fi

    # RULE156:
    if systemctl is-enabled firewalld.service 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active firewalld.service 2>/dev/null | grep -q 'active'; then
        _fw141_nft=""
        if sec_audit_have_bin nft && nft list ruleset 2>/dev/null | grep -q .; then
            _fw141_nft="; nftables ruleset is non-empty"
        fi
        sec_audit_report_pass 156 "firewalld.service is enabled and active${_fw141_nft}"
    else
        sec_audit_report_fail 156 "firewalld.service is not enabled or not active"
    fi
    else
    sec_audit_report_fail 156 "firewalld.service is not enabled or not active"
    fi

    # RULE157:
    if systemctl is-active firewalld &>/dev/null; then
    ACTIVE_ZONE=$(firewall-cmd --get-default-zone 2>/dev/null)
    ZONE_TARGET=$(firewall-cmd --zone="$ACTIVE_ZONE" --get-target 2>/dev/null)
    _fw142_if=$(firewall-cmd --zone="$ACTIVE_ZONE" --list-interfaces 2>/dev/null | wc -w)
    if [ "$ZONE_TARGET" = "DROP" ] || [ "$ZONE_TARGET" = "REJECT" ]; then
        sec_audit_report_pass 157 "firewalld default zone '$ACTIVE_ZONE' target is $ZONE_TARGET (${_fw142_if:-0} interface(s) assigned)"
    else
        sec_audit_report_fail 157 "firewalld active zone target is not secure (current: $ZONE_TARGET)"
    fi
    else
    sec_audit_report_fail 157 "firewalld is not active"
    fi

    # RULE158:
    if systemctl is-active firewalld &>/dev/null; then
    if firewall-cmd --list-rich-rules 2>/dev/null | grep -Eiq 'lo|loopback|127\.0\.0\.1|interface\s*=\s*\"lo\"|interface\s*=\s*lo\b'; then
        sec_audit_report_pass 158 "firewalld rich rules mention loopback / lo / localhost"
    else
        sec_audit_report_fail 158 "firewalld loopback traffic is not configured"
    fi
    else
    sec_audit_report_fail 158 "firewalld is not active"
    fi

    # RULE159:
    if systemctl is-active firewalld &>/dev/null; then
    if firewall-cmd --zone=trusted --list-sources 2>/dev/null | grep -qE '127\.0\.0\.1|::1'; then
        sec_audit_report_pass 159 "firewalld loopback source address traffic is configured"
    elif firewall-cmd --list-rich-rules 2>/dev/null | grep -q 'source address="127\.0\.0\.0/8"'; then
        sec_audit_report_pass 159 "firewalld loopback source address traffic is configured via rich-rules"
    else
        sec_audit_report_fail 159 "firewalld loopback zone source address not configured for 127.0.0.1/::1"
    fi
    else
    sec_audit_report_fail 159 "firewalld is not active"
    fi

    # RULE160:
    if systemctl is-active firewalld &>/dev/null; then
    SERVICES=$(firewall-cmd --list-services 2>/dev/null | wc -w)
    PORTS=$(firewall-cmd --list-ports 2>/dev/null | wc -w)
    SERVICES_P=$(firewall-cmd --permanent --list-services 2>/dev/null | wc -w)
    PORTS_P=$(firewall-cmd --permanent --list-ports 2>/dev/null | wc -w)
    if [ "$SERVICES" -gt 0 ] || [ "$PORTS" -gt 0 ]; then
        sec_audit_report_pass 160 "firewalld exposes $SERVICES service(s) and $PORTS port(s) at runtime (permanent: $SERVICES_P / $PORTS_P)"
    elif [ "$SERVICES_P" -gt 0 ] || [ "$PORTS_P" -gt 0 ]; then
        sec_audit_report_fail 160 "permanent firewalld rules exist ($SERVICES_P services, $PORTS_P ports) but runtime lists none — run firewall-cmd --reload"
    else
        sec_audit_report_fail 160 "firewalld services and ports are not configured"
    fi
    else
    sec_audit_report_fail 160 "firewalld is not active"
    fi

}

sec_audit_run_sshd() {
    # RULE161:
    if stat -Lc '%a' /etc/ssh/sshd_config 2>/dev/null | grep -q '^600$'; then
    if stat -Lc '%U:%G' /etc/ssh/sshd_config 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 161 "access to /etc/ssh/sshd_config is configured"
    else
        sec_audit_report_fail 161 "File /etc/ssh/sshd_config permissions or ownership not correct"
    fi
    else
    sec_audit_report_fail 161 "File /etc/ssh/sshd_config permissions or ownership not correct"
    fi

    if ! sec_audit_sshd_effective_usable; then
    for _sshn in 162 163 164 165 166 167 168 169 170 171 172 173 174 175 176 177 178 179 180 181 182; do
        sec_audit_report_fail "$_sshn" "unable_to_evaluate: sshd -T produced no effective configuration"
    done
    else

    # RULE162:
    PRIV_KEYS=$(sec_audit_sshd_effective_dump | awk '$1=="hostkey" {print $2}')
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
    sec_audit_report_pass 162 "access to SSH private host key files is configured"
    else
    sec_audit_report_fail 162 "File SSH private host key files permissions or ownership not correct"
    fi

    # RULE163:
    PUB_KEYS=$(sec_audit_sshd_effective_dump | awk '$1=="hostkey" {print $2".pub"}')
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
    sec_audit_report_pass 163 "access to SSH public host key files is configured"
    else
    sec_audit_report_fail 163 "File SSH public host key files permissions or ownership not correct"
    fi

    # RULE164:
    if sec_audit_sshd_t_grep -Piq '^\h*(allow|deny)(users|groups)\h+\H+'; then
    sec_audit_report_pass 164 "sshd access is configured"
    else
    sec_audit_report_fail 164 "sshd access controls (AllowUsers/DenyUsers/AllowGroups/DenyGroups) are not set as required"
    fi

    # RULE165:
    if sec_audit_sshd_t_grep -Piq '^banner\h+\/\H+'; then
    sec_audit_report_pass 165 "sshd Banner is configured"
    else
    sec_audit_report_fail 165 "sshd Banner does not meet the required policy (see sshd -T)"
    fi

    # RULE166:
    if sec_audit_sshd_t_grep -Piq '^ciphers\h+\"?([^#\n\r]+,)?((3des|blowfish|cast128|aes(128|192|256))-cbc|arcfour(128|256)?|rijndael-cbc@lysator\.liu\.se)\b'; then
    sec_audit_report_fail 166 "sshd Ciphers allow weak or legacy algorithms (see sshd -T)"
    else
    sec_audit_report_pass 166 "sshd Ciphers are configured"
    fi

    # RULE167:
    if sec_audit_sshd_t_grep -Piq 'clientaliveinterval\s+([1-9]|[1-9][0-9]+)'; then
    if sec_audit_sshd_t_grep -Piq 'clientalivecountmax\s+([1-9]|[1-9][0-9]+)'; then
        sec_audit_report_pass 167 "sshd ClientAliveInterval and ClientAliveCountMax are configured"
    else
        sec_audit_report_fail 167 "sshd ClientAliveInterval and ClientAliveCountMax are not configured as required (see sshd -T)"
    fi
    else
    sec_audit_report_fail 167 "sshd ClientAliveInterval and ClientAliveCountMax are not configured as required (see sshd -T)"
    fi

    # RULE168:
    if sec_audit_sshd_t_grep -iq 'disableforwarding yes'; then
    sec_audit_report_pass 168 "sshd DisableForwarding is enabled"
    else
    sec_audit_report_fail 168 "sshd DisableForwarding is not enabled in effective sshd -T output"
    fi

    # RULE169:
    if sec_audit_sshd_t_grep -iq 'gssapiauthentication no'; then
    sec_audit_report_pass 169 "sshd GSSAPIAuthentication is disabled"
    else
    sec_audit_report_fail 169 "sshd GSSAPIAuthentication is not disabled in effective sshd -T output"
    fi

    # RULE170:
    if sec_audit_sshd_t_grep -iq 'hostbasedauthentication no'; then
    sec_audit_report_pass 170 "sshd HostbasedAuthentication is disabled"
    else
    sec_audit_report_fail 170 "sshd HostbasedAuthentication is not disabled in effective sshd -T output"
    fi

    # RULE171:
    if sec_audit_sshd_t_grep -iq 'ignorerhosts yes'; then
    sec_audit_report_pass 171 "sshd IgnoreRhosts is enabled"
    else
    sec_audit_report_fail 171 "sshd IgnoreRhosts is not enabled in effective sshd -T output"
    fi

    # RULE172:
    if sec_audit_sshd_t_grep -Piq 'kexalgorithms\h+([^#\n\r]+,)?(diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1)\b'; then
    sec_audit_report_fail 172 "sshd KexAlgorithms does not meet the required policy (see sshd -T)"
    else
    sec_audit_report_pass 172 "sshd KexAlgorithms is configured"
    fi

    # RULE173:
    if sec_audit_sshd_t_grep -Piq 'logingracetime\s+([1-9]|[1-5][0-9]|60)\b'; then
    sec_audit_report_pass 173 "sshd LoginGraceTime is configured"
    else
    sec_audit_report_fail 173 "sshd LoginGraceTime does not meet the required policy (see sshd -T)"
    fi

    # RULE174:
    if sec_audit_sshd_t_grep -iq 'loglevel VERBOSE\|loglevel INFO'; then
    sec_audit_report_pass 174 "sshd LogLevel is configured"
    else
    sec_audit_report_fail 174 "sshd LogLevel does not meet the required policy (see sshd -T)"
    fi

    # RULE175:
    if sec_audit_sshd_t_grep -Piq 'macs\h+([^#\n\r]+,)?(hmac-md5|hmac-md5-96|hmac-ripemd160|hmac-sha1-96|umac-64@openssh\.com|hmac-md5-etm@openssh\.com|hmac-md5-96-etm@openssh\.com|hmac-ripemd160-etm@openssh\.com|hmac-sha1-96-etm@openssh\.com|umac-64-etm@openssh\.com|umac-128-etm@openssh\.com)\b'; then
    sec_audit_report_fail 175 "sshd MACs allow weak or legacy algorithms (see sshd -T)"
    else
    sec_audit_report_pass 175 "sshd MACs are configured"
    fi

    # RULE176:
    if sec_audit_sshd_t_grep -Piq 'maxauthtries\s+[1-4]\b'; then
    sec_audit_report_pass 176 "sshd MaxAuthTries is configured"
    else
    sec_audit_report_fail 176 "sshd MaxAuthTries does not meet the required policy (see sshd -T)"
    fi

    # RULE177:
    if sec_audit_sshd_t_awk '$1 ~ /^\s*maxstartups/{split($2, a, ":");{if(a[1] <= 10 && a[2] <= 30 && a[3] <= 60) print "ok"}}' | grep -q "ok"; then
    sec_audit_report_pass 177 "sshd MaxStartups is configured"
    else
    sec_audit_report_fail 177 "sshd MaxStartups does not meet the required policy (see sshd -T)"
    fi

    # RULE178:
    if sec_audit_sshd_t_grep -Piq 'maxsessions\s+([1-9]|10)\b'; then
    sec_audit_report_pass 178 "sshd MaxSessions is configured"
    else
    sec_audit_report_fail 178 "sshd MaxSessions does not meet the required policy (see sshd -T)"
    fi

    # RULE179:
    if sec_audit_sshd_t_grep -iq 'permitemptypasswords no'; then
    sec_audit_report_pass 179 "sshd PermitEmptyPasswords is disabled"
    else
    sec_audit_report_fail 179 "sshd PermitEmptyPasswords is not disabled in effective sshd -T output"
    fi

    # RULE180:
    if sec_audit_sshd_t_grep -iq 'permitrootlogin no'; then
    sec_audit_report_pass 180 "sshd PermitRootLogin is disabled"
    else
    sec_audit_report_fail 180 "sshd PermitRootLogin is not disabled in effective sshd -T output"
    fi

    # RULE181:
    if sec_audit_sshd_t_grep -iq 'permituserenvironment no'; then
    sec_audit_report_pass 181 "sshd PermitUserEnvironment is disabled"
    else
    sec_audit_report_fail 181 "sshd PermitUserEnvironment is not disabled in effective sshd -T output"
    fi

    # RULE182:
    if sec_audit_sshd_t_grep -iq 'usepam yes'; then
    sec_audit_report_pass 182 "sshd UsePAM is enabled"
    else
    sec_audit_report_fail 182 "sshd UsePAM is not enabled in effective sshd -T output"
    fi

    fi

}

sec_audit_run_sudo_su() {
    # RULE183:
    if rpm -q sudo &>/dev/null; then
    sec_audit_report_pass 183 "sudo is installed"
    else
    sec_audit_report_fail 183 "sudo package is not installed"
    fi

    # RULE184:
    if grep -rPi '^\h*Defaults\h+([^#\n\r]+,\h*)?use_pty\b' /etc/sudoers* 2>/dev/null; then
    if ! grep -rPi '^\h*Defaults\h+([^#\n\r]+,\h*)?!use_pty\b' /etc/sudoers* 2>/dev/null; then
        sec_audit_report_pass 184 "sudo commands use pty"
    else
        sec_audit_report_fail 184 "sudo is not configured to require a pseudo-terminal (use_pty)"
    fi
    else
    sec_audit_report_fail 184 "sudo is not configured to require a pseudo-terminal (use_pty)"
    fi

    # RULE185:
    if grep -rPsi "^\h*Defaults\h+([^#]+,\h*)?logfile\h*=\h*(\"|\')?\H+(\"|\')?(,\h*\H+\h*)*\h*(#.*)?$" /etc/sudoers* 2>/dev/null; then
    sec_audit_report_pass 185 "sudo log file exists"
    else
    sec_audit_report_fail 185 "sudo log file is missing or not configured"
    fi

    # RULE186:
    if grep -r "^[^#].*NOPASSWD" /etc/sudoers* 2>/dev/null; then
    sec_audit_report_fail 186 "NOPASSWD or password-less sudo rules violate escalation policy"
    else
    sec_audit_report_pass 186 "users must provide password for escalation"
    fi

    # RULE187:
    if grep -rPiq '^\h*Defaults\h+([^#\n\r]+,\h*)?!authenticate\b' /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
    sec_audit_report_fail 187 "Re-authentication is disabled"
    else
    sec_audit_report_pass 187 "Re-authentication is not disabled"
    fi

    # RULE188:
    TIMEOUT=$(sudo -V 2>/dev/null | grep "Authentication timestamp timeout:" | awk '{print $4}')
    TIMEOUT_INT=${TIMEOUT%%.*}
    if [ -n "$TIMEOUT_INT" ]; then
    if [ "$TIMEOUT_INT" -ge 0 ] && [ "$TIMEOUT_INT" -le 15 ]; then
        sec_audit_report_pass 188 "sudo timestamp_timeout is configured"
    else
        sec_audit_report_fail 188 "sudo timestamp_timeout is not set within the required range"
    fi
    else
    sec_audit_report_pass 188 "sudo timestamp_timeout is configured"
    fi

}

sec_audit_run_pam_auth() {
    # RULE189:
    if grep -Pi '^\h*auth\h+(?:required|requisite)\h+pam_wheel\.so\h+(?:[^#\n\r]+\h+)?((?!\2)(use_uid\b|group=\H+\b))\h+(?:[^#\n\r]+\h+)?((?!\1)(use_uid\b|group=\H+\b))(\h+.*)?$' /etc/pam.d/su 2>/dev/null; then
    GROUP=$(grep -Pi '^\h*auth\h+(?:required|requisite)\h+pam_wheel\.so\h+(?:[^#\n\r]+\h+)?((?!\2)(use_uid\b|group=\H+\b))\h+(?:[^#\n\r]+\h+)?((?!\1)(use_uid\b|group=\H+\b))(\h+.*)?$' /etc/pam.d/su 2>/dev/null | grep -oP 'group=\K\H+')
    if [ -n "$GROUP" ]; then
        if ! grep "^$GROUP:" /etc/group 2>/dev/null | grep -q ":$GROUP:x:"; then
            sec_audit_report_pass 189 "access to the su command is restricted"
        else
            sec_audit_report_fail 189 "su is not restricted to the wheel group in PAM configuration"
        fi
    else
        sec_audit_report_pass 189 "access to the su command is restricted"
    fi
    else
    sec_audit_report_fail 189 "su is not restricted to the wheel group in PAM configuration"
    fi

    # RULE190:
    ACTIVE_PROFILE=$(head -1 /etc/authselect/authselect.conf 2>/dev/null)
    if [ -z "$ACTIVE_PROFILE" ]; then
    sec_audit_report_fail 190 "active authselect profile does not include required pam modules"
    elif sec_audit_have_bin authselect && ! authselect check &>/dev/null; then
    sec_audit_report_fail 190 "authselect reports configuration drift (run authselect check / apply changes)"
    elif grep -P -- '\b(pam_pwquality\.so|pam_pwhistory\.so|pam_faillock\.so|pam_unix\.so)\b' /etc/authselect/"$ACTIVE_PROFILE"/{system,password}-auth 2>/dev/null; then
    sec_audit_report_pass 190 "active authselect profile includes pam modules (authselect check OK)"
    else
    sec_audit_report_fail 190 "active authselect profile does not include required pam modules"
    fi

    # RULE191:
    if sec_audit_pam_password_line_has_module pam_faillock.so; then
    sec_audit_report_pass 191 "pam_faillock.so on password stack in resolved password-auth/system-auth"
    else
    sec_audit_report_fail 191 "pam_faillock module is not enabled on the password stack"
    fi

    # RULE192:
    if sec_audit_pam_password_line_has_module pam_pwquality.so && sec_audit_pam_password_pwquality_before_unix_all_stacks; then
    sec_audit_report_pass 192 "pam_pwquality.so on password stack and ordered before pam_unix.so"
    elif sec_audit_pam_password_line_has_module pam_pwquality.so; then
    sec_audit_report_fail 192 "pam_pwquality.so present but not correctly ordered before pam_unix.so on password stack"
    else
    sec_audit_report_fail 192 "pam_pwquality module is not enabled on the password stack"
    fi

    # RULE193:
    if sec_audit_pam_password_line_has_module pam_pwhistory.so; then
    sec_audit_report_pass 193 "pam_pwhistory.so on password stack in resolved password-auth/system-auth"
    else
    sec_audit_report_fail 193 "pam_pwhistory module is not enabled on the password stack"
    fi

    # RULE194:
    if sec_audit_pam_password_line_has_module pam_unix.so; then
    sec_audit_report_pass 194 "pam_unix.so on password stack in resolved password-auth/system-auth"
    else
    sec_audit_report_fail 194 "pam_unix module is not enabled on the password stack"
    fi

    # RULE195:
    if grep -Psi 'deny\h*=\h*[1-5]\b' /etc/security/faillock.conf 2>/dev/null; then
    sec_audit_report_pass 195 "password failed attempts lockout is configured"
    else
    sec_audit_report_fail 195 "faillock deny threshold is not configured in /etc/security/faillock.conf"
    fi

    # RULE196:
    if grep -Psi 'unlock_time\h*=\h*(0|9[0-9][0-9]|[1-9][0-9]{3,})\b' /etc/security/faillock.conf 2>/dev/null; then
    sec_audit_report_pass 196 "password unlock time is configured"
    else
    sec_audit_report_fail 196 "faillock unlock_time is not set within the required range"
    fi

    # RULE197:
    if grep -Psi '\beven_deny_root\b' /etc/security/faillock.conf 2>/dev/null; then
    sec_audit_report_pass 197 "Root lockout is configured"
    else
    sec_audit_report_fail 197 "Root lockout is not configured"
    fi

    # RULE198:
    if grep -Psi '^\h*difok\h*=\h*[2-9]\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null; then
    sec_audit_report_pass 198 "difok is configured"
    else
    sec_audit_report_fail 198 "difok is not configured"
    fi

    # RULE199:
    if grep -Psi '^\h*minlen\h*=\h*(1[4-9]|[2-9][0-9]|[1-9][0-9]{2,})\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null; then
    sec_audit_report_pass 199 "password length is configured"
    else
    sec_audit_report_fail 199 "pwquality minlen (or equivalent) is not set to at least 14"
    fi

    # RULE200:
    if grep -Psi '^\h*(minclass|[dulo]credit)\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null; then
    sec_audit_report_pass 200 "password complexity is configured"
    else
    sec_audit_report_fail 200 "pwquality complexity (minclass/credits) is not configured"
    fi

    # RULE201:
    if grep -Psi '^\h*maxrepeat\h*=\h*[1-3]\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null; then
    sec_audit_report_pass 201 "maxrepeat is configured"
    else
    sec_audit_report_fail 201 "maxrepeat is not configured or greater than 3"
    fi

    # RULE202:
    if grep -Psi '^\h*maxsequence\h*=\h*[1-3]\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null; then
    sec_audit_report_pass 202 "maxsequence is configured"
    else
    sec_audit_report_fail 202 "maxsequence is not configured or greater than 3"
    fi

    # RULE203:
    if ! grep -Psi '^\h*dictcheck\h*=\h*0\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null; then
    sec_audit_report_pass 203 "password dictionary check is enabled"
    else
    sec_audit_report_fail 203 "pwquality dictcheck is disabled or weak"
    fi

    # RULE204:
    if grep -Psi '\h*enforce_for_root\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null; then
    sec_audit_report_pass 204 "password quality is enforced for the root user"
    else
    sec_audit_report_fail 204 "pwquality enforce_for_root is not set"
    fi

    # RULE205:
    if grep -Psi 'remember\h*=\h*(2[4-9]|[3-9][0-9]|[1-9][0-9]{2,})\b' /etc/security/pwhistory.conf 2>/dev/null; then
    sec_audit_report_pass 205 "password history remember is configured"
    elif sec_audit_pam_stacks_grep_Pi '^\h*password\h+([^#\n\r]+)\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?remember=[0-9]+'; then
    _r=$(sec_audit_pam_stack_paths_password_system | while IFS= read -r _p; do
        [[ -f "$_p" ]] || continue
        grep -Po 'remember=\K[0-9]+' "$_p" 2>/dev/null | head -n1 && break
    done)
    if [[ "${_r:-0}" -ge 24 ]]; then
        sec_audit_report_pass 205 "password history remember is configured (authselect/PAM stack)"
    else
        sec_audit_report_fail 205 "pwhistory remember value is below policy or not configured"
    fi
    else
    sec_audit_report_fail 205 "pwhistory remember value is below policy or not configured"
    fi

    # RULE206:
    if grep -Psi 'enforce_for_root\b' /etc/security/pwhistory.conf 2>/dev/null; then
    sec_audit_report_pass 206 "password history is enforced for the root user"
    else
    sec_audit_report_fail 206 "pwhistory enforce_for_root is not set"
    fi

    # RULE207:
    if sec_audit_pam_stacks_grep_P '^\h*password\h+([^#\n\r]+)\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?use_authtok\b'; then
    sec_audit_report_pass 207 "pam_pwhistory includes use_authtok"
    else
    sec_audit_report_fail 207 "pam_pwhistory line lacks use_authtok on password-auth/system-auth stack"
    fi

    # RULE208:
    if ! sec_audit_pam_auth_stacks_grep_Pi '^\h*auth\h+.*pam_unix\.so.*nullok'; then
    sec_audit_report_pass 208 "pam_unix does not include nullok"
    else
    sec_audit_report_fail 208 "pam_unix still allows nullok in the auth stack"
    fi

    # RULE209:
    if ! sec_audit_pam_stacks_grep_Pi '^\h*password\h+([^#\n\r]+)\h+pam_unix\.so.*remember='; then
    sec_audit_report_pass 209 "pam_unix does not include remember"
    else
    sec_audit_report_fail 209 "pam_unix password line still uses remember="
    fi

    # RULE210:
    if grep -q "pam_unix.so.*sha512" /etc/pam.d/password-auth 2>/dev/null && grep -q "pam_unix.so.*sha512" /etc/pam.d/system-auth 2>/dev/null; then
    sec_audit_report_pass 210 "sha512 is used"
    elif grep -q "pam_unix.so.*yescrypt" /etc/pam.d/password-auth 2>/dev/null && grep -q "pam_unix.so.*yescrypt" /etc/pam.d/system-auth 2>/dev/null; then
    sec_audit_report_pass 210 "yescrypt is used"
    else
    sec_audit_report_fail 210 "Strong hashing algorithm is not used"
    fi

    # RULE211:
    if sec_audit_pam_stacks_grep_P '^\h*password\h+([^#\n\r]+)\h+pam_unix\.so\h+([^#\n\r]+\h+)?use_authtok\b'; then
    sec_audit_report_pass 211 "pam_unix includes use_authtok"
    else
    sec_audit_report_fail 211 "pam_unix password line lacks use_authtok on password-auth/system-auth stack"
    fi

}

sec_audit_run_accounts() {
    # RULE212:
    if grep -Psi '^\h*PASS_MAX_DAYS\h+(36[0-5]|3[0-5][0-9]|[1-2][0-9][0-9]|[1-9][0-9]|[1-9])\b' /etc/login.defs 2>/dev/null; then
    if ! awk -F: '($2~/^\$.+\$/) {if($5 > 365 || $5 < 1)print}' /etc/shadow 2>/dev/null | grep -q '.'; then
        sec_audit_report_pass 212 "password expiration is configured"
    else
        sec_audit_report_fail 212 "PASS_MAX_DAYS or per-user shadow MAX exceeds policy or is unset"
    fi
    else
    sec_audit_report_fail 212 "PASS_MAX_DAYS or per-user shadow MAX exceeds policy or is unset"
    fi

    # RULE213:
    if grep -q "^PASS_MIN_DAYS" /etc/login.defs 2>/dev/null; then
    MIN_DAYS=$(grep "^PASS_MIN_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
    if [ "$MIN_DAYS" -ge 7 ] 2>/dev/null; then
        sec_audit_report_pass 213 "Minimum password days is configured"
    else
        sec_audit_report_fail 213 "Minimum password days is too low (recommended 7+)"
    fi
    else
    sec_audit_report_fail 213 "Minimum password days is not configured"
    fi

    # RULE214:
    if grep -Psi '^\h*PASS_WARN_AGE\h+([7-9]|[1-9][0-9]+)\b' /etc/login.defs 2>/dev/null; then
    if ! awk -F: '($2~/^\$.+\$/) {if($6 < 7)print}' /etc/shadow 2>/dev/null | grep -q '.'; then
        sec_audit_report_pass 214 "password expiration warning days is configured"
    else
        sec_audit_report_fail 214 "PASS_WARN_AGE is not set within policy in /etc/login.defs"
    fi
    else
    sec_audit_report_fail 214 "PASS_WARN_AGE is not set within policy in /etc/login.defs"
    fi

    # RULE215:
    if grep -Psi '^\h*ENCRYPT_METHOD\h+(SHA512|YESCRYPT)\b' /etc/login.defs 2>/dev/null; then
    sec_audit_report_pass 215 "strong password hashing algorithm is configured"
    else
    sec_audit_report_fail 215 "ENCRYPT_METHOD in /etc/login.defs does not use a strong hashing algorithm"
    fi

    # RULE216:
    if useradd -D 2>/dev/null | grep INACTIVE | cut -d= -f2 | grep -qE '^([1-9]|[1-4][0-9]|45)$'; then
    if ! awk -F: '($2~/^\$.+\$/) {if($7 > 45 || $7 < 0)print}' /etc/shadow 2>/dev/null | grep -q '.'; then
        sec_audit_report_pass 216 "inactive password lock is configured"
    else
        sec_audit_report_fail 216 "useradd INACTIVE or inactive lock policy is not configured"
    fi
    else
    sec_audit_report_fail 216 "useradd INACTIVE or inactive lock policy is not configured"
    fi

    # RULE217:
    FAIL195=0
    while IFS=: read -r user pass last_change rest; do
    if [ -n "$last_change" ] && [ "$last_change" -gt 0 ] 2>/dev/null; then
        current_date=$(date +%s)
        last_change_seconds=$((last_change * 86400))
        if [ "$last_change_seconds" -gt "$current_date" ]; then
            sec_audit_report_fail 217 "User $user has password change date in the future"
            FAIL195=1
        fi
    fi
    done < /etc/shadow 2>/dev/null
    if [ $FAIL195 -eq 0 ]; then
    sec_audit_report_pass 217 "All users last password change date is in the past"
    fi

    # RULE218:
    if awk -F: '($3 == 0) { print $1 }' /etc/passwd 2>/dev/null | grep -qx "root"; then
    if [ $(awk -F: '($3 == 0) { print $1 }' /etc/passwd 2>/dev/null | wc -l) -eq 1 ]; then
        sec_audit_report_pass 218 "root is the only UID 0 account"
    else
        sec_audit_report_fail 218 "Multiple accounts with UID 0 exist in /etc/passwd"
    fi
    else
    sec_audit_report_fail 218 "Multiple accounts with UID 0 exist in /etc/passwd"
    fi

    # RULE219:
    if awk -F: '($1 !~ /^(sync|shutdown|halt|operator)/ && $4=="0") {print $1":"$4}' /etc/passwd 2>/dev/null | grep -q "root:0"; then
    if [ $(awk -F: '($1 !~ /^(sync|shutdown|halt|operator)/ && $4=="0") {print}' /etc/passwd 2>/dev/null | wc -l) -eq 1 ]; then
        sec_audit_report_pass 219 "root is the only GID 0 account"
    else
        sec_audit_report_fail 219 "Multiple users use GID 0 outside policy"
    fi
    else
    sec_audit_report_fail 219 "Multiple users use GID 0 outside policy"
    fi

    # RULE220:
    if awk -F: '$3=="0"{print $1":"$3}' /etc/group 2>/dev/null | grep -q "root:0"; then
    if [ $(awk -F: '$3=="0"{print}' /etc/group 2>/dev/null | wc -l) -eq 1 ]; then
        sec_audit_report_pass 220 "group root is the only GID 0 group"
    else
        sec_audit_report_fail 220 "Multiple groups share GID 0"
    fi
    else
    sec_audit_report_fail 220 "Multiple groups share GID 0"
    fi

    # RULE221:
    if passwd -S root 2>/dev/null | awk '$2 ~ /^(P|L)/' | grep -q "root"; then
    sec_audit_report_pass 221 "root account access is controlled"
    else
    sec_audit_report_fail 221 "root SSH/console access restrictions are not configured as required"
    fi

    # RULE222:
    FAIL200=0
    ROOT_PATH=$(sudo -i echo "\$PATH" 2>/dev/null || echo "$PATH")
    if echo "$ROOT_PATH" | grep -q "::"; then
    sec_audit_report_fail 222 "Root PATH contains empty directory (::)"
    FAIL200=1
    fi
    if echo "$ROOT_PATH" | grep -q "\.:"; then
    sec_audit_report_fail 222 "Root PATH contains current directory (.)"
    FAIL200=1
    fi
    if [ $FAIL200 -eq 0 ]; then
    sec_audit_report_pass 222 "Root path integrity is maintained"
    fi

    # RULE223:
    if ! grep -Psi '^\h*umask\h+((\d{1,2}(\d[^7]|[^2-7]\d)\b)|(u=[rwx]{1,3},)?(((g=[rx]?[rx]?w[rx]?[rx]?\b)(,o=[rwx]{1,3})?)|((g=[wrx]{1,3},)?o=[wrx]{1,3}\b)))' /root/.bash_profile /root/.bashrc 2>/dev/null; then
    sec_audit_report_pass 223 "root user umask is configured"
    else
    sec_audit_report_fail 223 "root umask is not 027 (or stricter) in profile scripts"
    fi

    # RULE224:
    VALID_SHELLS=$(awk -F\/ '$NF != "nologin" && $NF != "false" {print}' /etc/shells 2>/dev/null | sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' -)
    UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs 2>/dev/null)
    if awk -v pat="^($VALID_SHELLS)$" -v uidmin="$UID_MIN" -F: '($1!~/^(root|halt|sync|shutdown|nfsnobody)$/ && ($3<uidmin || $3==65534) && $NF ~ pat) {print}' /etc/passwd 2>/dev/null | grep -q '.'; then
    sec_audit_report_fail 224 "System accounts still have an interactive login shell"
    else
    sec_audit_report_pass 224 "system accounts do not have a valid login shell"
    fi

    # RULE225:
    VALID_SHELLS=$(awk -F\/ '$NF != "nologin" && $NF != "false" {print}' /etc/shells 2>/dev/null | sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' -)
    FAIL203=0
    while IFS= read -r l_user; do
    if passwd -S "$l_user" 2>/dev/null | awk '$2 !~ /^L/ {print "found"}' | grep -q "found"; then
        sec_audit_report_fail 225 "Accounts without a valid shell are not locked in /etc/shadow"
        FAIL203=1
        break
    fi
    done <<< "$(awk -v pat="^($VALID_SHELLS)$" -F: '($1 != "root" && $NF !~ pat) {print $1}' /etc/passwd 2>/dev/null)"
    if [ $FAIL203 -eq 0 ]; then
    sec_audit_report_pass 225 "accounts without a valid login shell are locked"
    fi

    # RULE226:
    if grep -Ps '^\h*([^#\n\r]+)?\/nologin\b' /etc/shells 2>/dev/null; then
    sec_audit_report_fail 226 "nologin appears in /etc/shells"
    else
    sec_audit_report_pass 226 "nologin is not listed in /etc/shells"
    fi

    # RULE227:
    if grep -Psi '^([^#\n\r]+)?\bTMOUT=(9[0-9]{1,2}|[1-9][0-9]|[1-9])\b' /etc/*bashrc /etc/profile /etc/profile.d/*.sh 2>/dev/null; then
    sec_audit_report_pass 227 "default user shell timeout is configured"
    else
    sec_audit_report_fail 227 "TMOUT is not set for interactive shells in /etc/profile or profile.d"
    fi

    # RULE228:
    if grep -Psi '^\h*umask\h+0?(?:[0-7][2-7]7)\b' /etc/login.defs 2>/dev/null; then
    if grep -Psi '^\h*umask\h+0?027\b' /etc/profile.d/*.sh 2>/dev/null; then
        sec_audit_report_pass 228 "default user umask is configured"
    else
        sec_audit_report_fail 228 "Default user umask 027 is not set in /etc/profile or profile.d"
    fi
    else
    sec_audit_report_fail 228 "Default user umask 027 is not set in /etc/profile or profile.d"
    fi

}

sec_audit_run_aide() {
    # RULE229:
    if rpm -q aide &>/dev/null; then
    _a207_db=""
    if [ -f /var/lib/aide/aide.db.gz ] || [ -f /var/lib/aide/aide.db ]; then
        _a207_db="; AIDE database file present under /var/lib/aide"
    else
        _a207_db="; WARNING: no AIDE database under /var/lib/aide (initialize with aide --init)"
    fi
    sec_audit_report_pass 229 "AIDE package is installed${_a207_db}"
    else
    sec_audit_report_fail 229 "AIDE package is not installed"
    fi

    # RULE230:
    if grep -Ers '^([^#]+\s+)?(\/usr\/s?bin\/|^\s*)aide(\.wrapper)?\s(--?\S+\s)*(-(check|update)|\$AIDEARGS)\b' /etc/cron.* /etc/crontab /var/spool/cron/ /etc/cron.d 2>/dev/null; then
    sec_audit_report_pass 230 "filesystem integrity is regularly checked (cron/cron.d entry references aide)"
    elif systemctl is-enabled aidecheck.timer 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active aidecheck.timer 2>/dev/null | grep -q 'active'; then
        _a208_n=$(systemctl show aidecheck.timer -p NextElapseUSRealtime 2>/dev/null | cut -d= -f2-)
        sec_audit_report_pass 230 "aidecheck.timer enabled and active (next: ${_a208_n:-unknown})"
    else
        sec_audit_report_fail 230 "aidecheck.timer enabled but not active"
    fi
    else
    sec_audit_report_fail 230 "filesystem integrity is regularly checked"
    fi

    # RULE231:
    if ! rpm -q aide &>/dev/null; then
    sec_audit_report_fail 231 "AIDE not installed; cannot verify integrity of audit tools"
    elif ! [ -f /etc/aide.conf ]; then
    sec_audit_report_fail 231 "/etc/aide.conf missing"
    elif grep -qE '/sbin/(audit|auditctl|ausearch|aureport|autrace|auid)' /etc/aide.conf 2>/dev/null || \
     grep -qE '/usr/sbin/(audit|auditctl|ausearch|aureport|autrace)' /etc/aide.conf 2>/dev/null; then
    sec_audit_report_pass 231 "AIDE is configured to protect audit tools"
    else
    sec_audit_report_fail 231 "AIDE is not configured to protect audit tools"
    fi

}

sec_audit_run_logging() {
    # RULE232:
    if systemctl is-enabled systemd-journald.service 2>/dev/null | grep -q 'static'; then
    if systemctl is-active systemd-journald.service 2>/dev/null | grep -q 'active'; then
        sec_audit_report_pass 232 "journald service is active"
    else
        sec_audit_report_fail 232 "systemd-journald is not active or not in expected state"
    fi
    else
    sec_audit_report_fail 232 "systemd-journald is not active or not in expected state"
    fi

    # RULE233:
    if [ -d /var/log/journal ]; then
    DIR_PERM=$(stat -c '%a' /var/log/journal 2>/dev/null)
    if [ "$DIR_PERM" = "755" ] || [ "$DIR_PERM" = "750" ]; then
        sec_audit_report_pass 233 "journald log file access is configured (directory mode: $DIR_PERM)"
    else
        sec_audit_report_fail 233 "journald log directory has insecure permissions: $DIR_PERM"
    fi
    else
    sec_audit_report_pass 233 "journald log file access is configured (directory not found)"
    fi

    # RULE234:
    if grep -q "^SystemMaxUse\|^SystemMaxFileSize\|^MaxFileSec" /etc/systemd/journald.conf 2>/dev/null; then
    sec_audit_report_pass 234 "journald log file rotation is configured"
    else
    sec_audit_report_skip 234 "journald log file rotation using defaults (may be acceptable)"
    fi

    # RULE235:
    if systemctl is-active --quiet rsyslog; then
    if systemctl is-active --quiet systemd-journald; then
        sec_audit_report_fail 235 "more than one logging system is in use (both rsyslog and journald are active)"
    else
        sec_audit_report_pass 235 "only one logging system is in use (rsyslog)"
    fi
    elif systemctl is-active --quiet systemd-journald; then
    sec_audit_report_pass 235 "only one logging system is in use (journald)"
    else
    sec_audit_report_fail 235 "no logging system is active (neither rsyslog nor journald)"
    fi

    # RULE236:
    if rpm -q systemd-journal-remote &>/dev/null; then
    sec_audit_report_pass 236 "systemd-journal-remote is installed"
    else
    sec_audit_report_fail 236 "systemd-journal-remote package is not installed (if required by policy)"
    fi

    # RULE237:
    if ! rpm -q systemd-journal-remote &>/dev/null; then
    sec_audit_report_pass 237 "systemd-journal-remote not installed (upload auth N/A)"
    elif grep -rEiq '^\s*URL=\s*https://' /etc/systemd/journal-upload.conf /etc/systemd/journal-upload.conf.d/ 2>/dev/null; then
    sec_audit_report_pass 237 "journal-upload uses HTTPS URL"
    elif grep -rEiq '^\s*ServerKeyFile=|^\s*ServerCertificateFile=' /etc/systemd/journal-upload.conf /etc/systemd/journal-upload.conf.d/ 2>/dev/null; then
    sec_audit_report_pass 237 "journal-upload TLS key/certificate configured"
    else
    sec_audit_report_fail 237 "systemd-journal-upload authentication is not configured"
    fi

    # RULE238:
    if systemctl is-enabled systemd-journal-upload.service 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active systemd-journal-upload.service 2>/dev/null | grep -q 'active'; then
        sec_audit_report_pass 238 "systemd-journal-upload is enabled and active"
    else
        sec_audit_report_fail 238 "systemd-journal-upload is not enabled or not active"
    fi
    else
    sec_audit_report_fail 238 "systemd-journal-upload is not enabled or not active"
    fi

    # RULE239:
    if systemctl is-enabled systemd-journal-remote.socket systemd-journal-remote.service 2>/dev/null | grep -q 'enabled'; then
    sec_audit_report_fail 239 "systemd-journal-remote socket/service is enabled or active but should be disabled"
    elif systemctl is-active systemd-journal-remote.socket systemd-journal-remote.service 2>/dev/null | grep -q 'active'; then
    sec_audit_report_fail 239 "systemd-journal-remote socket/service is enabled or active but should be disabled"
    else
    sec_audit_report_pass 239 "systemd-journal-remote service is not in use"
    fi

    # RULE240:
    if systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -E '^ForwardToSyslog=no' | head -1 | grep -q "ForwardToSyslog=no"; then
    sec_audit_report_pass 240 "journald ForwardToSyslog is disabled"
    elif systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -E '^ForwardToSyslog=yes' | head -1 | grep -q "ForwardToSyslog=yes"; then
    sec_audit_report_fail 240 "journald ForwardToSyslog is disabled (should be no)"
    else
    sec_audit_report_pass 240 "journald ForwardToSyslog is disabled (default)"
    fi

    # RULE241:
    if systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -E '^Compress=yes' | head -1 | grep -q "Compress=yes"; then
    sec_audit_report_pass 241 "journald Compress is configured"
    else
    sec_audit_report_pass 241 "journald Compress is configured (default)"
    fi

    # RULE242:
    if systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -E '^Storage=persistent' | head -1 | grep -q "Storage=persistent"; then
    sec_audit_report_pass 242 "journald Storage is configured"
    else
    sec_audit_report_fail 242 "journald Storage=persistent (or required value) is not set in merged config"
    fi

    # RULE243:
    if rpm -q rsyslog &>/dev/null; then
    sec_audit_report_pass 243 "rsyslog is installed"
    else
    sec_audit_report_fail 243 "rsyslog package is not installed"
    fi

    # RULE244:
    if systemctl is-enabled rsyslog 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active rsyslog.service 2>/dev/null | grep -q 'active'; then
        sec_audit_report_pass 244 "rsyslog service is enabled and active"
    else
        sec_audit_report_fail 244 "rsyslog is not enabled or not active"
    fi
    else
    sec_audit_report_fail 244 "rsyslog is not enabled or not active"
    fi

    # RULE245:
    if systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -E '^ForwardToSyslog=yes' | head -1 | grep -q "ForwardToSyslog=yes"; then
    sec_audit_report_pass 245 "journald is configured to send logs to rsyslog"
    else
    sec_audit_report_fail 245 "journald ForwardToSyslog or forwarding to rsyslog is not configured"
    fi

    # RULE246:
    if grep -Ps '^\h*\$FileCreateMode\h+0[0,2,4,6][0,2,4]0\b' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null; then
    sec_audit_report_pass 246 "rsyslog log file creation mode is configured"
    else
    sec_audit_report_fail 246 "rsyslog $FileCreateMode (or equivalent) does not meet policy"
    fi

    # RULE247:
    if command -v rsyslogd &>/dev/null; then
    if [ -f /etc/rsyslog.conf ] && grep -v "^#" /etc/rsyslog.conf 2>/dev/null | grep -q "^\*\.\*\|^auth\|^mail\|^cron"; then
        sec_audit_report_pass 247 "rsyslog logging is configured"
    else
        sec_audit_report_fail 247 "rsyslog logging is not properly configured"
    fi
    else
    sec_audit_report_pass 247 "rsyslog is not installed"
    fi

    # RULE248:
    if grep -rE '^[^#[:space:]].*@@[^@[:space:]]' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -qvE '@@127\.0\.0\.1|@@localhost'; then
    sec_audit_report_pass 248 "rsyslog sends logs to a remote host"
    elif grep -rE '^[^#[:space:]].*[^@]@[^@[:space:]]' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -qvE '@127\.0\.0\.1|@localhost'; then
    sec_audit_report_pass 248 "rsyslog sends logs to a remote host"
    else
    sec_audit_report_fail 248 "rsyslog is not configured to send logs to a remote host"
    fi

    # RULE249:
    if grep -rE '^\s*module\(load="imtcp"\)|^\s*input\(type="imtcp"\)' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -q .; then
    sec_audit_report_fail 249 "rsyslog is configured to receive remote logs"
    else
    sec_audit_report_pass 249 "rsyslog is not configured to receive remote logs"
    fi

    # RULE250:
    if command -v logrotate &>/dev/null; then
    if [ -f /etc/logrotate.conf ] && grep -q "^rotate\|^daily\|^weekly\|^monthly" /etc/logrotate.conf 2>/dev/null; then
        sec_audit_report_pass 250 "rsyslog logrotate is configured"
    else
        sec_audit_report_fail 250 "rsyslog logrotate is not properly configured"
    fi
    else
    sec_audit_report_fail 250 "logrotate is not installed"
    fi

    # RULE251:
    FAIL225=0
    for logfile in /var/log/messages /var/log/secure /var/log/maillog /var/log/cron /var/log/boot.log; do
    if [ -f "$logfile" ]; then
        PERM=$(stat -c '%a' "$logfile" 2>/dev/null)
        OWNER=$(stat -c '%U' "$logfile" 2>/dev/null)
        if [ "$PERM" -gt 640 ] 2>/dev/null || [ "$OWNER" != "root" ]; then
            sec_audit_report_fail 251 "$logfile has insecure permissions ($PERM) or owner ($OWNER)"
            FAIL225=1
        fi
    fi
    done
    [ $FAIL225 -eq 0 ] && sec_audit_report_pass 251 "Access to all logfiles has been configured"

}

sec_audit_run_auditd() {
    # RULE252:
    if rpm -q audit audit-libs &>/dev/null; then
    sec_audit_report_pass 252 "auditd packages are installed"
    else
    sec_audit_report_fail 252 "audit audit-libs packages are not installed"
    fi

    # RULE253:
    if grep -E 'audit=1' /etc/default/grub 2>/dev/null | grep -q .; then
    sec_audit_report_pass 253 "audit=1 is set in kernel parameters"
    else
    _grubcfg=$(find /boot -maxdepth 3 -name grub.cfg 2>/dev/null | head -1)
    if [ -n "$_grubcfg" ] && grep -E '^\s*linux' "$_grubcfg" 2>/dev/null | grep -q 'audit=1'; then
        sec_audit_report_pass 253 "audit=1 is set in kernel parameters"
    else
        sec_audit_report_fail 253 "audit=1 is not set in kernel parameters"
    fi
    fi

    # RULE254:
    if grep -Psoi '^\h*GRUB_CMDLINE_LINUX=\"([^#\n\r]+\h+)?\baudit_backlog_limit=\d+\b' /etc/default/grub 2>/dev/null; then
    sec_audit_report_pass 254 "audit_backlog_limit is configured"
    else
    sec_audit_report_fail 254 "audit_backlog_limit is not set appropriately in audit rules or sysctl"
    fi

    # RULE255:
    if systemctl is-enabled auditd 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active auditd 2>/dev/null | grep -q 'active'; then
        sec_audit_report_pass 255 "auditd service is enabled and active"
    else
        sec_audit_report_fail 255 "auditd is not enabled or not active"
    fi
    else
    sec_audit_report_fail 255 "auditd is not enabled or not active"
    fi

    # RULE256:
    if grep -Po '^\h*max_log_file\h*=\h*\d+\b' /etc/audit/auditd.conf 2>/dev/null; then
    sec_audit_report_pass 256 "audit log storage size is configured"
    else
    sec_audit_report_fail 256 "max_log_file or rotation policy in auditd.conf does not meet policy"
    fi

    # RULE257:
    if grep -Pi '^\h*max_log_file_action\h*=\h*keep_logs\b' /etc/audit/auditd.conf 2>/dev/null; then
    sec_audit_report_pass 257 "audit logs are not automatically deleted"
    else
    sec_audit_report_fail 257 "max_log_file_action or keep_logs policy allows silent deletion"
    fi

    # RULE258:
    if grep -P '^\h*disk_full_action\h*=\h*(halt|single)\b' /etc/audit/auditd.conf 2>/dev/null; then
    if grep -P '^\h*disk_error_action\h*=\h*(syslog|single|halt)\b' /etc/audit/auditd.conf 2>/dev/null; then
        sec_audit_report_pass 258 "system is disabled when audit logs are full"
    else
        sec_audit_report_fail 258 "disk_full_action / space_left_action in auditd.conf does not meet policy"
    fi
    else
    sec_audit_report_fail 258 "disk_full_action / space_left_action in auditd.conf does not meet policy"
    fi

    # RULE259:
    if grep -P '^\h*space_left_action\h*=\h*(email|exec|single|halt)\b' /etc/audit/auditd.conf 2>/dev/null; then
    if grep -P '^\h*admin_space_left_action\h*=\h*(single|halt)\b' /etc/audit/auditd.conf 2>/dev/null; then
        sec_audit_report_pass 259 "system warns when audit logs are low on space"
    else
        sec_audit_report_fail 259 "space_left_action / admin_space_left_action in auditd.conf are incomplete"
    fi
    else
    sec_audit_report_fail 259 "space_left_action / admin_space_left_action in auditd.conf are incomplete"
    fi

    # RULE260:
    if sec_audit_audit_rule_loaded_and_on_disk -q "path=/etc/sudoers"; then
    if sec_audit_audit_rule_loaded_and_on_disk -q "dir=/etc/sudoers.d"; then
        sec_audit_report_pass 260 "sudoers and sudoers.d watch rules present in audit.rules and loaded in kernel"
    else
        sec_audit_report_fail 260 "/etc/sudoers.d directory watch missing on disk or not loaded"
    fi
    else
    sec_audit_report_fail 260 "/etc/sudoers file watch missing on disk or not loaded"
    fi

    # RULE261:
    if sec_audit_audit_rule_loaded_and_on_disk -q "execve"; then
    sec_audit_report_pass 261 "execve auditing present on disk and loaded"
    else
    sec_audit_report_fail 261 "actions as another user are not always logged (execve audit rule missing or not loaded)"
    fi

    # RULE262:
    if [ -f /var/log/sudo.log ]; then
    if sec_audit_audit_rule_loaded_and_on_disk -q "path=/var/log/sudo.log"; then
        sec_audit_report_pass 262 "audit rule for /var/log/sudo.log on disk and loaded"
    else
        sec_audit_report_fail 262 "events that modify the sudo log file are not collected (audit watch for /var/log/sudo.log missing or not loaded)"
    fi
    else
    sec_audit_report_fail 262 "events that modify the sudo log file are not collected (/var/log/sudo.log not found)"
    fi

    # RULE263:
    if sec_audit_audit_rule_loaded_and_on_disk -E -q 'adjtimex|settimeofday|clock_settime|stime'; then
    sec_audit_report_pass 263 "date and time modifications are audited"
    else
    sec_audit_report_fail 263 "date and time modifications are not audited"
    fi

    # RULE264:
    if auditctl -l 2>/dev/null | grep -q "sethostname\|setdomainname" || grep -q "sethostname\|setdomainname" /etc/audit/rules.d/*.rules 2>/dev/null; then
    sec_audit_report_pass 264 "hostname/domainname modifications are audited"
    else
        sec_audit_report_fail 264 "hostname/domainname modifications are not audited"
    fi

    # RULE265:
    if auditctl -l 2>/dev/null | grep -q "/etc/issue" || grep -q "/etc/issue" /etc/audit/rules.d/*.rules 2>/dev/null; then
    sec_audit_report_pass 265 "/etcissue modifications are audited"
    else
        sec_audit_report_fail 265 "/etc/issue modifications are not audited"
    fi

    # RULE266:
    if auditctl -l 2>/dev/null | grep -q "/etc/hosts\|/etc/hostname" || grep -q "/etc/hosts\|/etc/hostname" /etc/audit/rules.d/*.rules 2>/dev/null; then
    sec_audit_report_pass 266 "hosts file modifications are audited"
    else
        sec_audit_report_fail 266 "hosts file modifications are not audited"
    fi

    # RULE267:
    if auditctl -l 2>/dev/null | grep -q "/etc/sysconfig/network\|/etc/NetworkManager" || grep -q "/etc/sysconfig/network\|/etc/NetworkManager" /etc/audit/rules.d/*.rules 2>/dev/null; then
    sec_audit_report_pass 267 "network configuration modifications are audited"
    else
        sec_audit_report_fail 267 "network configuration modifications are not audited"
    fi

    # RULE268:
    if sec_audit_audit_rule_loaded_and_on_disk -q "dir=/etc/NetworkManager/"; then
    sec_audit_report_pass 268 "NetworkManager directory watch on disk and loaded"
    else
    sec_audit_report_fail 268 "events that modify /etc/NetworkManager directory are not collected"
    fi

    # RULE269:
    if command -v auditctl &>/dev/null; then
    if sec_audit_audit_rule_loaded_and_on_disk -E -q 'path=/usr/bin/sudo|path=/usr/bin/su|path=/bin/su'; then
        sec_audit_report_pass 269 "privileged command execution (sudo/su) audited on disk and loaded"
    else
        sec_audit_report_fail 269 "use of privileged commands is not being collected"
    fi
    else
        sec_audit_report_fail 269 "auditctl not available; use of privileged commands is not being collected"
    fi

    # RULE270:
    if sec_audit_audit_rule_loaded_and_on_disk -E -q 'EACCES|EPERM'; then
    sec_audit_report_pass 270 "unsuccessful access (EACCES/EPERM) auditing on disk and loaded"
    else
    sec_audit_report_fail 270 "unsuccessful file access attempts are not collected"
    fi

    # RULE271:
    if sec_audit_audit_rule_loaded_and_on_disk -q "path=/etc/group"; then
    sec_audit_report_pass 271 "/etc/group modifications are audited"
    else
    sec_audit_report_fail 271 "/etc/group modifications are not audited"
    fi

    # RULE272:
    if auditctl -l 2>/dev/null | grep -q "/etc/passwd" || grep -q "/etc/passwd" /etc/audit/rules.d/*.rules 2>/dev/null; then
    sec_audit_report_pass 272 "/etc/passwd modifications are audited"
    else
        sec_audit_report_fail 272 "/etc/passwd modifications are not audited"
    fi

    # RULE273:
    if sec_audit_audit_rule_loaded_and_on_disk -q "path=/etc/shadow"; then
    if sec_audit_audit_rule_loaded_and_on_disk -q "path=/etc/gshadow"; then
        sec_audit_report_pass 273 "shadow and gshadow watches on disk and loaded"
    else
        sec_audit_report_fail 273 "events that modify /etc/gshadow are not collected (watch missing on disk or not loaded)"
    fi
    else
    sec_audit_report_fail 273 "events that modify /etc/shadow are not collected (watch missing on disk or not loaded)"
    fi

    # RULE274:
    if sec_audit_audit_rule_loaded_and_on_disk -q "path=/etc/security/opasswd"; then
    sec_audit_report_pass 274 "opasswd modifications are audited"
    else
    sec_audit_report_fail 274 "opasswd modifications are not audited"
    fi

    # RULE275:
    if auditctl -l 2>/dev/null | grep -q "/etc/nsswitch.conf" || grep -q "/etc/nsswitch.conf" /etc/audit/rules.d/*.rules 2>/dev/null; then
    sec_audit_report_pass 275 "nsswitch.conf modifications are audited"
    else
        sec_audit_report_fail 275 "nsswitch.conf modifications are not audited"
    fi

    # RULE276:
    if auditctl -l 2>/dev/null | grep -q "/etc/pam.conf\|/etc/pam.d" || grep -q "/etc/pam.conf\|/etc/pam.d" /etc/audit/rules.d/*.rules 2>/dev/null; then
    sec_audit_report_pass 276 "PAM configuration modifications are audited"
    else
        sec_audit_report_fail 276 "PAM configuration modifications are not audited"
    fi

    # RULE277:
    if auditctl -l 2>/dev/null | grep -q "chmod\|fchmod\|fchmodat" || grep -q "chmod\|fchmod\|fchmodat" /etc/audit/rules.d/*.rules 2>/dev/null; then
    sec_audit_report_pass 277 "permission modification events are audited"
    else
        sec_audit_report_fail 277 "permission modification events are not audited"
    fi

    # RULE278:
    if auditctl -l 2>/dev/null | grep -q "chown\|fchown\|lchown\|fchownat" || grep -q "chown\|fchown\|lchown\|fchownat" /etc/audit/rules.d/*.rules 2>/dev/null; then
    sec_audit_report_pass 278 "ownership modification events are audited"
    else
        sec_audit_report_fail 278 "ownership modification events are not audited"
    fi

    # RULE279:
    if auditctl -l 2>/dev/null | grep -q "xattr" || grep -q "xattr" /etc/audit/rules.d/*.rules 2>/dev/null; then
    sec_audit_report_pass 279 "xattr modification events are audited"
    else
        sec_audit_report_fail 279 "xattr modification events are not audited"
    fi

    # RULE280:
    if sec_audit_audit_rule_loaded_and_on_disk -q "mount"; then
    sec_audit_report_pass 280 "mount syscall auditing on disk and loaded"
    else
    sec_audit_report_fail 280 "successful file system mounts are not collected"
    fi

    # RULE281:
    if sec_audit_audit_rule_loaded_and_on_disk -E -q 'utmp|wtmp|btmp'; then
    sec_audit_report_pass 281 "session initiation (utmp/wtmp/btmp) auditing on disk and loaded"
    else
    sec_audit_report_fail 281 "session initiation information is not collected"
    fi

    # RULE282:
    if sec_audit_audit_rule_loaded_and_on_disk -E -q 'lastlog|faillock'; then
    sec_audit_report_pass 282 "login/logout related auditing on disk and loaded"
    else
    sec_audit_report_fail 282 "login and logout events are not collected"
    fi

    # RULE283:
    if sec_audit_audit_rule_loaded_and_on_disk -q "unlink"; then
    sec_audit_report_pass 283 "unlink auditing on disk and loaded"
    else
    sec_audit_report_fail 283 "unlink file deletion events by users are not collected"
    fi

    # RULE284:
    if sec_audit_audit_rule_loaded_and_on_disk -q "rename"; then
    sec_audit_report_pass 284 "rename events are audited"
    else
    sec_audit_report_fail 284 "rename events are not audited"
    fi

    # RULE285:
    if auditctl -l 2>/dev/null | grep -q "/etc/selinux\|/usr/share/selinux" || grep -q "/etc/selinux\|/usr/share/selinux" /etc/audit/rules.d/*.rules 2>/dev/null; then
    sec_audit_report_pass 285 "SELinux modifications are audited"
    else
        sec_audit_report_fail 285 "SELinux modifications are not audited"
    fi

    uid_min=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs 2>/dev/null || echo "1000")

    # RULE286:
    if auditctl -l 2>/dev/null | grep -q "/usr/bin/chcon.*auid>=$uid_min" || grep -q "/usr/bin/chcon.*auid>=$uid_min" /etc/audit/rules.d/*.rules 2>/dev/null; then
    sec_audit_report_pass 286 "chcon command usage is audited"
    else
        sec_audit_report_fail 286 "chcon command usage is not audited"
    fi

    uid_min=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs 2>/dev/null || echo "1000")

    # RULE287:
    if auditctl -l 2>/dev/null | grep -q "/usr/bin/setfacl.*auid>=$uid_min" || grep -q "/usr/bin/setfacl.*auid>=$uid_min" /etc/audit/rules.d/*.rules 2>/dev/null; then
    sec_audit_report_pass 287 "setfacl command usage is audited"
    else
        sec_audit_report_fail 287 "setfacl command usage is not audited"
    fi

    uid_min=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs 2>/dev/null || echo "1000")

    # RULE288:
    if auditctl -l 2>/dev/null | grep -q "/usr/bin/chacl.*auid>=$uid_min" || grep -q "/usr/bin/chacl.*auid>=$uid_min" /etc/audit/rules.d/*.rules 2>/dev/null; then
    sec_audit_report_pass 288 "chacl command usage is audited"
    else
        sec_audit_report_fail 288 "chacl command usage is not audited"
    fi

    uid_min=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs 2>/dev/null || echo "1000")

    # RULE289:
    if auditctl -l 2>/dev/null | grep -q "/usr/sbin/usermod.*auid>=$uid_min" || grep -q "/usr/sbin/usermod.*auid>=$uid_min" /etc/audit/rules.d/*.rules 2>/dev/null; then
    sec_audit_report_pass 289 "usermod command usage is audited"
    else
        sec_audit_report_fail 289 "usermod command usage is not audited"
    fi

    # RULE290:
    if sec_audit_audit_rule_loaded_and_on_disk -q "init_module"; then
    sec_audit_report_pass 290 "init_module auditing on disk and loaded"
    else
    sec_audit_report_fail 290 "kernel module loading unloading and modification is not collected"
    fi

    # RULE291:
    if sec_audit_audit_rule_loaded_and_on_disk -E -q 'init_module|finit_module'; then
    sec_audit_report_pass 291 "init_module/finit_module calls are audited"
    else
    sec_audit_report_fail 291 "init_module/finit_module calls are not audited"
    fi

    uid_min=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs 2>/dev/null || echo "1000")

    # RULE292:
    if auditctl -l 2>/dev/null | grep -q "delete_module.*auid>=$uid_min" || grep -q "delete_module.*auid>=$uid_min" /etc/audit/rules.d/*.rules 2>/dev/null; then
    sec_audit_report_pass 292 "delete_module calls are audited"
    else
        sec_audit_report_fail 292 "delete_module calls are not audited"
    fi

    uid_min=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs 2>/dev/null || echo "1000")

    # RULE293:
    if auditctl -l 2>/dev/null | grep -q "query_module.*auid>=$uid_min" || grep -q "query_module.*auid>=$uid_min" /etc/audit/rules.d/*.rules 2>/dev/null; then
    sec_audit_report_pass 293 "query_module calls are audited"
    else
        sec_audit_report_fail 293 "query_module calls are not audited"
    fi

    # RULE294:
    if grep -q "^\s*-c" /etc/audit/rules.d/*.rules 2>/dev/null; then
    sec_audit_report_pass 294 "audit rules will continue loading on errors"
    else
    sec_audit_report_fail 294 "audit rules may stop loading on errors"
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
    if augenrules --check 2>/dev/null | grep -q "No change"; then
    sec_audit_report_pass 296 "the running and on disk configuration is the same"
    else
    sec_audit_report_fail 296 "Loaded audit rules differ from on-disk rules (augenrules --check)"
    fi

    # RULE297:
    if [ -f /etc/audit/auditd.conf ]; then
    LOG_DIR=$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")
    if [ -d "$LOG_DIR" ]; then
        if stat -Lc '%a' "$LOG_DIR" 2>/dev/null | grep -qE '^750$'; then
            sec_audit_report_pass 297 "the audit log file directory mode is configured"
        else
            sec_audit_report_fail 297 "Audit log directory mode is not 750 or directory missing"
        fi
    else
        sec_audit_report_fail 297 "Audit log directory mode is not 750 or directory missing"
    fi
    else
    sec_audit_report_fail 297 "Audit log directory mode is not 750 or directory missing"
    fi

    # RULE298:
    if [ -f /etc/audit/auditd.conf ]; then
    LOG_DIR=$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")
    if [ -d "$LOG_DIR" ]; then
        if sec_audit_soft_find --timeout=10 "$LOG_DIR" -xdev -ignore_readdir_race -maxdepth 1 -type f -perm /0137 2>/dev/null | grep -q '.'; then
            sec_audit_report_fail 298 "One or more audit log files have overly permissive modes"
        else
            sec_audit_report_pass 298 "audit log files mode is configured"
        fi
    else
        sec_audit_report_fail 298 "One or more audit log files have overly permissive modes"
    fi
    else
    sec_audit_report_fail 298 "One or more audit log files have overly permissive modes"
    fi

    # RULE299:
    if [ -f /etc/audit/auditd.conf ]; then
    LOG_DIR=$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")
    if [ -d "$LOG_DIR" ]; then
        if sec_audit_soft_find --timeout=10 "$LOG_DIR" -xdev -ignore_readdir_race -maxdepth 1 -type f ! -user root 2>/dev/null | grep -q '.'; then
            sec_audit_report_fail 299 "One or more audit log files are not owned by root"
        else
            sec_audit_report_pass 299 "audit log files owner is configured"
        fi
    else
        sec_audit_report_fail 299 "One or more audit log files are not owned by root"
    fi
    else
    sec_audit_report_fail 299 "One or more audit log files are not owned by root"
    fi

    # RULE300:
    if [ -f /etc/audit/auditd.conf ]; then
    LOG_DIR=$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")
    LOG_GROUP=$(awk -F= '/^\s*log_group\s*/{print $2}' /etc/audit/auditd.conf | xargs)
    if [ "$LOG_GROUP" = "root" ] || [ "$LOG_GROUP" = "adm" ]; then
        if [ -d "$LOG_DIR" ]; then
            if sec_audit_soft_find --timeout=10 "$LOG_DIR" -xdev -ignore_readdir_race -maxdepth 1 -type f \( ! -group root -a ! -group adm \) 2>/dev/null | grep -q '.'; then
                sec_audit_report_fail 300 "Audit log files group ownership does not match log_group policy"
            else
                sec_audit_report_pass 300 "audit log files group owner is configured"
            fi
        else
            sec_audit_report_fail 300 "Audit log files group ownership does not match log_group policy"
        fi
    else
        sec_audit_report_fail 300 "Audit log files group ownership does not match log_group policy"
    fi
    else
    sec_audit_report_fail 300 "Audit log files group ownership does not match log_group policy"
    fi

    # RULE301:
    if sec_audit_soft_find --timeout=10 /etc/audit/ -xdev -ignore_readdir_race -type f \( -name "*.conf" -o -name '*.rules' \) -perm /0137 2>/dev/null | grep -q '.'; then
    sec_audit_report_fail 301 "Audit .conf/.rules files have insecure permissions"
    else
    sec_audit_report_pass 301 "audit configuration files mode is configured"
    fi

    # RULE302:
    if sec_audit_soft_find --timeout=10 /etc/audit/ -xdev -ignore_readdir_race -type f \( -name "*.conf" -o -name '*.rules' \) ! -user root 2>/dev/null | grep -q '.'; then
    sec_audit_report_fail 302 "Audit configuration files are not owned as required"
    else
    sec_audit_report_pass 302 "audit configuration files owner is configured"
    fi

    # RULE303:
    if sec_audit_soft_find --timeout=10 /etc/audit/ -xdev -ignore_readdir_race -type f \( -name "*.conf" -o -name '*.rules' \) ! -group root 2>/dev/null | grep -q '.'; then
    sec_audit_report_fail 303 "Audit configuration files group ownership does not meet policy"
    else
    sec_audit_report_pass 303 "audit configuration files group owner is configured"
    fi

    # RULE304:
    FAIL254=0
    for tool in /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules; do
    if [ -f "$tool" ]; then
        if [ $(( $(stat -Lc '%#a' "$tool" 2>/dev/null) & 0022 )) -gt 0 ]; then
            FAIL254=1
        fi
    fi
    done
    if [ $FAIL254 -eq 0 ]; then
    sec_audit_report_pass 304 "audit tools mode is configured"
    else
    sec_audit_report_fail 304 "One or more /sbin/audit* tools have insecure permissions"
    fi

    # RULE305:
    FAIL255=0
    for tool in /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules; do
    if [ -f "$tool" ]; then
        if [ "$(stat -Lc '%U' "$tool" 2>/dev/null)" != "root" ]; then
            FAIL255=1
        fi
    fi
    done
    if [ $FAIL255 -eq 0 ]; then
    sec_audit_report_pass 305 "audit tools owner is configured"
    else
    sec_audit_report_fail 305 "One or more /sbin/audit* tools are not owned by root"
    fi

    # RULE306:
    FAIL256=0
    for tool in /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules; do
    if [ -f "$tool" ]; then
        if [ "$(stat -Lc '%G' "$tool" 2>/dev/null)" != "root" ]; then
            FAIL256=1
        fi
    fi
    done
    if [ $FAIL256 -eq 0 ]; then
    sec_audit_report_pass 306 "audit tools group owner is configured"
    else
    sec_audit_report_fail 306 "One or more /sbin/audit* tools have incorrect group ownership"
    fi

}

sec_audit_run_identity_files() {
    # RULE307:
    if stat -Lc '%a' /etc/passwd 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' /etc/passwd 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 307 "access to /etc/passwd is configured"
    else
        sec_audit_report_fail 307 "File /etc/passwd permissions or ownership not correct"
    fi
    else
    sec_audit_report_fail 307 "File /etc/passwd permissions or ownership not correct"
    fi

    # RULE308:
    if [ -e /etc/passwd- ]; then
    if stat -Lc '%a' /etc/passwd- 2>/dev/null | grep -qE '^[0-6]44$'; then
        if stat -Lc '%U:%G' /etc/passwd- 2>/dev/null | grep -q '^root:root$'; then
            sec_audit_report_pass 308 "access to /etc/passwd- is configured"
        else
            sec_audit_report_fail 308 "File /etc/passwd- permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 308 "File /etc/passwd- permissions or ownership not correct"
    fi
    else
    sec_audit_report_pass 308 "/etc/passwd- is absent (optional file; permission check skipped)"
    fi

    # RULE309:
    if stat -Lc '%a' /etc/group 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' /etc/group 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 309 "access to /etc/group is configured"
    else
        sec_audit_report_fail 309 "File /etc/group permissions or ownership not correct"
    fi
    else
    sec_audit_report_fail 309 "File /etc/group permissions or ownership not correct"
    fi

    # RULE310:
    if [ -e /etc/group- ]; then
    if stat -Lc '%a' /etc/group- 2>/dev/null | grep -qE '^[0-6]44$'; then
        if stat -Lc '%U:%G' /etc/group- 2>/dev/null | grep -q '^root:root$'; then
            sec_audit_report_pass 310 "access to /etc/group- is configured"
        else
            sec_audit_report_fail 310 "File /etc/group- permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 310 "File /etc/group- permissions or ownership not correct"
    fi
    else
    sec_audit_report_pass 310 "/etc/group- is absent (optional file; permission check skipped)"
    fi

    # RULE311:
    if stat -Lc '%a' /etc/shadow 2>/dev/null | grep -qE '^[0-6]40$'; then
    if stat -Lc '%U' /etc/shadow 2>/dev/null | grep -q 'root'; then
        if stat -Lc '%G' /etc/shadow 2>/dev/null | grep -qE 'root|shadow'; then
            sec_audit_report_pass 311 "access to /etc/shadow is configured"
        else
            sec_audit_report_fail 311 "File /etc/shadow permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 311 "File /etc/shadow permissions or ownership not correct"
    fi
    else
    sec_audit_report_fail 311 "File /etc/shadow permissions or ownership not correct"
    fi

    # RULE312:
    if [ -e /etc/shadow- ]; then
    if stat -Lc '%a' /etc/shadow- 2>/dev/null | grep -qE '^[0-6]40$'; then
        if stat -Lc '%U' /etc/shadow- 2>/dev/null | grep -q 'root'; then
            if stat -Lc '%G' /etc/shadow- 2>/dev/null | grep -qE 'root|shadow'; then
                sec_audit_report_pass 312 "access to /etc/shadow- is configured"
            else
                sec_audit_report_fail 312 "File /etc/shadow- permissions or ownership not correct"
            fi
        else
            sec_audit_report_fail 312 "File /etc/shadow- permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 312 "File /etc/shadow- permissions or ownership not correct"
    fi
    else
    sec_audit_report_pass 312 "/etc/shadow- is absent (optional file; permission check skipped)"
    fi

    # RULE313:
    if [ -e /etc/gshadow ]; then
    if stat -Lc '%a' /etc/gshadow 2>/dev/null | grep -qE '^[0-6]40$'; then
        if stat -Lc '%U' /etc/gshadow 2>/dev/null | grep -q 'root'; then
            if stat -Lc '%G' /etc/gshadow 2>/dev/null | grep -qE 'root|shadow'; then
                sec_audit_report_pass 313 "access to /etc/gshadow is configured"
            else
                sec_audit_report_fail 313 "File /etc/gshadow permissions or ownership not correct"
            fi
        else
            sec_audit_report_fail 313 "File /etc/gshadow permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 313 "File /etc/gshadow permissions or ownership not correct"
    fi
    else
    sec_audit_report_pass 313 "/etc/gshadow is absent (optional file; permission check skipped)"
    fi

    # RULE314:
    if [ -e /etc/gshadow- ]; then
    if stat -Lc '%a' /etc/gshadow- 2>/dev/null | grep -qE '^[0-6]40$'; then
        if stat -Lc '%U' /etc/gshadow- 2>/dev/null | grep -q 'root'; then
            if stat -Lc '%G' /etc/gshadow- 2>/dev/null | grep -qE 'root|shadow'; then
                sec_audit_report_pass 314 "access to /etc/gshadow- is configured"
            else
                sec_audit_report_fail 314 "File /etc/gshadow- permissions or ownership not correct"
            fi
        else
            sec_audit_report_fail 314 "File /etc/gshadow- permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 314 "File /etc/gshadow- permissions or ownership not correct"
    fi
    else
    sec_audit_report_pass 314 "/etc/gshadow- is absent (optional file; permission check skipped)"
    fi

    # RULE315:
    if stat -Lc '%a' /etc/shells 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' /etc/shells 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 315 "access to /etc/shells is configured"
    else
        sec_audit_report_fail 315 "File /etc/shells permissions or ownership not correct"
    fi
    else
    sec_audit_report_fail 315 "File /etc/shells permissions or ownership not correct"
    fi

    # RULE316:
    if [ -e /etc/security/opasswd ]; then
    if stat -Lc '%a' /etc/security/opasswd 2>/dev/null | grep -q '^600$'; then
        if stat -Lc '%U:%G' /etc/security/opasswd 2>/dev/null | grep -q '^root:root$'; then
            sec_audit_report_pass 316 "access to /etc/security/opasswd is configured"
        else
            sec_audit_report_fail 316 "File /etc/security/opasswd permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 316 "File /etc/security/opasswd permissions or ownership not correct"
    fi
    else
    sec_audit_report_pass 316 "/etc/security/opasswd is absent (optional file; permission check skipped)"
    fi

}

sec_audit_run_filesystem_integrity() {
    # RULE317:
    CRITICAL_PATHS="/bin /sbin /usr/bin /usr/sbin /etc /var /home"
    if sec_audit_soft_find_timed_out sec_audit_soft_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type f -perm -0002 -print; then
    sec_audit_report_fail 317 "incomplete_scan: world-writable file search timed out under critical paths"
    elif sec_audit_soft_find_timed_out sec_audit_soft_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type d -perm -0002 -print; then
    sec_audit_report_fail 317 "incomplete_scan: world-writable directory search timed out under critical paths"
    else
    WW_FILES=$(sec_audit_soft_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type f -perm -0002 -print 2>/dev/null | wc -l)
    WW_DIRS=$(sec_audit_soft_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type d -perm -0002 -print 2>/dev/null | wc -l)
    if [ "${WW_FILES:-0}" -eq 0 ] && [ "${WW_DIRS:-0}" -eq 0 ]; then
        sec_audit_report_pass 317 "No critical world writable files or directories found"
    else
        sec_audit_report_fail 317 "Found potential world-writable items ($WW_FILES files, $WW_DIRS dirs)"
    fi
    fi

    # RULE318:
    orphan_fail=0
    while IFS= read -r mount_point; do
    [ -d "$mount_point" ] || continue
    if sec_audit_soft_find --timeout=120 "$mount_point" -xdev -ignore_readdir_race \( -nouser -o -nogroup \) -print -quit 2>/dev/null | grep -q .; then
        orphan_fail=1
        break
    fi
    done <<< "$(sec_audit_safe_find_roots)"
    if [ "${orphan_fail:-0}" -eq 0 ]; then
    sec_audit_report_pass 318 "No files or directories without owner or group found"
    else
    sec_audit_report_fail 318 "Files or directories without owner or group exist"
    fi

    # RULE319:
    SPECIAL_COUNTS=$(
    while IFS= read -r mount_point; do
        [ -d "$mount_point" ] || continue
        sec_audit_soft_find --timeout=120 "$mount_point" -xdev -ignore_readdir_race -type f -perm /6000 -printf '%m\n' 2>/dev/null
    done <<< "$(sec_audit_safe_find_roots)" | awk '
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
    sec_audit_report_skip 319 "SUID and SGID files found ($SUID_FILES SUID, $SGID_FILES SGID). Please review manually."
    else
    sec_audit_report_pass 319 "No SUID or SGID files found"
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
    FAIL271=0
    while IFS=: read -r user pass uid gid rest; do
    if ! grep -q "^.*:.*:$gid:" /etc/group 2>/dev/null; then
        sec_audit_report_fail 322 "User $user has primary group GID $gid which does not exist in /etc/group"
        FAIL271=1
    fi
    done < /etc/passwd 2>/dev/null
    [ $FAIL271 -eq 0 ] && sec_audit_report_pass 322 "All groups in /etc/passwd exist in /etc/group"

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
    home_fail=0
    valid_shells="^($(awk -F/ '$NF != "nologin" {print}' /etc/shells 2>/dev/null | sed -r 's|/|\\/|g' | paste -sd '|' -))$"
    while IFS=: read -r user home; do
    [[ -n "$user" && -n "$home" && "$user" != root ]] || continue
    if [ ! -d "$home" ]; then
        home_fail=1
    elif [ "$(stat -c '%U' "$home" 2>/dev/null)" != "$user" ] || [ "$(stat -c '%a' "$home" 2>/dev/null)" -gt 750 ] 2>/dev/null; then
        home_fail=1
    fi
    done < <(awk -v pat="$valid_shells" -F: '$(NF) ~ pat {print $1 " " $(NF-1)}' /etc/passwd 2>/dev/null)
    if [ "${home_fail:-0}" -eq 0 ]; then
    sec_audit_report_pass 327 "Local interactive user home directories are configured"
    else
    sec_audit_report_fail 327 "Some local interactive user home directories have issues"
    fi

    # RULE328:
    FAIL276=0
    while IFS=: read -r user pass uid gid rest; do
    if [ "$uid" -ge 1000 ] 2>/dev/null && [ "$uid" -lt 65534 ]; then
        home=$(echo "$rest" | cut -d: -f1)
        for dotfile in "$home/.bashrc" "$home/.bash_profile" "$home/.profile" "$home/.bash_logout"; do
            if [ -f "$dotfile" ]; then
                perm=$(stat -c '%a' "$dotfile" 2>/dev/null)
                if [ "${perm:2:1}" -gt 0 ] 2>/dev/null || [ "${perm:1:1}" -gt 0 ] 2>/dev/null; then
                    sec_audit_report_fail 328 "User $user dot file $dotfile has world/group write permissions ($perm)"
                    FAIL276=1
                fi
            fi
        done
    fi
    done < /etc/passwd 2>/dev/null
    [ $FAIL276 -eq 0 ] && sec_audit_report_pass 328 "Local interactive user dot files access is configured"

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
    sec_audit_run_unused_services
    sec_audit_run_client_tools
    sec_audit_run_chrony
    sec_audit_run_cron_at
    sec_audit_run_network_stack
    sec_audit_run_firewalld
    sec_audit_run_sshd
    sec_audit_run_sudo_su
    sec_audit_run_pam_auth
    sec_audit_run_accounts
    sec_audit_run_aide
    sec_audit_run_logging
    sec_audit_run_auditd
    sec_audit_run_identity_files
    sec_audit_run_filesystem_integrity
    exit 0
}

sec_audit_main "$@"
