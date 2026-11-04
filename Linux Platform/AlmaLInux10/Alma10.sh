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

AL10_FIND_CAP="${AL10_FIND_CAP:-20}"
AL10_CMD_CAP="${AL10_CMD_CAP:-12}"
AL10_DNF_CAP="${AL10_DNF_CAP:-30}"
AL10_ALLOW_CONTAINER_KMOD="${AL10_ALLOW_CONTAINER_KMOD:-${ALMA_CRE_ALLOW_CONTAINER_MODULES:-0}}"

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

# =============================================================================
# Rule section runners (RULE1 .. RULE276)
# =============================================================================

sec_audit_run_kernel_modules() {
    # RULE1-10 kernel filesystem / bus modules
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
}

sec_audit_run_filesystem_partitions() {
    sec_audit_assert_isolated_mount 11 /tmp "/tmp is tmpfs or a separate partition" tmp
    sec_audit_assert_mount_option 12 /tmp nodev
    sec_audit_assert_mount_option 13 /tmp nosuid
    sec_audit_assert_mount_option 14 /tmp noexec
    sec_audit_assert_isolated_mount 15 /dev/shm "/dev/shm is tmpfs or a separate partition" shm
    sec_audit_assert_mount_option 16 /dev/shm nodev
    sec_audit_assert_mount_option 17 /dev/shm nosuid
    sec_audit_assert_mount_option 18 /dev/shm noexec
    sec_audit_assert_isolated_mount 19 /home "separate partition exists for /home"
    sec_audit_assert_mount_option 20 /home nodev
    sec_audit_assert_mount_option 21 /home nosuid
    sec_audit_assert_isolated_mount 22 /var "separate partition exists for /var"
    sec_audit_assert_mount_option 23 /var nodev
    sec_audit_assert_mount_option 24 /var nosuid
    sec_audit_assert_isolated_mount 25 /var/tmp "separate partition exists for /var/tmp"
    sec_audit_assert_mount_option 26 /var/tmp nodev
    sec_audit_assert_mount_option 27 /var/tmp nosuid
    sec_audit_assert_mount_option 28 /var/tmp noexec
    sec_audit_assert_isolated_mount 29 /var/log "separate partition exists for /var/log"
    sec_audit_assert_mount_option 30 /var/log nodev
    sec_audit_assert_mount_option 31 /var/log nosuid
    sec_audit_assert_mount_option 32 /var/log noexec
    sec_audit_assert_isolated_mount 33 /var/log/audit "separate partition exists for /var/log/audit"
    sec_audit_assert_mount_option 34 /var/log/audit nodev
    sec_audit_assert_mount_option 35 /var/log/audit nosuid
    sec_audit_assert_mount_option 36 /var/log/audit noexec
}

sec_audit_run_package_security() {
    # RULE37 GPG keys
    _gpg_n=$(sec_audit_rpm_gpg_pubkey_count)
    _gpg_sample=""
    _gpg_alma=""
    if sec_audit_have_bin rpm && [ "${_gpg_n:-0}" -gt 0 ]; then
        _gpg_sample=$(rpm -qa 'gpg-pubkey*' --qf '%{VERSION}\n' 2>/dev/null | awk 'NF && NR<=6 { s=(s?s ",":s) $1 } END { print s }')
        if rpm -qa 'gpg-pubkey*' --qf '%{SUMMARY}\n' 2>/dev/null | grep -qi 'almalinux'; then
            _gpg_alma="; AlmaLinux signing key summary present"
        fi
    fi
    if ! sec_audit_have_bin rpm; then
        sec_audit_report_fail 37 "rpm not available; cannot verify gpg-pubkey packages in the RPM database"
    elif [ "${_gpg_n:-0}" -eq 0 ]; then
        sec_audit_report_fail 37 "no gpg-pubkey packages in the RPM database (import distribution or repository signing keys)"
    else
        sec_audit_report_pass 37 "${_gpg_n} gpg-pubkey package(s) in RPM DB (sample VERSION ids: ${_gpg_sample:-n/a})${_gpg_alma}"
    fi

    # RULE38 gpgcheck
    _gc_main=$(sec_audit_dnf_main_option gpgcheck)
    _gc_repo=$(sec_audit_list_repos_gpgcheck_disabled | head -n1)
    if sec_audit_truthy_false "$_gc_main"; then
        sec_audit_report_fail 38 "merged [main] gpgcheck is disabled (effective value: ${_gc_main})"
    elif [ -n "$_gc_repo" ]; then
        sec_audit_report_fail 38 "enabled repository section explicitly sets gpgcheck=0 (${_gc_repo//|/ -> })"
    else
        sec_audit_report_pass 38 "[main] gpgcheck is not false and no enabled .repo section forces gpgcheck=0"
    fi

    # RULE39 repo_gpgcheck
    _rgc_main=$(sec_audit_dnf_main_option repo_gpgcheck)
    _rgc_repo=$(sec_audit_list_repos_repogpg_disabled | head -n1)
    if sec_audit_truthy_false "$_rgc_main"; then
        sec_audit_report_fail 39 "merged [main] repo_gpgcheck is disabled (effective value: ${_rgc_main})"
    elif [ -z "$_rgc_main" ]; then
        sec_audit_report_fail 39 "repo_gpgcheck not explicitly enabled in merged [main] (dnf defaults to false when unset)"
    elif ! sec_audit_truthy_true "$_rgc_main"; then
        sec_audit_report_fail 39 "repo_gpgcheck in [main] is not a true value (expected 1/true/yes/on; got: ${_rgc_main})"
    elif [ -n "$_rgc_repo" ]; then
        sec_audit_report_fail 39 "enabled repository section explicitly sets repo_gpgcheck=0 (${_rgc_repo//|/ -> })"
    else
        sec_audit_report_pass 39 "repo_gpgcheck enabled in [main] and no enabled .repo section forces repo_gpgcheck=0"
    fi

    # RULE40 repositories
    _dnf_n=$(sec_audit_dnf_enabled_repo_count)
    if [ ! -d /etc/yum.repos.d ]; then
        sec_audit_report_fail 40 "/etc/yum.repos.d is missing"
    else
        _nrepo=0
        shopt -s nullglob
        for _rf in /etc/yum.repos.d/*.repo; do
            [ -f "$_rf" ] && _nrepo=$((_nrepo + 1))
        done
        shopt -u nullglob
        if [ "${_nrepo:-0}" -eq 0 ]; then
            sec_audit_report_fail 40 "no .repo files under /etc/yum.repos.d"
        elif ! sec_audit_enabled_repo_defines_uri; then
            sec_audit_report_fail 40 "no enabled repository section defines a non-empty baseurl, mirrorlist, or metalink"
        elif sec_audit_have_bin dnf && [ "${_dnf_n:-0}" -eq 0 ]; then
            sec_audit_report_fail 40 ".repo files define URIs but dnf repolist enabled reports 0 repos (metadata, plugin, or config error)"
        elif sec_audit_have_bin dnf && [ "${_dnf_n:-0}" -gt 0 ]; then
            sec_audit_report_pass 40 "${_nrepo} .repo file(s); dnf reports ${_dnf_n} enabled repo(s); enabled sections include package URIs"
        else
            sec_audit_report_pass 40 "${_nrepo} .repo file(s); enabled sections include baseurl/mirrorlist/metalink (dnf not used for count)"
        fi
    fi

    # RULE41 weak deps
    _iwd=$(sec_audit_dnf_main_option install_weak_deps)
    if sec_audit_truthy_false "$_iwd"; then
        sec_audit_report_pass 41 "install_weak_deps is false in merged [main]"
    elif [ -z "$_iwd" ]; then
        sec_audit_report_fail 41 "install_weak_deps not set to 0/false/no/off in [main] (dnf default enables weak dependencies)"
    else
        sec_audit_report_fail 41 "install_weak_deps is not false in merged [main] (effective: ${_iwd})"
    fi
}

sec_audit_run_selinux() {
    # RULE42-48 SELinux
    if sec_audit_rpm_any_installed libselinux; then
        _sel_extra=""
        sec_audit_rpm_any_installed selinux-policy-targeted && _sel_extra="; selinux-policy-targeted installed"
        sec_audit_report_pass 42 "SELinux is installed (libselinux)${_sel_extra}"
    else
        sec_audit_report_fail 42 "SELinux stack (libselinux) is not installed"
    fi

    if grep -Pq '(selinux|enforcing)=0\b' /proc/cmdline 2>/dev/null; then
        sec_audit_report_fail 43 "SELinux is disabled via kernel command line (/proc/cmdline)"
    elif grep -Prsq '^\h*([^#\n\r]+\h+)?kernelopts=([^#\n\r]+\h+)?(selinux|enforcing)=0\b' /boot/grub2 /boot/efi 2>/dev/null; then
        sec_audit_report_fail 43 "SELinux is disabled via bootloader configuration"
    else
        sec_audit_report_pass 43 "SELinux is not disabled in bootloader configuration"
    fi

    if grep -Psiq '^\h*SELINUXTYPE\h*=\h*(targeted|mls)\b' /etc/selinux/config 2>/dev/null; then
        _pol=$(awk -F= '/^[[:space:]]*SELINUXTYPE=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' /etc/selinux/config)
        sec_audit_report_pass 44 "SELinux policy is configured (SELINUXTYPE=${_pol})"
    else
        sec_audit_report_fail 44 "SELinux policy type is not set to targeted or mls in /etc/selinux/config"
    fi

    _ge=$(getenforce 2>/dev/null || true)
    _sel_cfg=$(awk -F= '/^[[:space:]]*SELINUX=/{gsub(/[[:space:]]/,"",$2); print tolower($2); exit}' /etc/selinux/config 2>/dev/null)
    if [[ "$_sel_cfg" == "disabled" ]]; then
        sec_audit_report_fail 45 "SELinux is disabled in /etc/selinux/config"
    elif [[ "$_ge" == "Disabled" ]]; then
        sec_audit_report_fail 45 "getenforce reports Disabled"
    elif [[ "$_ge" == "Permissive" ]]; then
        sec_audit_report_fail 45 "SELinux is permissive (CRE default requires enforcing)"
    elif [[ "$_ge" == "Enforcing" ]]; then
        sec_audit_report_pass 45 "the SELinux mode is not disabled (enforcing)"
    else
        sec_audit_report_fail 45 "SELinux mode is not in an acceptable state (config=${_sel_cfg:-unset}, getenforce=${_ge:-unknown})"
    fi

    if [[ "$_ge" != "Enforcing" ]]; then
        sec_audit_report_fail 46 "getenforce is '${_ge:-unknown}', expected Enforcing"
    elif [[ "$_sel_cfg" != "enforcing" ]]; then
        sec_audit_report_fail 46 "runtime Enforcing but /etc/selinux/config SELINUX=${_sel_cfg:-unset} (will revert after reboot)"
    else
        sec_audit_report_pass 46 "the SELinux mode is enforcing (runtime and config)"
    fi

    _unc=$(ps -eZ 2>/dev/null | awk '/unconfined_service_t/ {c++} END {print c+0}')
    if [ "${_unc:-0}" -gt 0 ]; then
        sec_audit_report_fail 47 "Processes running with unconfined_service_t were detected (${_unc})"
    else
        sec_audit_report_pass 47 "no unconfined services exist"
    fi

    if sec_audit_rpm_any_installed setroubleshoot; then
        sec_audit_report_fail 48 "SETroubleshoot package is installed"
    else
        sec_audit_report_pass 48 "SETroubleshoot is not installed"
    fi
}

sec_audit_run_bootloader() {
    # RULE49-50 bootloader
    if sec_audit_grub_cfg_matches '^[[:space:]]*set superusers' && sec_audit_grub_cfg_matches 'password_pbkdf2'; then
        sec_audit_report_pass 49 "bootloader password is set (grub.cfg under /boot/grub2 or EFI)"
    else
        sec_audit_report_fail 49 "GRUB bootloader superuser/password_pbkdf2 is not configured as required in grub.cfg"
    fi

    _grub_ok=0
    while IFS= read -r _gcfg; do
        [[ -f "$_gcfg" ]] || continue
        if sec_audit_mode_within_max "$_gcfg" 600 && sec_audit_path_owned_by "$_gcfg" "root:root"; then
            _grub_ok=1
            break
        fi
    done <<< "$(sec_audit_list_grub_cfg_paths)"
    if [ "$_grub_ok" -eq 1 ]; then
        sec_audit_report_pass 50 "access to bootloader config is configured"
    else
        sec_audit_report_fail 50 "/boot/grub2/grub.cfg (or EFI grub.cfg) owner/mode is not root:root with mode 600 or stricter"
    fi
}

sec_audit_run_process_hardening() {
    # RULE51 core dumps
    if sec_audit_core_dumps_limited; then
        sec_audit_report_pass 51 "limits * hard core 0 present and systemd DefaultLimitCORE does not allow unlimited core dumps"
    elif grep -Psiq '^\*\s+hard\s+core\s+0\b' /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null; then
        sec_audit_report_fail 51 "limits.conf sets hard core 0 but systemd DefaultLimitCORE contradicts"
    else
        sec_audit_report_fail 51 "core file size limits are not configured (limits * hard core 0 not found)"
    fi

    sec_audit_assert_sysctl_equals 52 fs.protected_hardlinks 1
    sec_audit_assert_sysctl_equals 53 fs.protected_symlinks 1
    sec_audit_assert_sysctl_equals 54 fs.suid_dumpable 0
    sec_audit_assert_sysctl_equals 55 kernel.dmesg_restrict 1
    sec_audit_assert_sysctl_equals 56 kernel.kptr_restrict 2
    sec_audit_assert_sysctl_equals 57 kernel.yama.ptrace_scope 1
    sec_audit_assert_sysctl_equals 58 kernel.randomize_va_space 2

    _cd_cat=$(systemd-analyze cat-config systemd/coredump.conf 2>/dev/null)
    _corep=$(sec_audit_sysctl_runtime kernel.core_pattern)
    if printf '%s\n' "$_cd_cat" | grep -Pq '^\h*ProcessSizeMax=\h*0\b'; then
        if [[ "$_corep" == *systemd-coredump* ]] || [[ "$_corep" == *coredump* ]]; then
            sec_audit_report_pass 59 "merged coredump.conf sets ProcessSizeMax=0; kernel.core_pattern uses systemd-coredump"
        else
            sec_audit_report_pass 59 "merged coredump.conf sets ProcessSizeMax=0 (kernel.core_pattern='${_corep:-?}')"
        fi
    else
        sec_audit_report_fail 59 "merged systemd/coredump.conf does not set ProcessSizeMax=0"
    fi

    if printf '%s\n' "$_cd_cat" | grep -Pq '^\h*Storage=\h*none\b'; then
        sec_audit_report_pass 60 "merged systemd/coredump.conf sets Storage=none"
    else
        sec_audit_report_fail 60 "merged systemd/coredump.conf does not set Storage=none"
    fi
}

sec_audit_run_crypto_policy() {
    # RULE61-63 crypto policy
    _cp_show=""
    sec_audit_have_bin update-crypto-policies && _cp_show=$(update-crypto-policies --show 2>/dev/null)
    _cp_cfg=""
    [[ -f /etc/crypto-policies/config ]] && _cp_cfg=$(tr -d '[:space:]' </etc/crypto-policies/config 2>/dev/null)
    if { [[ -f /etc/crypto-policies/config ]] && grep -Piq '^\h*LEGACY\b' /etc/crypto-policies/config 2>/dev/null; } || [[ "$(sec_audit_to_lower "$_cp_show")" == "legacy" ]]; then
        sec_audit_report_fail 61 "System-wide crypto policy is LEGACY (config=${_cp_cfg:-?}, show=${_cp_show:-?})"
    else
        sec_audit_report_pass 61 "system wide crypto policy is not set to legacy (config=${_cp_cfg:-unset}, show=${_cp_show:-n/a})"
    fi

    if [[ -f /etc/crypto-policies/state/CURRENT.pol ]] && grep -Piq '(^\h*mac\h*=\h*([^#\n\r]+)?-128|hmac-sha1)' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null; then
        sec_audit_report_fail 62 "Weak MAC algorithms still present in /etc/crypto-policies/state/CURRENT.pol"
    else
        sec_audit_report_pass 62 "system wide crypto policy macs are configured"
    fi

    if grep -Piq '^\h*cipher@(lib|open)ssh(-server|-client)?\h*=\h*([^#\n\r]+)?-CBC\b' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null \
        || grep -Piq '^\h*cipher\h*=\h*([^#\n\r]+)?-CBC\b' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null; then
        sec_audit_report_fail 63 "CBC ciphers remain enabled for SSH in crypto policy (CURRENT.pol)"
    else
        sec_audit_report_pass 63 "system-wide crypto policy does not enable CBC ciphers for SSH"
    fi
}

sec_audit_run_banners() {
    # RULE64-69 banners
    if sec_audit_banner_exposes_os /etc/motd; then
        sec_audit_report_fail 64 "/etc/motd contains OS-disclosing tokens (\\v/\\r/\\m/\\s or os-release ID)"
    elif [[ -f /etc/motd ]]; then
        sec_audit_report_pass 64 "/etc/motd is configured (no OS-disclosing tokens)"
    else
        sec_audit_report_pass 64 "/etc/motd is configured (file absent)"
    fi

    if sec_audit_banner_exposes_os /etc/issue; then
        sec_audit_report_fail 65 "/etc/issue contains OS-disclosing tokens"
    elif [[ -f /etc/issue ]]; then
        sec_audit_report_pass 65 "/etc/issue is configured"
    else
        sec_audit_report_fail 65 "/etc/issue is missing"
    fi

    if [[ -f /etc/issue.net ]]; then
        if sec_audit_banner_exposes_os /etc/issue.net; then
            sec_audit_report_fail 66 "/etc/issue.net contains OS-disclosing tokens"
        else
            sec_audit_report_pass 66 "/etc/issue.net is configured"
        fi
    else
        sec_audit_report_pass 66 "/etc/issue.net is configured (file absent)"
    fi

    sec_audit_assert_path_access 67 /etc/motd 644 root:root "access to /etc/motd is configured" 1
    sec_audit_assert_path_access 68 /etc/issue 644 root:root "access to /etc/issue is configured" 0
    sec_audit_assert_path_access 69 /etc/issue.net 644 root:root "access to /etc/issue.net is configured" 1
}

sec_audit_run_gdm() {
    # RULE70-75 GDM (not applicable when gdm is absent)
    if ! sec_audit_gdm_installed; then
        sec_audit_report_pass 70 "GDM login banner is configured (gdm not installed)"
        sec_audit_report_pass 71 "GDM disable-user-list is configured (gdm not installed)"
        sec_audit_report_pass 72 "GDM screen lock is configured (gdm not installed)"
        sec_audit_report_pass 73 "GDM automount is configured (gdm not installed)"
        sec_audit_report_pass 74 "GDM autorun-never is configured (gdm not installed)"
        sec_audit_report_pass 75 "Xwayland is configured (gdm not installed)"
    else
        _gdm_cfg="/etc/gdm/custom.conf"
        if [[ -f $_gdm_cfg ]] && grep -Pzo "\[org/gnome/login-screen\][^\[]*banner-message-enable=true" "$_gdm_cfg" 2>/dev/null | grep -q .; then
            sec_audit_report_pass 70 "GDM login banner is configured"
        elif sec_audit_dconf_gdm_matches "banner-message-enable=true"; then
            sec_audit_report_pass 70 "GDM login banner is configured (dconf)"
        else
            sec_audit_report_fail 70 "GDM login banner is not configured in ${_gdm_cfg} or dconf"
        fi
        if grep -q "DisableUserList=true" "$_gdm_cfg" 2>/dev/null || sec_audit_dconf_gdm_matches "disable-user-list=true"; then
            sec_audit_report_pass 71 "GDM disable-user-list is configured"
        else
            sec_audit_report_fail 71 "GDM disable-user-list is not configured"
        fi
        if sec_audit_dconf_gdm_matches "idle-delay=uint32" || sec_audit_dconf_gdm_matches "lock-delay=uint32"; then
            sec_audit_report_pass 72 "GDM screen lock is configured"
        else
            sec_audit_report_fail 72 "GDM screen lock is not configured"
        fi
        if sec_audit_dconf_gdm_matches "automount=false" || sec_audit_dconf_gdm_matches "automount-open=false"; then
            sec_audit_report_pass 73 "GDM automount is configured"
        else
            sec_audit_report_fail 73 "GDM automount is not configured"
        fi
        if sec_audit_dconf_gdm_matches "autorun-never=true"; then
            sec_audit_report_pass 74 "GDM autorun-never is configured"
        else
            sec_audit_report_fail 74 "GDM autorun-never is not configured"
        fi
        if grep -Psiq '^\h*WaylandEnable=false' "$_gdm_cfg" 2>/dev/null; then
            sec_audit_report_pass 75 "Xwayland is configured (WaylandEnable=false)"
        else
            sec_audit_report_fail 75 "WaylandEnable=false is not set in GDM custom.conf"
        fi
    fi
}

sec_audit_run_unused_services() {
    # RULE76-93 unused services
    sec_audit_assert_service_unused 76 autofs "autofs services are not in use" "autofs services are installed and enabled or actively running" "autofs.service"
    sec_audit_assert_service_unused 77 avahi "avahi daemon services are not in use" "avahi daemon services are installed and enabled or actively running" "avahi-daemon.socket" "avahi-daemon.service"
    sec_audit_assert_service_unused 78 cockpit-ws "cockpit web services are not in use" "cockpit web services are installed and enabled or actively running" "cockpit.socket" "cockpit.service"
    sec_audit_assert_service_unused 79 dhcp-server "dhcp server services are not in use" "dhcp server services are installed and enabled or actively running" "dhcpd.service" "dhcpd6.service"
    sec_audit_assert_service_unused 80 bind "dns server services are not in use" "dns server services are installed and enabled or actively running" "named.service"
    sec_audit_assert_service_unused 81 dnsmasq "dnsmasq services are not in use" "dnsmasq services are installed and enabled or actively running" "dnsmasq.service"
    sec_audit_assert_service_unused 82 vsftpd "ftp server services are not in use" "ftp server services are installed and enabled or actively running" "vsftpd.service"

    if sec_audit_rpm_any_installed dovecot cyrus-imapd; then
        if sec_audit_systemd_unit_live dovecot.socket dovecot.service cyrus-imapd.service; then
            sec_audit_report_fail 83 "message access server services are installed and enabled or actively running"
        else
            sec_audit_report_pass 83 "message access server services are not in use (package present but units masked/disabled/inactive)"
        fi
    else
        sec_audit_report_pass 83 "message access server services are not in use"
    fi

    sec_audit_assert_service_unused 84 nfs-utils "network file system services are not in use" "network file system services are installed and enabled or actively running" "nfs-server.service"
    sec_audit_assert_service_unused 85 cups "print server services are not in use" "print server services are installed and enabled or actively running" "cups.socket" "cups.service"
    sec_audit_assert_service_unused 86 rpcbind "rpcbind services are not in use" "rpcbind services are installed and enabled or actively running" "rpcbind.socket" "rpcbind.service"
    sec_audit_assert_service_unused 87 rsync-daemon "rsync services are not in use" "rsync services are installed and enabled or actively running" "rsyncd.socket" "rsyncd.service"
    sec_audit_assert_service_unused 88 samba "samba file server services are not in use" "samba file server services are installed and enabled or actively running" "smb.service"
    sec_audit_assert_service_unused 89 net-snmp "snmp services are not in use" "snmp services are installed and enabled or actively running" "snmpd.service"
    sec_audit_assert_service_unused 90 telnet-server "telnet server services are not in use" "telnet server services are installed and enabled or actively running" "telnet.socket"
    sec_audit_assert_service_unused 91 tftp-server "tftp server services are not in use" "tftp server services are installed and enabled or actively running" "tftp.socket" "tftp.service"
    sec_audit_assert_service_unused 92 squid "web proxy server services are not in use" "web proxy server services are installed and enabled or actively running" "squid.service"

    if sec_audit_rpm_any_installed httpd nginx; then
        if sec_audit_systemd_unit_live httpd.service nginx.service; then
            sec_audit_report_fail 93 "web server services are installed and enabled or actively running"
        else
            sec_audit_report_pass 93 "web server services are not in use (package present but units masked/disabled/inactive)"
        fi
    else
        sec_audit_report_pass 93 "web server services are not in use"
    fi

    if sec_audit_rpm_any_installed gdm || sec_audit_systemd_unit_live gdm.service gdm.socket; then
        sec_audit_report_fail 94 "GNOME Display Manager (gdm) package is still installed or unit is live"
    else
        sec_audit_report_pass 94 "GNOME Display Manager is removed"
    fi

    if sec_audit_rpm_any_installed xorg-x11-server-Xwayland xorg-x11-server-Xorg; then
        sec_audit_report_fail 95 "X window server services are installed"
    else
        sec_audit_report_pass 95 "X window server services are not in use"
    fi
}

sec_audit_run_client_tools() {
    sec_audit_assert_package_absent 96 ftp "ftp client is not installed" "ftp client package is installed"
    sec_audit_assert_package_absent 97 openldap-clients "ldap client is not installed" "ldap client package is installed"
    sec_audit_assert_package_absent 98 telnet "telnet client is not installed" "telnet client package is installed"
    sec_audit_assert_package_absent 99 tftp "tftp client is not installed" "tftp client package is installed"
}

sec_audit_run_chrony() {
    # RULE100-102 chrony
    if sec_audit_rpm_any_installed chrony; then
        if [[ "$(sec_audit_systemd_is_active chronyd.service)" == "active" ]]; then
            sec_audit_report_pass 100 "chrony is installed and chronyd.service is active"
        else
            sec_audit_report_fail 100 "chrony is installed but chronyd.service is not active (state=$(sec_audit_systemd_is_active chronyd.service))"
        fi
    else
        sec_audit_report_fail 100 "time synchronization is not in use (chrony not installed)"
    fi

    _ch_src=$(grep -Eh '^(server|pool)[[:space:]]' /etc/chrony.conf /etc/chrony.d/*.conf 2>/dev/null | grep -cve '^[[:space:]]*$' || true)
    if [ "${_ch_src:-0}" -gt 0 ]; then
        _ch_track=""
        if sec_audit_have_bin chronyc && [[ "$(sec_audit_systemd_is_active chronyd.service)" == "active" ]]; then
            if chronyc -n tracking 2>/dev/null | grep -qiE '^(reference time|stratum|leap status)'; then
                _ch_track="; chronyc tracking responds"
            fi
            if chronyc -n sources 2>/dev/null | grep -qE '^\^[*#]'; then
                _ch_track="${_ch_track}; chronyc sources lists a selected source"
            fi
        fi
        sec_audit_report_pass 101 "chrony has ${_ch_src} server/pool line(s) in conf or chrony.d${_ch_track}"
    else
        sec_audit_report_fail 101 "chrony is not configured with time sources (no server/pool in chrony.conf or chrony.d)"
    fi

    if grep -Psiq -- '^\h*OPTIONS=\"?\h*([^#\n\r]+\h+)?-u\h+root\b' /etc/sysconfig/chronyd 2>/dev/null; then
        sec_audit_report_fail 102 "chronyd is configured to run as root (OPTIONS in /etc/sysconfig/chronyd)"
    else
        sec_audit_report_pass 102 "chrony is not run as the root user"
    fi
}

sec_audit_run_cron_at() {
    # RULE103-112 cron / at
    if [[ "$(sec_audit_systemd_is_enabled crond.service)" == "enabled" && "$(sec_audit_systemd_is_active crond.service)" == "active" ]]; then
        sec_audit_report_pass 103 "cron daemon is enabled and active"
    else
        sec_audit_report_fail 103 "crond service is not enabled or not active (enabled=$(sec_audit_systemd_is_enabled crond.service), active=$(sec_audit_systemd_is_active crond.service))"
    fi

    sec_audit_assert_path_access 104 /etc/crontab 600 root:root "access to /etc/crontab is configured" 0
    sec_audit_assert_path_access 105 /etc/cron.hourly 700 root:root "access to /etc/cron.hourly is configured" 0
    sec_audit_assert_path_access 106 /etc/cron.daily 700 root:root "access to /etc/cron.daily is configured" 0
    sec_audit_assert_path_access 107 /etc/cron.weekly 700 root:root "access to /etc/cron.weekly is configured" 0
    sec_audit_assert_path_access 108 /etc/cron.monthly 700 root:root "access to /etc/cron.monthly is configured" 0
    sec_audit_assert_path_access 109 /etc/cron.yearly 700 root:root "access to /etc/cron.yearly is configured" 0
    sec_audit_assert_path_access 110 /etc/cron.d 700 root:root "access to /etc/cron.d is configured" 0

    if [[ -e /etc/cron.deny ]]; then
        sec_audit_report_fail 111 "cron.deny exists; cron access should be allow-list based (/etc/cron.allow)"
    else
        sec_audit_assert_path_access 111 /etc/cron.allow 640 root:root "access to crontab is configured" 0 crontab
    fi

    if [[ -e /etc/at.deny ]]; then
        sec_audit_report_fail 112 "at.deny exists; at access should be allow-list based (/etc/at.allow)"
    else
        sec_audit_assert_path_access 112 /etc/at.allow 640 root:root "access to at is configured" 0 daemon
    fi
}

sec_audit_run_network_stack() {
    # RULE113 IPv6 status
    if [[ -f /proc/sys/net/ipv6/conf/all/disable_ipv6 ]]; then
        _v6=$(tr -d '[:space:]' </proc/sys/net/ipv6/conf/all/disable_ipv6)
        sec_audit_report_pass 113 "IPv6 status is identified (net.ipv6.conf.all.disable_ipv6=${_v6})"
    else
        sec_audit_report_fail 113 "IPv6 status is not identified (/proc/sys/net/ipv6/conf/all/disable_ipv6 missing)"
    fi

    # RULE114 wireless
    _wl=0
    if compgen -G "/sys/class/net/*/wireless" >/dev/null; then
        _wl=1
    fi
    if sec_audit_have_bin nmcli && nmcli -t -f TYPE,DEVICE device 2>/dev/null | grep -q '^wifi:'; then
        _wl=1
    fi
    if [ "$_wl" -eq 1 ]; then
        sec_audit_report_fail 114 "Wireless interfaces are present on this host"
    else
        sec_audit_report_pass 114 "wireless interfaces are not available"
    fi

    sec_audit_assert_service_unused 115 bluez "bluetooth services are not in use" "bluetooth services are installed and enabled or actively running" "bluetooth.service"
    sec_audit_assert_kmod_disabled 116 "atm kernel module" atm atm.ko* "atm"
    sec_audit_assert_kmod_disabled 117 "can kernel module" can can.ko* "can"
    sec_audit_assert_kmod_disabled 118 "dccp kernel module" dccp dccp.ko* "dccp"
    sec_audit_assert_kmod_disabled 119 "tipc kernel module" tipc tipc.ko* "tipc"
    sec_audit_assert_kmod_disabled 120 "rds kernel module" rds rds.ko* "rds"
    sec_audit_assert_kmod_disabled 121 "sctp kernel module" sctp sctp.ko* "sctp"

    sec_audit_assert_sysctl_equals 122 net.ipv4.ip_forward 0
    sec_audit_assert_sysctl_equals 123 net.ipv4.conf.all.forwarding 0
    sec_audit_assert_sysctl_equals 124 net.ipv4.conf.default.forwarding 0
    sec_audit_assert_sysctl_equals 125 net.ipv4.conf.all.send_redirects 0
    sec_audit_assert_sysctl_equals 126 net.ipv4.conf.default.send_redirects 0
    sec_audit_assert_sysctl_equals 127 net.ipv4.conf.all.accept_redirects 0
    sec_audit_assert_sysctl_equals 128 net.ipv4.conf.all.secure_redirects 0
    sec_audit_assert_sysctl_equals 129 net.ipv4.conf.all.rp_filter 1
    sec_audit_assert_sysctl_equals 130 net.ipv4.conf.default.rp_filter 1
    sec_audit_assert_sysctl_equals 131 net.ipv4.conf.all.log_martians 1
    sec_audit_assert_sysctl_equals 132 net.ipv4.conf.default.log_martians 1
    sec_audit_assert_sysctl_equals 133 net.ipv4.tcp_syncookies 1
    sec_audit_assert_sysctl_equals 134 net.ipv6.conf.all.forwarding 0
    sec_audit_assert_sysctl_equals 135 net.ipv6.conf.default.forwarding 0
    sec_audit_assert_sysctl_equals 136 net.ipv6.conf.all.accept_redirects 0
    sec_audit_assert_sysctl_equals 137 net.ipv6.conf.all.accept_ra 0
    sec_audit_assert_sysctl_equals 138 net.ipv6.conf.default.accept_ra 0
}

sec_audit_run_firewalld() {
    # RULE139-144 firewalld
    if sec_audit_rpm_any_installed firewalld; then
        sec_audit_report_pass 139 "firewalld is installed"
    else
        sec_audit_report_fail 139 "firewalld package is not installed"
    fi

    if grep -Psiq 'FirewallBackend\h*=\h*nftables\b' /etc/firewalld/firewalld.conf 2>/dev/null; then
        _fw_be=""
        if sec_audit_have_bin firewall-cmd && firewall-cmd --state 2>/dev/null | grep -qi running; then
            _fw_be=$(firewall-cmd --get-backend 2>/dev/null)
            if [[ "$_fw_be" == "nftables" ]]; then
                sec_audit_report_pass 140 "firewalld.conf uses nftables and runtime backend is nftables"
            else
                sec_audit_report_pass 140 "firewalld.conf uses nftables (runtime backend reports '${_fw_be:-?}')"
            fi
        else
            sec_audit_report_pass 140 "firewalld.conf uses nftables (firewalld not running; runtime backend not verified)"
        fi
    else
        sec_audit_report_fail 140 "firewalld backend is not configured (FirewallBackend=nftables missing in firewalld.conf)"
    fi

    if [[ "$(sec_audit_systemd_is_enabled firewalld.service)" == "enabled" && "$(sec_audit_systemd_is_active firewalld.service)" == "active" ]]; then
        _fw_nft=""
        if sec_audit_have_bin nft && nft list ruleset 2>/dev/null | grep -q .; then
            _fw_nft="; nftables ruleset is non-empty"
        fi
        sec_audit_report_pass 141 "firewalld.service is enabled and active${_fw_nft}"
    else
        sec_audit_report_fail 141 "firewalld.service is not enabled or not active"
    fi

    if [[ "$(sec_audit_systemd_is_active firewalld.service)" == "active" ]] && sec_audit_have_bin firewall-cmd; then
        _zone=$(firewall-cmd --get-default-zone 2>/dev/null)
        _ztarget=$(firewall-cmd --zone="$_zone" --get-target 2>/dev/null)
        _zif=$(firewall-cmd --zone="$_zone" --list-interfaces 2>/dev/null | wc -w)
        if [ "$_ztarget" = "DROP" ] || [ "$_ztarget" = "REJECT" ]; then
            sec_audit_report_pass 142 "firewalld default zone '$_zone' target is $_ztarget (${_zif:-0} interface(s) assigned)"
        else
            sec_audit_report_fail 142 "firewalld active zone target is not DROP/REJECT (current: ${_ztarget:-?})"
        fi
        if firewall-cmd --list-rich-rules 2>/dev/null | grep -Eiq 'lo|loopback|127\.0\.0\.1|interface\s*=\s*"?lo"?'; then
            sec_audit_report_pass 143 "firewalld rich rules mention loopback / lo / localhost"
        elif firewall-cmd --zone="$_zone" --query-interface=lo &>/dev/null; then
            sec_audit_report_pass 143 "firewalld loopback interface is assigned to the default zone"
        else
            sec_audit_report_fail 143 "firewalld loopback traffic is not configured"
        fi
        _svc=$(firewall-cmd --list-services 2>/dev/null | wc -w)
        _ports=$(firewall-cmd --list-ports 2>/dev/null | wc -w)
        _svc_p=$(firewall-cmd --permanent --list-services 2>/dev/null | wc -w)
        _ports_p=$(firewall-cmd --permanent --list-ports 2>/dev/null | wc -w)
        if [ "$_svc" -gt 0 ] || [ "$_ports" -gt 0 ]; then
            sec_audit_report_pass 144 "firewalld exposes $_svc service(s) and $_ports port(s) at runtime (permanent: $_svc_p / $_ports_p)"
        elif [ "$_svc_p" -gt 0 ] || [ "$_ports_p" -gt 0 ]; then
            sec_audit_report_fail 144 "permanent firewalld rules exist ($_svc_p services, $_ports_p ports) but runtime lists none — run firewall-cmd --reload"
        else
            sec_audit_report_fail 144 "firewalld services and ports are not configured"
        fi
    else
        sec_audit_report_fail 142 "firewalld is not active"
        sec_audit_report_fail 143 "firewalld is not active"
        sec_audit_report_fail 144 "firewalld is not active"
    fi
}

sec_audit_run_sshd() {
    sec_audit_assert_path_access 145 /etc/ssh/sshd_config 600 root:root "access to /etc/ssh/sshd_config is configured" 0

    if ! sec_audit_sshd_config_ready; then
        _sshd_why="unable_to_evaluate: sshd effective config unavailable"
        if ! sec_audit_have_bin sshd; then
            _sshd_why="unable_to_evaluate: openssh-server (sshd) is not installed"
        elif [[ ! -f /etc/ssh/sshd_config ]]; then
            _sshd_why="unable_to_evaluate: /etc/ssh/sshd_config is missing"
        fi
        for _sshn in 146 147 148 149 150 151 152 153 154 155 156 157 158 159 160 161 162 163 164 165 166; do
            sec_audit_report_fail "$_sshn" "$_sshd_why"
        done
    else
        _priv_fail=0
        _pub_fail=0
        _hk_n=0
        while IFS= read -r _hk; do
            [ -n "$_hk" ] || continue
            _hk_n=$((_hk_n + 1))
            if [[ ! -f $_hk ]]; then
                _priv_fail=1
            elif ! sec_audit_mode_within_max "$_hk" 600 || ! sec_audit_path_owned_by "$_hk" "root:root"; then
                _priv_fail=1
            fi
            if [[ ! -f ${_hk}.pub ]]; then
                _pub_fail=1
            elif ! sec_audit_mode_within_max "${_hk}.pub" 644 || ! sec_audit_path_owned_by "${_hk}.pub" "root:root"; then
                _pub_fail=1
            fi
        done < <(sec_audit_sshd_effective_config | awk '$1=="hostkey"{print $2}')
        if [ "$_hk_n" -eq 0 ]; then
            sec_audit_report_fail 146 "sshd -T lists no hostkey files"
            sec_audit_report_fail 147 "sshd -T lists no hostkey files"
        else
            if [ "$_priv_fail" -eq 0 ]; then
                sec_audit_report_pass 146 "access to SSH private host key files is configured (${_hk_n} key(s))"
            else
                sec_audit_report_fail 146 "SSH private host key files permissions or ownership not correct"
            fi
            if [ "$_pub_fail" -eq 0 ]; then
                sec_audit_report_pass 147 "access to SSH public host key files is configured (${_hk_n} key(s))"
            else
                sec_audit_report_fail 147 "SSH public host key files permissions or ownership not correct"
            fi
        fi

        if sec_audit_sshd_config_grep -Piq '^\h*(allow|deny)(users|groups)\h+\H+'; then
            sec_audit_report_pass 148 "sshd access is configured (Allow/Deny Users/Groups present in sshd -T)"
        else
            sec_audit_report_fail 148 "sshd access controls (AllowUsers/DenyUsers/AllowGroups/DenyGroups) are not set"
        fi

        _banner=$(sec_audit_sshd_get banner)
        if [[ -n "$_banner" && "$_banner" != "none" && "$_banner" == /* ]]; then
            sec_audit_report_pass 149 "sshd Banner is configured (${_banner})"
        else
            sec_audit_report_fail 149 "sshd Banner does not meet the required policy (see sshd -T)"
        fi

        if sec_audit_sshd_config_grep -Piq '^ciphers\h+\"?([^#\n\r]+,)?((3des|blowfish|cast128|aes(128|192|256))-cbc|arcfour(128|256)?|rijndael-cbc@lysator\.liu\.se)\b'; then
            sec_audit_report_fail 150 "sshd Ciphers allow weak or legacy algorithms (see sshd -T)"
        else
            sec_audit_report_pass 150 "sshd Ciphers are configured"
        fi

        _cai=$(sec_audit_sshd_get_int clientaliveinterval)
        _cac=$(sec_audit_sshd_get_int clientalivecountmax)
        if [[ -n "$_cai" && "$_cai" -ge 1 && -n "$_cac" && "$_cac" -ge 1 ]]; then
            sec_audit_report_pass 151 "sshd ClientAliveInterval=${_cai} and ClientAliveCountMax=${_cac}"
        else
            sec_audit_report_fail 151 "sshd ClientAliveInterval and ClientAliveCountMax are not configured as required (interval=${_cai:-?}, countmax=${_cac:-?})"
        fi

        [[ "$(sec_audit_to_lower "$(sec_audit_sshd_get disableforwarding)")" == "yes" ]] && sec_audit_report_pass 152 "sshd DisableForwarding is enabled" || sec_audit_report_fail 152 "sshd DisableForwarding is not enabled"
        [[ "$(sec_audit_to_lower "$(sec_audit_sshd_get gssapiauthentication)")" == "no" ]] && sec_audit_report_pass 153 "sshd GSSAPIAuthentication is disabled" || sec_audit_report_fail 153 "sshd GSSAPIAuthentication is not disabled"
        [[ "$(sec_audit_to_lower "$(sec_audit_sshd_get hostbasedauthentication)")" == "no" ]] && sec_audit_report_pass 154 "sshd HostbasedAuthentication is disabled" || sec_audit_report_fail 154 "sshd HostbasedAuthentication is not disabled"
        [[ "$(sec_audit_to_lower "$(sec_audit_sshd_get ignorerhosts)")" == "yes" ]] && sec_audit_report_pass 155 "sshd IgnoreRhosts is enabled" || sec_audit_report_fail 155 "sshd IgnoreRhosts is not enabled"

        if sec_audit_sshd_config_grep -Piq 'kexalgorithms\h+([^#\n\r]+,)?(diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1)\b'; then
            sec_audit_report_fail 156 "sshd KexAlgorithms includes weak SHA-1 groups"
        else
            sec_audit_report_pass 156 "sshd KexAlgorithms is configured"
        fi

        _lgt=$(sec_audit_sshd_get_int logingracetime)
        if [[ -n "$_lgt" && "$_lgt" -ge 1 && "$_lgt" -le 60 ]]; then
            sec_audit_report_pass 157 "sshd LoginGraceTime is configured (${_lgt})"
        else
            sec_audit_report_fail 157 "sshd LoginGraceTime does not meet the required policy (${_lgt:-?}, expected 1-60)"
        fi

        case "$(sec_audit_to_lower "$(sec_audit_sshd_get loglevel)")" in
            verbose|info) sec_audit_report_pass 158 "sshd LogLevel is configured ($(sec_audit_sshd_get loglevel))" ;;
            *) sec_audit_report_fail 158 "sshd LogLevel does not meet the required policy ($(sec_audit_sshd_get loglevel))" ;;
        esac

        if sec_audit_sshd_config_grep -Piq 'macs\h+([^#\n\r]+,)?(hmac-md5|hmac-md5-96|hmac-ripemd160|hmac-sha1-96|umac-64@openssh\.com|hmac-md5-etm@openssh\.com|hmac-md5-96-etm@openssh\.com|hmac-ripemd160-etm@openssh\.com|hmac-sha1-96-etm@openssh\.com|umac-64-etm@openssh\.com)\b'; then
            sec_audit_report_fail 159 "sshd MACs allow weak or legacy algorithms"
        else
            sec_audit_report_pass 159 "sshd MACs are configured"
        fi

        _mat=$(sec_audit_sshd_get_int maxauthtries)
        if [[ -n "$_mat" && "$_mat" -ge 1 && "$_mat" -le 4 ]]; then
            sec_audit_report_pass 160 "sshd MaxAuthTries is configured (${_mat})"
        else
            sec_audit_report_fail 160 "sshd MaxAuthTries does not meet the required policy (${_mat:-?}, expected 1-4)"
        fi

        _msu=$(sec_audit_sshd_get maxstartups)
        IFS=: read -r _ms1 _ms2 _ms3 <<<"${_msu:-10:30:60}"
        if [[ "${_ms1:-99}" -le 10 && "${_ms2:-99}" -le 30 && "${_ms3:-99}" -le 60 ]]; then
            sec_audit_report_pass 161 "sshd MaxStartups is configured (${_msu})"
        else
            sec_audit_report_fail 161 "sshd MaxStartups does not meet the required policy (${_msu:-?})"
        fi

        _msess=$(sec_audit_sshd_get_int maxsessions)
        if [[ -n "$_msess" && "$_msess" -ge 1 && "$_msess" -le 10 ]]; then
            sec_audit_report_pass 162 "sshd MaxSessions is configured (${_msess})"
        else
            sec_audit_report_fail 162 "sshd MaxSessions does not meet the required policy (${_msess:-?}, expected 1-10)"
        fi

        [[ "$(sec_audit_to_lower "$(sec_audit_sshd_get permitemptypasswords)")" == "no" ]] && sec_audit_report_pass 163 "sshd PermitEmptyPasswords is disabled" || sec_audit_report_fail 163 "sshd PermitEmptyPasswords is not disabled"
        case "$(sec_audit_to_lower "$(sec_audit_sshd_get permitrootlogin)")" in
            no|prohibit-password|without-password) sec_audit_report_pass 164 "sshd PermitRootLogin is disabled ($(sec_audit_sshd_get permitrootlogin))" ;;
            *) sec_audit_report_fail 164 "sshd PermitRootLogin is not disabled ($(sec_audit_sshd_get permitrootlogin))" ;;
        esac
        [[ "$(sec_audit_to_lower "$(sec_audit_sshd_get permituserenvironment)")" == "no" ]] && sec_audit_report_pass 165 "sshd PermitUserEnvironment is disabled" || sec_audit_report_fail 165 "sshd PermitUserEnvironment is not disabled"
        [[ "$(sec_audit_to_lower "$(sec_audit_sshd_get usepam)")" == "yes" ]] && sec_audit_report_pass 166 "sshd UsePAM is enabled" || sec_audit_report_fail 166 "sshd UsePAM is not enabled"
    fi
}

sec_audit_run_sudo_su() {
    # RULE167-172 sudo / su
    if sec_audit_rpm_any_installed sudo; then
        sec_audit_report_pass 167 "sudo is installed"
    else
        sec_audit_report_fail 167 "sudo package is not installed"
    fi

    if grep -rPiq '^\h*Defaults\h+([^#\n\r]+,\h*)?use_pty\b' /etc/sudoers /etc/sudoers.d 2>/dev/null \
        && ! grep -rPi '^\h*Defaults\h+([^#\n\r]+,\h*)?!use_pty\b' /etc/sudoers /etc/sudoers.d 2>/dev/null; then
        sec_audit_report_pass 168 "sudo commands use pty"
    else
        sec_audit_report_fail 168 "sudo is not configured to require a pseudo-terminal (use_pty)"
    fi

    if grep -rPsiq "^\h*Defaults\h+([^#]+,\h*)?logfile\h*=\h*(\"|')?\H+(\"|')?" /etc/sudoers /etc/sudoers.d 2>/dev/null; then
        sec_audit_report_pass 169 "sudo log file exists"
    else
        sec_audit_report_fail 169 "sudo log file is missing or not configured"
    fi

    if grep -rE '^[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | grep -vE '^\s*#' | grep -q .; then
        sec_audit_report_fail 170 "NOPASSWD or password-less sudo rules violate escalation policy"
    else
        sec_audit_report_pass 170 "users must provide password for escalation"
    fi

    _to=$(sudo -V 2>/dev/null | awk -F': ' '/Authentication timestamp timeout/{print $2; exit}')
    _to_int=${_to%%.*}
    if [ -n "$_to_int" ] && [[ "$_to_int" =~ ^[0-9]+$ ]]; then
        if [ "$_to_int" -ge 0 ] && [ "$_to_int" -le 15 ]; then
            sec_audit_report_pass 171 "sudo timestamp_timeout is configured (${_to} minutes)"
        else
            sec_audit_report_fail 171 "sudo timestamp_timeout is not set within the required range (${_to} minutes)"
        fi
    else
        sec_audit_report_pass 171 "sudo timestamp_timeout is configured (vendor default)"
    fi

    if grep -Pi '^\h*auth\h+(required|requisite)\h+pam_wheel\.so\b' /etc/pam.d/su 2>/dev/null | grep -q use_uid; then
        sec_audit_report_pass 172 "access to the su command is restricted (pam_wheel.so use_uid)"
    else
        sec_audit_report_fail 172 "su is not restricted to the wheel group in PAM configuration"
    fi
}

sec_audit_run_pam_auth() {
    # RULE173-189 PAM / authselect / pwquality
    _as_profile=$(head -1 /etc/authselect/authselect.conf 2>/dev/null)
    if [ -z "$_as_profile" ]; then
        sec_audit_report_fail 173 "active authselect profile does not include required pam modules"
    elif sec_audit_have_bin authselect && ! authselect check &>/dev/null; then
        sec_audit_report_fail 173 "authselect reports configuration drift (run authselect check / apply changes)"
    elif grep -Pq -- '\b(pam_pwquality\.so|pam_pwhistory\.so|pam_faillock\.so|pam_unix\.so)\b' /etc/authselect/"$_as_profile"/{system,password}-auth 2>/dev/null; then
        sec_audit_report_pass 173 "active authselect profile includes pam modules (authselect check OK)"
    else
        sec_audit_report_fail 173 "active authselect profile does not include required pam modules"
    fi

    if sec_audit_pam_password_stack_has pam_faillock.so || sec_audit_pam_auth_stack_has pam_faillock.so; then
        sec_audit_report_pass 174 "pam_faillock.so present on password or auth stack in resolved PAM files"
    else
        sec_audit_report_fail 174 "pam_faillock module is not enabled on the password/auth stack"
    fi

    if sec_audit_pam_password_stack_has pam_pwquality.so && sec_audit_pam_pwquality_before_unix; then
        sec_audit_report_pass 175 "pam_pwquality.so on password stack and ordered before pam_unix.so"
    elif sec_audit_pam_password_stack_has pam_pwquality.so; then
        sec_audit_report_fail 175 "pam_pwquality.so present but not correctly ordered before pam_unix.so"
    else
        sec_audit_report_fail 175 "pam_pwquality module is not enabled on the password stack"
    fi

    if sec_audit_pam_password_stack_has pam_pwhistory.so; then
        sec_audit_report_pass 176 "pam_pwhistory.so on password stack in resolved password-auth/system-auth"
    else
        sec_audit_report_fail 176 "pam_pwhistory module is not enabled on the password stack"
    fi

    if sec_audit_pam_password_stack_has pam_unix.so; then
        sec_audit_report_pass 177 "pam_unix.so on password stack in resolved password-auth/system-auth"
    else
        sec_audit_report_fail 177 "pam_unix module is not enabled on the password stack"
    fi

    _deny=$(awk -F= '/^[[:space:]]*deny[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' /etc/security/faillock.conf 2>/dev/null)
    if [[ "$_deny" =~ ^[1-5]$ ]]; then
        sec_audit_report_pass 178 "password failed attempts lockout is configured (deny=${_deny})"
    else
        sec_audit_report_fail 178 "faillock deny threshold is not configured in /etc/security/faillock.conf (got ${_deny:-unset}, expected 1-5)"
    fi

    _ut=$(awk -F= '/^[[:space:]]*unlock_time[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' /etc/security/faillock.conf 2>/dev/null)
    if [[ "$_ut" == "0" ]] || { [[ "$_ut" =~ ^[0-9]+$ ]] && [ "$_ut" -ge 900 ]; }; then
        sec_audit_report_pass 179 "password unlock time is configured (unlock_time=${_ut})"
    else
        sec_audit_report_fail 179 "faillock unlock_time is not set within the required range (got ${_ut:-unset})"
    fi

    _minlen=$(awk -F= '/^[[:space:]]*minlen[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null | tail -n1)
    if [[ "$_minlen" =~ ^[0-9]+$ ]] && [ "$_minlen" -ge 14 ]; then
        sec_audit_report_pass 180 "password length is configured (minlen=${_minlen})"
    else
        sec_audit_report_fail 180 "pwquality minlen is not set to at least 14 (got ${_minlen:-unset})"
    fi

    if grep -Psiq '^\h*(minclass|[dulo]credit)\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null; then
        sec_audit_report_pass 181 "password complexity is configured"
    else
        sec_audit_report_fail 181 "pwquality complexity (minclass/credits) is not configured"
    fi

    if ! grep -Psiq '^\h*dictcheck\h*=\h*0\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null; then
        sec_audit_report_pass 182 "password dictionary check is enabled"
    else
        sec_audit_report_fail 182 "pwquality dictcheck is disabled"
    fi

    if grep -Psiq '\h*enforce_for_root\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null; then
        sec_audit_report_pass 183 "password quality is enforced for the root user"
    else
        sec_audit_report_fail 183 "pwquality enforce_for_root is not set"
    fi

    _rem=$(awk -F= '/^[[:space:]]*remember[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' /etc/security/pwhistory.conf 2>/dev/null)
    if [[ "$_rem" =~ ^[0-9]+$ ]] && [ "$_rem" -ge 24 ]; then
        sec_audit_report_pass 184 "password history remember is configured (remember=${_rem})"
    elif sec_audit_pam_password_igrep '^\h*password\h+([^#\n\r]+)\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?remember=[0-9]+'; then
        _r184=$(sec_audit_pam_password_stack_paths | while IFS= read -r _p184; do
            [[ -f "$_p184" ]] || continue
            grep -Po 'remember=\K[0-9]+' "$_p184" 2>/dev/null | head -n1 && break
        done)
        if [[ "${_r184:-0}" -ge 24 ]]; then
            sec_audit_report_pass 184 "password history remember is configured (authselect/PAM stack remember=${_r184})"
        else
            sec_audit_report_fail 184 "pwhistory remember value is below policy or not configured"
        fi
    else
        sec_audit_report_fail 184 "pwhistory remember value is below policy or not configured"
    fi

    if grep -Psiq 'enforce_for_root\b' /etc/security/pwhistory.conf 2>/dev/null; then
        sec_audit_report_pass 185 "password history is enforced for the root user"
    else
        sec_audit_report_fail 185 "pwhistory enforce_for_root is not set"
    fi

    if sec_audit_pam_password_grep '^\h*password\h+([^#\n\r]+)\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?use_authtok\b'; then
        sec_audit_report_pass 186 "pam_pwhistory includes use_authtok"
    else
        sec_audit_report_fail 186 "pam_pwhistory line lacks use_authtok on password-auth/system-auth stack"
    fi

    if ! sec_audit_pam_login_auth_igrep '^\h*auth\h+.*pam_unix\.so.*nullok'; then
        sec_audit_report_pass 187 "pam_unix does not include nullok"
    else
        sec_audit_report_fail 187 "pam_unix still allows nullok in the auth stack"
    fi

    if ! sec_audit_pam_password_igrep '^\h*password\h+([^#\n\r]+)\h+pam_unix\.so.*remember='; then
        sec_audit_report_pass 188 "pam_unix does not include remember"
    else
        sec_audit_report_fail 188 "pam_unix password line still uses remember="
    fi

    if sec_audit_pam_password_grep '^\h*password\h+([^#\n\r]+)\h+pam_unix\.so\h+([^#\n\r]+\h+)?use_authtok\b'; then
        sec_audit_report_pass 189 "pam_unix includes use_authtok"
    else
        sec_audit_report_fail 189 "pam_unix password line lacks use_authtok on password-auth/system-auth stack"
    fi
}

sec_audit_run_accounts() {
    # RULE190-206 accounts / umask / TMOUT
    _pmax=$(sec_audit_login_defs_value PASS_MAX_DAYS)
    if ! sec_audit_can_read_shadow; then
        sec_audit_report_fail 190 "cannot read /etc/shadow to verify per-user PASS_MAX_DAYS"
    elif [[ "$_pmax" =~ ^[0-9]+$ ]] && [ "$_pmax" -ge 1 ] && [ "$_pmax" -le 365 ]; then
        if awk -F: '($2~/^\$.+\$/) {if($5 > 365 || $5 < 1) exit 1}' /etc/shadow 2>/dev/null; then
            sec_audit_report_pass 190 "password expiration is configured (PASS_MAX_DAYS=${_pmax})"
        else
            sec_audit_report_fail 190 "PASS_MAX_DAYS=${_pmax} but one or more shadow MAX values exceed policy"
        fi
    else
        sec_audit_report_fail 190 "PASS_MAX_DAYS is unset or outside 1-365 (${_pmax:-unset})"
    fi

    _pmin=$(sec_audit_login_defs_value PASS_MIN_DAYS)
    if [[ "$_pmin" =~ ^[0-9]+$ ]] && [ "$_pmin" -ge 7 ]; then
        sec_audit_report_pass 191 "Minimum password days is configured (PASS_MIN_DAYS=${_pmin})"
    else
        sec_audit_report_fail 191 "Minimum password days is not configured or too low (${_pmin:-unset}, expected >=7)"
    fi

    _pwarn=$(sec_audit_login_defs_value PASS_WARN_AGE)
    if ! sec_audit_can_read_shadow; then
        sec_audit_report_fail 192 "cannot read /etc/shadow to verify per-user PASS_WARN_AGE"
    elif [[ "$_pwarn" =~ ^[0-9]+$ ]] && [ "$_pwarn" -ge 7 ]; then
        if awk -F: '($2~/^\$.+\$/) {if($6 < 7) exit 1}' /etc/shadow 2>/dev/null; then
            sec_audit_report_pass 192 "password expiration warning days is configured (PASS_WARN_AGE=${_pwarn})"
        else
            sec_audit_report_fail 192 "PASS_WARN_AGE=${_pwarn} but one or more shadow WARN values are below 7"
        fi
    else
        sec_audit_report_fail 192 "PASS_WARN_AGE is not set within policy (${_pwarn:-unset})"
    fi

    _enc=$(sec_audit_login_defs_value ENCRYPT_METHOD)
    case "$(sec_audit_to_lower "$_enc")" in
        sha512|yescrypt) sec_audit_report_pass 193 "strong password hashing algorithm is configured (${_enc})" ;;
        *) sec_audit_report_fail 193 "ENCRYPT_METHOD in /etc/login.defs does not use a strong hashing algorithm (${_enc:-unset})" ;;
    esac

    _inact=$(useradd -D 2>/dev/null | awk -F= '/INACTIVE/{print $2; exit}')
    if ! sec_audit_can_read_shadow; then
        sec_audit_report_fail 194 "cannot read /etc/shadow to verify per-user inactive lock"
    elif [[ "$_inact" =~ ^[0-9]+$ ]] && [ "$_inact" -ge 1 ] && [ "$_inact" -le 45 ]; then
        if awk -F: '($2~/^\$.+\$/) {if($7 > 45 || $7 < 0) exit 1}' /etc/shadow 2>/dev/null; then
            sec_audit_report_pass 194 "inactive password lock is configured (INACTIVE=${_inact})"
        else
            sec_audit_report_fail 194 "useradd INACTIVE=${_inact} but one or more shadow inactive values exceed policy"
        fi
    else
        sec_audit_report_fail 194 "useradd INACTIVE or inactive lock policy is not configured (${_inact:-unset})"
    fi

    _fut=0
    _now=$(date +%s)
    if ! sec_audit_can_read_shadow; then
        sec_audit_report_fail 195 "cannot read /etc/shadow to verify last password change dates"
    else
        while IFS=: read -r _u _p _last _rest; do
            if [[ "$_last" =~ ^[0-9]+$ ]] && [ "$_last" -gt 0 ]; then
                if [ $((_last * 86400)) -gt "$_now" ]; then
                    _fut=$((_fut + 1))
                fi
            fi
        done < /etc/shadow 2>/dev/null
        if [ "$_fut" -eq 0 ]; then
            sec_audit_report_pass 195 "All users last password change date is in the past"
        else
            sec_audit_report_fail 195 "${_fut} account(s) have a last password change date in the future"
        fi
    fi

    _uid0=$(awk -F: '($3==0){print $1}' /etc/passwd 2>/dev/null)
    _uid0n=$(printf '%s\n' "$_uid0" | grep -cve '^[[:space:]]*$' || true)
    if [ "$_uid0n" -eq 1 ] && [[ "$_uid0" == "root" ]]; then
        sec_audit_report_pass 196 "root is the only UID 0 account"
    else
        sec_audit_report_fail 196 "UID 0 accounts: $(printf '%s' "$_uid0" | tr '\n' ' ')"
    fi

    _gid0u=$(awk -F: '($1 !~ /^(sync|shutdown|halt|operator)$/ && $4=="0"){print $1}' /etc/passwd 2>/dev/null)
    _gid0un=$(printf '%s\n' "$_gid0u" | grep -cve '^[[:space:]]*$' || true)
    if [ "$_gid0un" -eq 1 ] && [[ "$_gid0u" == "root" ]]; then
        sec_audit_report_pass 197 "root is the only GID 0 account"
    else
        sec_audit_report_fail 197 "GID 0 users outside policy: $(printf '%s' "$_gid0u" | tr '\n' ' ')"
    fi

    _gid0g=$(awk -F: '$3=="0"{print $1}' /etc/group 2>/dev/null)
    _gid0gn=$(printf '%s\n' "$_gid0g" | grep -cve '^[[:space:]]*$' || true)
    if [ "$_gid0gn" -eq 1 ] && [[ "$_gid0g" == "root" ]]; then
        sec_audit_report_pass 198 "group root is the only GID 0 group"
    else
        sec_audit_report_fail 198 "GID 0 groups: $(printf '%s' "$_gid0g" | tr '\n' ' ')"
    fi

    if passwd -S root 2>/dev/null | awk '$2 ~ /^(P|L)/' | grep -q root; then
        sec_audit_report_pass 199 "root account access is controlled"
    else
        sec_audit_report_fail 199 "root password status is not P or L (passwd -S root)"
    fi

    _rpath=$(sudo -i printenv PATH 2>/dev/null || printf '%s' "$PATH")
    _rbad=0
    [[ "$_rpath" == *::* ]] && _rbad=1
    [[ "$_rpath" == .*:* || "$_rpath" == *:.* || "$_rpath" == "." ]] && _rbad=1
    if [ "$_rbad" -eq 0 ]; then
        sec_audit_report_pass 200 "Root path integrity is maintained"
    else
        sec_audit_report_fail 200 "Root PATH contains empty or current-directory entries"
    fi

    if ! grep -Psi '^\h*umask\h+((\d{1,2}(\d[^7]|[^2-7]\d)\b)|(u=[rwx]{1,3},)?(((g=[rx]?[rx]?w[rx]?[rx]?\b)(,o=[rwx]{1,3})?)|((g=[wrx]{1,3},)?o=[wrx]{1,3}\b)))' /root/.bash_profile /root/.bashrc 2>/dev/null; then
        sec_audit_report_pass 201 "root user umask is configured"
    else
        sec_audit_report_fail 201 "root umask is not 027 (or stricter) in profile scripts"
    fi

    _vsp=$(sec_audit_interactive_shell_pattern)
    _umin=$(sec_audit_get_uid_min)
    if awk -v pat="^($_vsp)$" -v uidmin="$_umin" -F: '($1!~/^(root|halt|sync|shutdown|nfsnobody)$/ && ($3<uidmin || $3==65534) && $NF ~ pat) {found=1} END {exit found?0:1}' /etc/passwd 2>/dev/null; then
        sec_audit_report_fail 202 "System accounts still have an interactive login shell"
    else
        sec_audit_report_pass 202 "system accounts do not have a valid login shell"
    fi

    _unlocked=0
    while IFS= read -r _lu; do
        [ -n "$_lu" ] || continue
        if passwd -S "$_lu" 2>/dev/null | awk '$2 !~ /^L/ {exit 0} {exit 1}'; then
            _unlocked=$((_unlocked + 1))
        fi
    done <<< "$(awk -v pat="^($_vsp)$" -F: '($1 != "root" && $NF !~ pat) {print $1}' /etc/passwd 2>/dev/null)"
    if [ "$_unlocked" -eq 0 ]; then
        sec_audit_report_pass 203 "accounts without a valid login shell are locked"
    else
        sec_audit_report_fail 203 "${_unlocked} account(s) without a valid shell are not locked"
    fi

    if grep -Psq '^\h*([^#\n\r]+)?\/nologin\b' /etc/shells 2>/dev/null; then
        sec_audit_report_fail 204 "nologin appears in /etc/shells"
    else
        sec_audit_report_pass 204 "nologin is not listed in /etc/shells"
    fi

    if grep -Psiq '^([^#\n\r]+)?\bTMOUT=(9[0-9]{1,2}|[1-9][0-9]|[1-9])\b' /etc/*bashrc /etc/profile /etc/profile.d/*.sh 2>/dev/null; then
        sec_audit_report_pass 205 "default user shell timeout is configured"
    else
        sec_audit_report_fail 205 "TMOUT is not set for interactive shells in /etc/profile or profile.d"
    fi

    if grep -Psiq '^\h*umask\h+0?(?:[0-7][2-7]7)\b' /etc/login.defs 2>/dev/null \
        && grep -Psi '^\h*umask\h+0?027\b' /etc/profile.d/*.sh 2>/dev/null; then
        sec_audit_report_pass 206 "default user umask is configured"
    else
        sec_audit_report_fail 206 "Default user umask 027 is not set in /etc/login.defs and profile.d"
    fi
}

sec_audit_run_aide() {
    # RULE207-208 AIDE
    if sec_audit_rpm_any_installed aide; then
        if [[ -f /var/lib/aide/aide.db.gz || -f /var/lib/aide/aide.db ]]; then
            sec_audit_report_pass 207 "AIDE package is installed and database file is present under /var/lib/aide"
        else
            sec_audit_report_fail 207 "AIDE is installed but no database under /var/lib/aide (initialize with aide --init)"
        fi
    else
        sec_audit_report_fail 207 "AIDE package is not installed"
    fi

    if grep -Ersq '^([^#]+\s+)?(\/usr\/s?bin\/|^\s*)aide(\.wrapper)?\s(--?\S+\s)*(-(check|update)|\$AIDEARGS)\b' /etc/cron.* /etc/crontab /var/spool/cron/ /etc/cron.d 2>/dev/null; then
        sec_audit_report_pass 208 "filesystem integrity is regularly checked (cron/cron.d entry references aide)"
    elif [[ "$(sec_audit_systemd_is_enabled aidecheck.timer)" == "enabled" && "$(sec_audit_systemd_is_active aidecheck.timer)" == "active" ]]; then
        _next=$(systemctl show aidecheck.timer -p NextElapseUSecRealtime 2>/dev/null | cut -d= -f2-)
        sec_audit_report_pass 208 "aidecheck.timer enabled and active (next: ${_next:-unknown})"
    else
        sec_audit_report_fail 208 "filesystem integrity is not regularly checked (no cron entry and aidecheck.timer not enabled/active)"
    fi
}

sec_audit_run_logging() {
    # RULE209-225 logging
    _jd_en=$(sec_audit_systemd_is_enabled systemd-journald.service)
    _jd_act=$(sec_audit_systemd_is_active systemd-journald.service)
    if [[ "$_jd_act" == "active" ]]; then
        sec_audit_report_pass 209 "journald service is active (enable=${_jd_en})"
    else
        sec_audit_report_fail 209 "systemd-journald is not active (enable=${_jd_en}, active=${_jd_act})"
    fi

    if [[ -d /var/log/journal ]]; then
        _jp=$(sec_audit_path_mode_octal /var/log/journal)
        if sec_audit_mode_within_max /var/log/journal 755; then
            sec_audit_report_pass 210 "journald log file access is configured (directory mode: ${_jp})"
        else
            sec_audit_report_fail 210 "journald log directory has insecure permissions: ${_jp}"
        fi
    else
        sec_audit_report_pass 210 "journald log file access is configured (directory not found; volatile journal)"
    fi

    _jmax=$(sec_audit_journald_get SystemMaxUse)
    _jfsz=$(sec_audit_journald_get SystemMaxFileSize)
    _jfsec=$(sec_audit_journald_get MaxFileSec)
    if [[ -n "$_jmax" || -n "$_jfsz" || -n "$_jfsec" ]]; then
        sec_audit_report_pass 211 "journald log file rotation is configured (SystemMaxUse=${_jmax:-default}, SystemMaxFileSize=${_jfsz:-default}, MaxFileSec=${_jfsec:-default})"
    else
        sec_audit_report_fail 211 "journald log file rotation is not explicitly configured in merged journald.conf"
    fi

    _rsys_act=$(sec_audit_systemd_is_active rsyslog.service)
    if [[ "$_rsys_act" == "active" && "$_jd_act" == "active" ]]; then
        sec_audit_report_fail 212 "more than one logging system is in use (both rsyslog and journald are active)"
    elif [[ "$_rsys_act" == "active" ]]; then
        sec_audit_report_pass 212 "only one logging system is in use (rsyslog)"
    elif [[ "$_jd_act" == "active" ]]; then
        sec_audit_report_pass 212 "only one logging system is in use (journald)"
    else
        sec_audit_report_fail 212 "no logging system is active (neither rsyslog nor journald)"
    fi

    if sec_audit_rpm_any_installed systemd-journal-remote; then
        sec_audit_report_pass 213 "systemd-journal-remote is installed"
    else
        sec_audit_report_fail 213 "systemd-journal-remote package is not installed"
    fi

    if [[ "$(sec_audit_systemd_is_enabled systemd-journal-upload.service)" == "enabled" && "$(sec_audit_systemd_is_active systemd-journal-upload.service)" == "active" ]]; then
        sec_audit_report_pass 214 "systemd-journal-upload is enabled and active"
    else
        sec_audit_report_fail 214 "systemd-journal-upload is not enabled or not active"
    fi

    if sec_audit_systemd_unit_live systemd-journal-remote.socket systemd-journal-remote.service; then
        sec_audit_report_fail 215 "systemd-journal-remote socket/service is enabled or active but should be disabled"
    else
        sec_audit_report_pass 215 "systemd-journal-remote service is not in use"
    fi

    _fts=$(sec_audit_to_lower "$(sec_audit_journald_get ForwardToSyslog)")
    if [[ "$_fts" == "no" || -z "$_fts" ]]; then
        sec_audit_report_pass 216 "journald ForwardToSyslog is disabled (${_fts:-default})"
    else
        sec_audit_report_fail 216 "journald ForwardToSyslog is ${_fts} (expected no)"
    fi

    _cmp=$(sec_audit_to_lower "$(sec_audit_journald_get Compress)")
    if [[ "$_cmp" == "yes" || -z "$_cmp" ]]; then
        sec_audit_report_pass 217 "journald Compress is configured (${_cmp:-default yes})"
    else
        sec_audit_report_pass 217 "journald Compress is configured (${_cmp})"
    fi

    _stor=$(sec_audit_to_lower "$(sec_audit_journald_get Storage)")
    if [[ "$_stor" == "persistent" ]]; then
        sec_audit_report_pass 218 "journald Storage is configured (persistent)"
    else
        sec_audit_report_fail 218 "journald Storage=persistent is not set in merged config (got ${_stor:-unset})"
    fi

    if sec_audit_rpm_any_installed rsyslog; then
        sec_audit_report_pass 219 "rsyslog is installed"
    else
        sec_audit_report_fail 219 "rsyslog package is not installed"
    fi

    if [[ "$(sec_audit_systemd_is_enabled rsyslog.service)" == "enabled" && "$_rsys_act" == "active" ]]; then
        sec_audit_report_pass 220 "rsyslog service is enabled and active"
    else
        sec_audit_report_fail 220 "rsyslog is not enabled or not active"
    fi

    if [[ "$_fts" == "yes" ]]; then
        sec_audit_report_pass 221 "journald is configured to send logs to rsyslog"
    else
        sec_audit_report_fail 221 "journald ForwardToSyslog or forwarding to rsyslog is not configured"
    fi

    if grep -Psq '^\h*\$FileCreateMode\h+0[0,2,4,6][0,2,4]0\b' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null; then
        sec_audit_report_pass 222 "rsyslog log file creation mode is configured"
    else
        sec_audit_report_fail 222 "rsyslog \$FileCreateMode (or equivalent) does not meet policy"
    fi

    if sec_audit_have_bin rsyslogd; then
        if [[ -f /etc/rsyslog.conf ]] && grep -vE '^[[:space:]]*#' /etc/rsyslog.conf 2>/dev/null | grep -qE '^\*\.\*|^auth|^mail|^cron|^*.*'; then
            sec_audit_report_pass 223 "rsyslog logging is configured"
        else
            sec_audit_report_fail 223 "rsyslog logging is not properly configured"
        fi
    else
        sec_audit_report_pass 223 "rsyslog is not installed"
    fi

    if sec_audit_have_bin logrotate; then
        if [[ -f /etc/logrotate.conf ]] && grep -qE '^rotate|^daily|^weekly|^monthly' /etc/logrotate.conf 2>/dev/null; then
            sec_audit_report_pass 224 "rsyslog logrotate is configured"
        else
            sec_audit_report_fail 224 "rsyslog logrotate is not properly configured"
        fi
    else
        sec_audit_report_fail 224 "logrotate is not installed"
    fi

    _log_bad=0
    _log_detail=""
    for _lf in /var/log/messages /var/log/secure /var/log/maillog /var/log/cron /var/log/boot.log; do
        [[ -f $_lf ]] || continue
        if ! sec_audit_mode_within_max "$_lf" 640 || [[ "$(sec_audit_path_owner_user "$_lf")" != "root" ]]; then
            _log_bad=$((_log_bad + 1))
            _log_detail="${_log_detail}${_lf}:$(sec_audit_path_mode_octal "$_lf"):$(sec_audit_path_owner_user "$_lf") "
        fi
    done
    if [ "$_log_bad" -eq 0 ]; then
        sec_audit_report_pass 225 "Access to all logfiles has been configured"
    else
        sec_audit_report_fail 225 "insecure logfile permissions: ${_log_detail}"
    fi
}

sec_audit_run_auditd() {
    # RULE226-256 auditd
    if sec_audit_rpm_every_installed audit audit-libs; then
        sec_audit_report_pass 226 "auditd packages are installed"
    else
        sec_audit_report_fail 226 "audit audit-libs packages are not installed"
    fi

    if grep -Psoiq '^\h*GRUB_CMDLINE_LINUX=\"([^#\n\r]+\h+)?\baudit_backlog_limit=\d+\b' /etc/default/grub 2>/dev/null \
        || grep -Pq '\baudit_backlog_limit=[0-9]+' /proc/cmdline 2>/dev/null; then
        sec_audit_report_pass 227 "audit_backlog_limit is configured"
    else
        sec_audit_report_fail 227 "audit_backlog_limit is not set in GRUB_CMDLINE_LINUX or /proc/cmdline"
    fi

    if [[ "$(sec_audit_systemd_is_enabled auditd.service)" == "enabled" && "$(sec_audit_systemd_is_active auditd.service)" == "active" ]]; then
        sec_audit_report_pass 228 "auditd service is enabled and active"
    else
        sec_audit_report_fail 228 "auditd is not enabled or not active"
    fi

    if grep -Poq '^\h*max_log_file\h*=\h*\d+\b' /etc/audit/auditd.conf 2>/dev/null; then
        sec_audit_report_pass 229 "audit log storage size is configured"
    else
        sec_audit_report_fail 229 "max_log_file or rotation policy in auditd.conf does not meet policy"
    fi

    if grep -Piq '^\h*max_log_file_action\h*=\h*keep_logs\b' /etc/audit/auditd.conf 2>/dev/null; then
        sec_audit_report_pass 230 "audit logs are not automatically deleted"
    else
        sec_audit_report_fail 230 "max_log_file_action or keep_logs policy allows silent deletion"
    fi

    if grep -Pq '^\h*disk_full_action\h*=\h*(halt|single)\b' /etc/audit/auditd.conf 2>/dev/null \
        && grep -P '^\h*disk_error_action\h*=\h*(syslog|single|halt)\b' /etc/audit/auditd.conf 2>/dev/null; then
        sec_audit_report_pass 231 "system is disabled when audit logs are full"
    else
        sec_audit_report_fail 231 "disk_full_action / disk_error_action in auditd.conf does not meet policy"
    fi

    if grep -Pq '^\h*space_left_action\h*=\h*(email|exec|single|halt)\b' /etc/audit/auditd.conf 2>/dev/null \
        && grep -P '^\h*admin_space_left_action\h*=\h*(single|halt)\b' /etc/audit/auditd.conf 2>/dev/null; then
        sec_audit_report_pass 232 "system warns when audit logs are low on space"
    else
        sec_audit_report_fail 232 "space_left_action / admin_space_left_action in auditd.conf are incomplete"
    fi

    if sec_audit_audit_rule_on_disk_and_loaded -q "path=/etc/sudoers" && sec_audit_audit_rule_on_disk_and_loaded -q "dir=/etc/sudoers.d"; then
        sec_audit_report_pass 233 "sudoers and sudoers.d watch rules present in audit.rules and loaded in kernel"
    elif sec_audit_audit_rule_on_disk_and_loaded -q "path=/etc/sudoers"; then
        sec_audit_report_fail 233 "/etc/sudoers.d directory watch missing on disk or not loaded"
    else
        sec_audit_report_fail 233 "/etc/sudoers file watch missing on disk or not loaded"
    fi

    if sec_audit_audit_rule_on_disk_and_loaded -q "execve"; then
        sec_audit_report_pass 234 "execve auditing present on disk and loaded"
    else
        sec_audit_report_fail 234 "actions as another user are not always logged (execve audit rule missing or not loaded)"
    fi

    if [[ -f /var/log/sudo.log ]] && sec_audit_audit_rule_on_disk_and_loaded -q "path=/var/log/sudo.log"; then
        sec_audit_report_pass 235 "audit rule for /var/log/sudo.log on disk and loaded"
    elif [[ ! -f /var/log/sudo.log ]]; then
        sec_audit_report_fail 235 "events that modify the sudo log file are not collected (/var/log/sudo.log not found)"
    else
        sec_audit_report_fail 235 "events that modify the sudo log file are not collected (audit watch missing or not loaded)"
    fi

    if sec_audit_audit_rule_on_disk_and_loaded -q "dir=/etc/NetworkManager/"; then
        sec_audit_report_pass 236 "NetworkManager directory watch on disk and loaded"
    else
        sec_audit_report_fail 236 "events that modify /etc/NetworkManager directory are not collected"
    fi

    if sec_audit_audit_rule_on_disk_and_loaded -E -q 'path=/usr/bin/sudo|path=/usr/bin/su|path=/bin/su'; then
        sec_audit_report_pass 237 "privileged command execution (sudo/su) audited on disk and loaded"
    else
        sec_audit_report_fail 237 "use of privileged commands is not being collected"
    fi

    if sec_audit_audit_rule_on_disk_and_loaded -E -q 'EACCES|EPERM'; then
        sec_audit_report_pass 238 "unsuccessful access (EACCES/EPERM) auditing on disk and loaded"
    else
        sec_audit_report_fail 238 "unsuccessful file access attempts are not collected"
    fi

    if sec_audit_audit_rule_on_disk_and_loaded -q "path=/etc/shadow" && sec_audit_audit_rule_on_disk_and_loaded -q "path=/etc/gshadow"; then
        sec_audit_report_pass 239 "shadow and gshadow watches on disk and loaded"
    elif sec_audit_audit_rule_on_disk_and_loaded -q "path=/etc/shadow"; then
        sec_audit_report_fail 239 "events that modify /etc/gshadow are not collected"
    else
        sec_audit_report_fail 239 "events that modify /etc/shadow are not collected"
    fi

    if sec_audit_audit_rule_on_disk_and_loaded -q "mount"; then
        sec_audit_report_pass 240 "mount syscall auditing on disk and loaded"
    else
        sec_audit_report_fail 240 "successful file system mounts are not collected"
    fi

    if sec_audit_audit_rule_on_disk_and_loaded -E -q 'utmp|wtmp|btmp'; then
        sec_audit_report_pass 241 "session initiation (utmp/wtmp/btmp) auditing on disk and loaded"
    else
        sec_audit_report_fail 241 "session initiation information is not collected"
    fi

    if sec_audit_audit_rule_on_disk_and_loaded -E -q 'lastlog|faillock'; then
        sec_audit_report_pass 242 "login/logout related auditing on disk and loaded"
    else
        sec_audit_report_fail 242 "login and logout events are not collected"
    fi

    if sec_audit_audit_rule_on_disk_and_loaded -q "unlink"; then
        sec_audit_report_pass 243 "unlink auditing on disk and loaded"
    else
        sec_audit_report_fail 243 "unlink file deletion events by users are not collected"
    fi

    if sec_audit_audit_rule_on_disk_and_loaded -q "init_module"; then
        sec_audit_report_pass 244 "init_module auditing on disk and loaded"
    else
        sec_audit_report_fail 244 "kernel module loading unloading and modification is not collected"
    fi

    if sec_audit_audit_rule_on_disk_and_loaded -- '-e 2'; then
        sec_audit_report_pass 245 "the audit configuration is immutable (-e 2 loaded and on disk)"
    elif sec_audit_audit_rules_file_grep -q -- '-e 2'; then
        sec_audit_report_fail 245 "Immutable rule (-e 2) is on disk but not loaded (auditctl -l)"
    elif sec_audit_auditctl_list_grep -q -- '-e 2'; then
        sec_audit_report_fail 245 "Immutable rule (-e 2) is loaded but missing from on-disk audit rules"
    else
        sec_audit_report_fail 245 "Immutable rule (-e 2) is missing from loaded and on-disk audit rules"
    fi

    if sec_audit_have_bin augenrules && augenrules --check 2>/dev/null | grep -q "No change"; then
        sec_audit_report_pass 246 "the running and on disk configuration is the same"
    elif ! sec_audit_have_bin augenrules; then
        sec_audit_report_fail 246 "augenrules is not available; cannot compare loaded vs on-disk audit rules"
    else
        sec_audit_report_fail 246 "Loaded audit rules differ from on-disk rules (augenrules --check)"
    fi

    _alogdir=$(sec_audit_auditd_log_directory || true)
    if [[ -n "$_alogdir" && -d "$_alogdir" ]]; then
        if [[ "$(sec_audit_path_mode_octal "$_alogdir")" == "750" ]]; then
            sec_audit_report_pass 247 "the audit log file directory mode is configured (${_alogdir} mode 750)"
        else
            sec_audit_report_fail 247 "Audit log directory mode is $(sec_audit_path_mode_octal "$_alogdir"), expected 750"
        fi
        if sec_audit_soft_find --timeout=10 "$_alogdir" -xdev -ignore_readdir_race -maxdepth 1 -type f -perm /0137 2>/dev/null | grep -q .; then
            sec_audit_report_fail 248 "One or more audit log files have overly permissive modes"
        else
            sec_audit_report_pass 248 "audit log files mode is configured"
        fi
        if sec_audit_soft_find --timeout=10 "$_alogdir" -xdev -ignore_readdir_race -maxdepth 1 -type f ! -user root 2>/dev/null | grep -q .; then
            sec_audit_report_fail 249 "One or more audit log files are not owned by root"
        else
            sec_audit_report_pass 249 "audit log files owner is configured"
        fi
        _lg=$(awk -F= '/^[[:space:]]*log_group[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' /etc/audit/auditd.conf 2>/dev/null)
        if [[ "$_lg" == "root" || "$_lg" == "adm" ]]; then
            if sec_audit_soft_find --timeout=10 "$_alogdir" -xdev -ignore_readdir_race -maxdepth 1 -type f \( ! -group root -a ! -group adm \) 2>/dev/null | grep -q .; then
                sec_audit_report_fail 250 "Audit log files group ownership does not match log_group policy"
            else
                sec_audit_report_pass 250 "audit log files group owner is configured"
            fi
        else
            sec_audit_report_fail 250 "auditd.conf log_group is '${_lg:-unset}', expected root or adm"
        fi
    else
        sec_audit_report_fail 247 "Audit log directory is missing"
        sec_audit_report_fail 248 "Audit log directory is missing"
        sec_audit_report_fail 249 "Audit log directory is missing"
        sec_audit_report_fail 250 "Audit log directory is missing"
    fi

    if [[ -d /etc/audit ]] && sec_audit_soft_find --timeout=10 /etc/audit/ -xdev -ignore_readdir_race -type f \( -name "*.conf" -o -name '*.rules' \) -perm /0137 2>/dev/null | grep -q .; then
        sec_audit_report_fail 251 "Audit .conf/.rules files have insecure permissions"
    else
        sec_audit_report_pass 251 "audit configuration files mode is configured"
    fi

    if [[ -d /etc/audit ]] && sec_audit_soft_find --timeout=10 /etc/audit/ -xdev -ignore_readdir_race -type f \( -name "*.conf" -o -name '*.rules' \) ! -user root 2>/dev/null | grep -q .; then
        sec_audit_report_fail 252 "Audit configuration files are not owned as required"
    else
        sec_audit_report_pass 252 "audit configuration files owner is configured"
    fi

    if [[ -d /etc/audit ]] && sec_audit_soft_find --timeout=10 /etc/audit/ -xdev -ignore_readdir_race -type f \( -name "*.conf" -o -name '*.rules' \) ! -group root 2>/dev/null | grep -q .; then
        sec_audit_report_fail 253 "Audit configuration files group ownership does not meet policy"
    else
        sec_audit_report_pass 253 "audit configuration files group owner is configured"
    fi

    _tool_mode=0
    _tool_own=0
    _tool_grp=0
    for _tool in /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules /usr/sbin/auditctl /usr/sbin/aureport /usr/sbin/ausearch /usr/sbin/auditd /usr/sbin/augenrules; do
        [[ -f $_tool ]] || continue
        if ! sec_audit_mode_within_max "$_tool" 755 || (( 8#$(sec_audit_path_mode_octal "$_tool") & 8#0022 )); then
            _tool_mode=1
        fi
        [[ "$(sec_audit_path_owner_user "$_tool")" == "root" ]] || _tool_own=1
        [[ "$(sec_audit_path_owner_group "$_tool")" == "root" ]] || _tool_grp=1
    done
    [ "$_tool_mode" -eq 0 ] && sec_audit_report_pass 254 "audit tools mode is configured" || sec_audit_report_fail 254 "One or more audit tools have insecure permissions"
    [ "$_tool_own" -eq 0 ] && sec_audit_report_pass 255 "audit tools owner is configured" || sec_audit_report_fail 255 "One or more audit tools are not owned by root"
    [ "$_tool_grp" -eq 0 ] && sec_audit_report_pass 256 "audit tools group owner is configured" || sec_audit_report_fail 256 "One or more audit tools have incorrect group ownership"
}

sec_audit_run_identity_files() {
    # RULE257-266 identity files
    sec_audit_assert_path_access 257 /etc/passwd 644 root:root "access to /etc/passwd is configured" 0
    sec_audit_assert_path_access 258 /etc/passwd- 644 root:root "access to /etc/passwd- is configured" 1
    sec_audit_assert_path_access 259 /etc/group 644 root:root "access to /etc/group is configured" 0
    sec_audit_assert_path_access 260 /etc/group- 644 root:root "access to /etc/group- is configured" 1
    sec_audit_assert_path_access 261 /etc/shadow 640 root:root "access to /etc/shadow is configured" 0 shadow
    sec_audit_assert_path_access 262 /etc/shadow- 640 root:root "access to /etc/shadow- is configured" 1 shadow
    sec_audit_assert_path_access 263 /etc/gshadow 640 root:root "access to /etc/gshadow is configured" 1 shadow
    sec_audit_assert_path_access 264 /etc/gshadow- 640 root:root "access to /etc/gshadow- is configured" 1 shadow
    sec_audit_assert_path_access 265 /etc/shells 644 root:root "access to /etc/shells is configured" 0
    sec_audit_assert_path_access 266 /etc/security/opasswd 600 root:root "access to /etc/security/opasswd is configured" 1
}

sec_audit_run_filesystem_integrity() {
    # RULE267 world-writable (sticky dirs excluded)
    _crit="/bin /sbin /usr/bin /usr/sbin /etc /var /home"
    if sec_audit_find_hit_timeout sec_audit_soft_find --timeout=10 $_crit -xdev -ignore_readdir_race -maxdepth 2 -type f -perm -0002 -print; then
        sec_audit_report_fail 267 "incomplete_scan: world-writable file search timed out under critical paths"
    elif sec_audit_find_hit_timeout sec_audit_soft_find --timeout=10 $_crit -xdev -ignore_readdir_race -maxdepth 2 -type d -perm -0002 ! -perm -1000 -print; then
        sec_audit_report_fail 267 "incomplete_scan: world-writable directory search timed out under critical paths"
    else
        _wwf=$(sec_audit_soft_find --timeout=10 $_crit -xdev -ignore_readdir_race -maxdepth 2 -type f -perm -0002 -print 2>/dev/null | wc -l)
        _wwd=$(sec_audit_soft_find --timeout=10 $_crit -xdev -ignore_readdir_race -maxdepth 2 -type d -perm -0002 ! -perm -1000 -print 2>/dev/null | wc -l)
        if [ "$_wwf" -eq 0 ] && [ "$_wwd" -eq 0 ]; then
            sec_audit_report_pass 267 "No critical world writable files or non-sticky directories found"
        else
            sec_audit_report_fail 267 "Found potential world-writable items (${_wwf} files, ${_wwd} non-sticky dirs)"
        fi
    fi

    _special=$(
        while IFS= read -r _mp; do
            [ -d "$_mp" ] || continue
            sec_audit_soft_find --timeout=120 "$_mp" -xdev -ignore_readdir_race -type f -perm /6000 -printf '%m\n' 2>/dev/null
        done <<< "$(sec_audit_local_fs_roots)" | awk '
            {
                d = int(($1 % 10000) / 1000)
                if (d == 4 || d == 5 || d == 6 || d == 7) suid++
                if (d == 2 || d == 3 || d == 6 || d == 7) sgid++
            }
            END { print suid + 0, sgid + 0 }
        '
    )
    read -r _suid _sgid <<< "$_special"
    if [ "${_suid:-0}" -gt 0 ] || [ "${_sgid:-0}" -gt 0 ]; then
        sec_audit_report_skip 268 "SUID/SGID files require manual review (${_suid} SUID, ${_sgid} SGID); manual inventory required"
    else
        sec_audit_report_pass 268 "No SUID or SGID files found"
    fi

    if awk -F: '($2 != "x") { found=1 } END { exit found?0:1 }' /etc/passwd 2>/dev/null; then
        sec_audit_report_fail 269 "Non-shadow password field found in /etc/passwd (second field not x)"
    else
        sec_audit_report_pass 269 "accounts in /etc/passwd use shadowed passwords"
    fi

    if ! sec_audit_can_read_shadow; then
        sec_audit_report_fail 270 "cannot read /etc/shadow to verify password hashes"
    elif awk -F: '($2 == "") { found=1 } END { exit found?0:1 }' /etc/shadow 2>/dev/null; then
        sec_audit_report_fail 270 "Empty password hash found in /etc/shadow"
    else
        sec_audit_report_pass 270 "/etc/shadow password fields are not empty"
    fi

    _miss_gid=0
    while IFS=: read -r _u _pw _uid _gid _rest; do
        [ -n "$_gid" ] || continue
        if ! awk -F: -v g="$_gid" '$3==g {found=1} END {exit found?0:1}' /etc/group 2>/dev/null; then
            _miss_gid=$((_miss_gid + 1))
        fi
    done < /etc/passwd 2>/dev/null
    if [ "$_miss_gid" -eq 0 ]; then
        sec_audit_report_pass 271 "All groups in /etc/passwd exist in /etc/group"
    else
        sec_audit_report_fail 271 "${_miss_gid} user(s) have a primary GID that does not exist in /etc/group"
    fi

    _dup_uid=$(awk -F: '{c[$3]++} END {for (u in c) if (c[u]>1) n++} END {print n+0}' /etc/passwd 2>/dev/null)
    _dup_gid=$(awk -F: '{c[$3]++} END {for (g in c) if (c[g]>1) n++} END {print n+0}' /etc/group 2>/dev/null)
    _dup_un=$(awk -F: '{c[$1]++} END {for (u in c) if (c[u]>1) n++} END {print n+0}' /etc/passwd 2>/dev/null)
    _dup_gn=$(awk -F: '{c[$1]++} END {for (g in c) if (c[g]>1) n++} END {print n+0}' /etc/group 2>/dev/null)
    [ "${_dup_uid:-0}" -eq 0 ] && sec_audit_report_pass 272 "no duplicate UIDs exist" || sec_audit_report_fail 272 "Duplicate UID entries exist in /etc/passwd (${_dup_uid})"
    [ "${_dup_gid:-0}" -eq 0 ] && sec_audit_report_pass 273 "no duplicate GIDs exist" || sec_audit_report_fail 273 "Duplicate GID entries exist in /etc/group (${_dup_gid})"
    [ "${_dup_un:-0}" -eq 0 ] && sec_audit_report_pass 274 "no duplicate user names exist" || sec_audit_report_fail 274 "Duplicate user names exist in /etc/passwd (${_dup_un})"
    [ "${_dup_gn:-0}" -eq 0 ] && sec_audit_report_pass 275 "no duplicate group names exist" || sec_audit_report_fail 275 "Duplicate group names exist in /etc/group (${_dup_gn})"

    _dot_bad=0
    _umin=$(sec_audit_get_uid_min)
    while IFS=: read -r _u _pw _uid _gid _gecos _home _sh; do
        [[ "$_uid" =~ ^[0-9]+$ ]] || continue
        [ "$_uid" -ge "$_umin" ] || continue
        [ "$_uid" -lt 65534 ] || continue
        for _df in "$_home/.bashrc" "$_home/.bash_profile" "$_home/.profile" "$_home/.bash_logout"; do
            [[ -f $_df ]] || continue
            if ! sec_audit_mode_within_max "$_df" 644 || (( 8#$(sec_audit_path_mode_octal "$_df") & 8#0022 )); then
                _dot_bad=$((_dot_bad + 1))
            fi
        done
    done < /etc/passwd 2>/dev/null
    if [ "$_dot_bad" -eq 0 ]; then
        sec_audit_report_pass 276 "Local interactive user dot files access is configured"
    else
        sec_audit_report_fail 276 "${_dot_bad} user dot file(s) have group/world write permissions"
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
