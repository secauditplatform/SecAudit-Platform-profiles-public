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

UB20_FIND_CAP="${UB20_FIND_CAP:-20}"
UB20_CMD_CAP="${UB20_CMD_CAP:-12}"
UB20_APT_CAP="${UB20_APT_CAP:-30}"
UB20_ALLOW_CONTAINER_KMOD="${UB20_ALLOW_CONTAINER_KMOD:-${UB20_ALLOW_CONTAINER_MODULES:-0}}"

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
    n=$(sec_audit_exec_with_timeout "$UB20_APT_CAP" dnf -q repolist enabled 2>/dev/null | awk '
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
    sec_audit_have_bin sysctl || return 1
    sysctl -n "$1" 2>/dev/null | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

sec_audit_sysctl_runtime() { printf '%s' "$(sec_audit_sysctl_runtime_raw "$1")"; }

sec_audit_live_sysctl_is() {
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
    if ! sec_audit_live_sysctl_is "$key" "$want"; then
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
    local pattern="$1" cap="${2:-$UB20_FIND_CAP}" rc=0 out=""
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
            [[ "${UB20_ALLOW_CONTAINER_KMOD}" == "1" ]]
            ;;
        *) return 1 ;;
    esac
}

sec_audit_assert_kmod_disabled() {
    local num="$1" label="$2" mod="$3" ko_pattern="$4"
    shift 4
    local alias loaded=0 a
    if sec_audit_kmod_container_exception "$mod"; then
        sec_audit_report_pass "$num" "${label} (waived: UB20_ALLOW_CONTAINER_KMOD=1)"
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
sec_audit_file_owner() { stat -Lc '%U:%G' "$1" 2>/dev/null; }
sec_audit_file_user() { stat -Lc '%U' "$1" 2>/dev/null; }
sec_audit_file_group() { stat -Lc '%G' "$1" 2>/dev/null; }

sec_audit_mode_within_max() {
    local path="$1" max="$2" got
    [[ -e $path ]] || return 1
    got=$(sec_audit_path_mode_octal "$path") || return 1
    [[ "$got" =~ ^[0-7]+$ ]] || return 1
    (( (8#$got & ~8#$max) == 0 ))
}

sec_audit_path_owned_by() {
    local path="$1" want="$2"
    [[ "$(sec_audit_file_owner "$path")" == "$want" ]]
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
        if [[ "$(sec_audit_file_user "$path")" != "${owner%%:*}" ]]; then
            sec_audit_report_fail "$num" "${path} owner is $(sec_audit_file_user "$path"), expected ${owner%%:*}"
            return 0
        fi
        case "$(sec_audit_file_group "$path")" in
            ${owner##*:}|${extra_group}) ;;
            *) sec_audit_report_fail "$num" "${path} group is $(sec_audit_file_group "$path"), expected ${owner##*:} or ${extra_group}"; return 0 ;;
        esac
    else
        if ! sec_audit_path_owned_by "$path" "$owner"; then
            sec_audit_report_fail "$num" "${path} owner is $(sec_audit_file_owner "$path"), expected ${owner}"
            return 0
        fi
    fi
    sec_audit_report_pass "$num" "$pass_msg (mode $(sec_audit_path_mode_octal "$path"), owner $(sec_audit_file_owner "$path"))"
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

# --- Ubuntu body compatibility aliases ---









sec_audit__rule_kernel_mod_unavailable() { sec_audit_assert_kmod_disabled "$@"; }
sec_audit__rule_service_not_in_use() { sec_audit_assert_service_unused "$@"; }
sec_audit__rule_sysctl_check() { sec_audit_assert_sysctl_equals "$@"; }
sec_audit_mount_persisted() { sec_audit_mount_is_persisted "$@"; }
sec_audit_mount_is_mounted() { sec_audit_mount_is_dedicated "$@"; }

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

sec_audit_pkg_any_installed() { sec_audit_dpkg_installed "$1" && return 0; return 1; }

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

sec_audit_sysctl_multi_rule() {
    local num="$1" pass_msg="$2" fail_msg="$3" key want
    shift 3
    while [ $# -gt 0 ]; do
        key=$1
        want=$2
        shift 2
        if ! sec_audit_sysctl_runtime_equals "$key" "$want"; then
            sec_audit_report_fail "$num" "${fail_msg}"
            return 0
        fi
    done
    sec_audit_report_pass "$num" "${pass_msg}"
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
    builtin printf '%s
' /etc/pam.d/common-password
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

sec_audit_dpkg_installed() {
    dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'
}



sec_audit_apt_sources_configured() {
    local n=0
    [[ -f /etc/apt/sources.list ]] && n=$((n + 1))
    shopt -s nullglob
    for f in /etc/apt/sources.list.d/*.list; do
        [[ -f $f ]] && n=$((n + 1))
    done
    shopt -u nullglob
    [ "$n" -gt 0 ]
}

sec_audit_apt_gpg_keys_configured() {
    if sec_audit_have_bin apt-key; then
        apt-key list 2>/dev/null | grep -qE '^pub'
        return $?
    fi
    if sec_audit_have_bin gpg; then
        gpg --list-keys --keyid-format long 2>/dev/null | grep -q '^pub'
        return $?
    fi
    return 1
}

sec_audit_pam_common_files() {
    for f in /etc/pam.d/common-password /etc/pam.d/common-auth /etc/pam.d/common-account /etc/pam.d/common-session; do
        [[ -f $f ]] && builtin printf '%s\n' "$f"
    done
}

sec_audit_pam_common_password_has_module() {
    grep -qE "^[[:space:]]*password[[:space:]].*${1}" /etc/pam.d/common-password 2>/dev/null
}

sec_audit_apparmor_bootloader_enabled() {
    grep -qE '(apparmor=1|security=apparmor)' /proc/cmdline 2>/dev/null || \
    grep -rqE '^\s*GRUB_CMDLINE_LINUX=.*(apparmor=1|security=apparmor)' /etc/default/grub /etc/default/grub.d/*.cfg 2>/dev/null
}

sec_audit_apparmor_profiles_enforce_or_complain() {
    sec_audit_have_bin apparmor_status || return 1
    apparmor_status 2>/dev/null | grep -q 'profiles are loaded' || return 1
    local other
    other=$(apparmor_status 2>/dev/null | awk '/profiles are in/ && !/enforce mode/ && !/complain mode/ {sum+=$1} END{print sum+0}')
    [ "${other:-0}" -eq 0 ]
}

sec_audit_apparmor_all_enforcing() {
    sec_audit_have_bin apparmor_status || return 1
    apparmor_status 2>/dev/null | grep -qE '^[1-9][0-9]* profiles are in enforce mode' && \
    apparmor_status 2>/dev/null | grep -qE '^0 profiles are in complain mode'
}

sec_audit_grub_cfg_permissions_ok() {
    local p u g
    for f in /boot/grub/grub.cfg; do
        [[ -f $f ]] || continue
        p=$(stat -c '%a' "$f" 2>/dev/null)
        u=$(stat -c '%U' "$f" 2>/dev/null)
        g=$(stat -c '%G' "$f" 2>/dev/null)
        [[ -n $p && $p -le 600 && $u == root && $g == root ]] && return 0
    done
    return 1
}

sec_audit_grub_bootloader_password_set() {
    grep -qE '^\s*set\s+superusers' /boot/grub/grub.cfg 2>/dev/null && \
    grep -qE '^\s*password' /boot/grub/grub.cfg 2>/dev/null
}

sec_audit_apport_disabled() {
    if ! sec_audit_dpkg_installed apport; then
        return 0
    fi
    grep -qE '^enabled=0' /etc/default/apport 2>/dev/null && \
    ! systemctl is-active apport.service 2>/dev/null | grep -q '^active'
}

sec_audit_mail_local_only() {
    if ! ss -lntu 2>/dev/null | grep -qE ':25[[:space:]]'; then
        return 0
    fi
    ! ss -lntu 2>/dev/null | grep -E ':25[[:space:]]' | grep -qvE '(127\.0\.0\.1|\[::1\]):25'
}

sec_audit__find_perm_count() {
    local expr="$1" n=0
    while IFS= read -r root; do
        c=$(sec_audit_soft_find --timeout=25 "$root" -xdev $expr 2>/dev/null | wc -l)
        n=$((n + c))
    done < <(sec_audit_local_fs_roots)
    builtin printf '%s' "$n"
}

sec_audit_stat_mode_le() {
    local f="$1" max="$2"
    local p
    p=$(stat -c '%a' "$f" 2>/dev/null) || return 1
    [ -n "$p" ] && [ "$p" -le "$max" ]
}

sec_audit_check_kernel_mod_rule() {
    local num="$1" mod="$2" ko_glob="$3" alt_mod="${4:-}" label="${5:-$mod}"
    if sec_audit_kernel_mod_in_modules_load "$mod" ${alt_mod:+"$alt_mod"}; then
        sec_audit_report_fail "$num" "${label} kernel module is listed in modules-load.d (auto-load at boot)"
    elif ! sec_audit_soft_find --timeout=20 /usr/lib/modules/ /lib/modules/ -xdev -ignore_readdir_race -type f -name "$ko_glob" 2>/dev/null | grep -q .; then
        sec_audit_report_pass "$num" "${label} kernel module is not available"
    elif ! lsmod 2>/dev/null | grep -qE "^${mod}\b" && \
         { sec_audit_have_bin modprobe && modprobe --showconfig 2>/dev/null | grep -Pq "^\h*(blacklist|install)\h+(${mod}|${alt_mod:-${mod}})\b" || \
           grep -rqE "^[[:space:]]*(blacklist|install)[[:space:]]+(${mod}|${alt_mod:-${mod}})\b" /etc/modprobe.d /usr/lib/modprobe.d 2>/dev/null; }; then
        sec_audit_report_pass "$num" "${label} kernel module is not available"
    else
        sec_audit_report_fail "$num" "${label} kernel module is available, loaded, or not effectively blocked"
    fi
}

sec_audit_service_not_in_use_rule() {
    local num="$1" unit="$2" pkg="$3" label="$4"
    if systemctl is-active "$unit" &>/dev/null 2>&1 || sec_audit_dpkg_installed "$pkg"; then
        sec_audit_report_fail "$num" "${label} is installed or active"
    else
        sec_audit_report_pass "$num" "${label} is not in use"
    fi
}

sec_audit_sshd_effective_equals() {
    local key="$1" want="$2" got
    got=$(sec_audit_sshd_t_grep -iE "^[[:space:]]*${key}[[:space:]]+" 2>/dev/null | awk '{print $2}' | head -n1)
    [[ "${got,,}" == "${want,,}" ]]
}

sec_audit_sshd_effective_not_weak_token() {
    local key="$1" weak_re="$2"
    ! sec_audit_sshd_t_grep -iE "^[[:space:]]*${key}[[:space:]]+" 2>/dev/null | grep -qiE "$weak_re"
}

sec_audit_ufw_active_enabled() {
    systemctl is-active ufw 2>/dev/null | grep -q '^active$' && \
    systemctl is-enabled ufw 2>/dev/null | grep -q '^enabled$'
}

sec_audit_nftables_service_ok() {
    sec_audit_dpkg_installed nftables && systemctl is-enabled nftables 2>/dev/null | grep -q enabled
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
# Section runners (RULE1 .. RULE313)
# =============================================================================

sec_audit_run_kernel_modules() {
    # RULE1-278

# RULE1:
sec_audit_check_kernel_mod_rule 1 cramfs "cramfs.ko*"

# RULE2:
sec_audit_check_kernel_mod_rule 2 freevxfs "freevxfs.ko*"

# RULE3:
sec_audit_check_kernel_mod_rule 3 hfs "hfs.ko*"

# RULE4:
sec_audit_check_kernel_mod_rule 4 hfsplus "hfsplus.ko*"

# RULE5:
sec_audit_check_kernel_mod_rule 5 jffs2 "jffs2.ko*"

# RULE6:
sec_audit_check_kernel_mod_rule 6 overlay "overlay.ko*"

# RULE7:
sec_audit_check_kernel_mod_rule 7 squashfs "squashfs.ko*"

# RULE8:
sec_audit_check_kernel_mod_rule 8 udf "udf.ko*"

# RULE9:
sec_audit_check_kernel_mod_rule 9 usb_storage "usb-storage.ko*" usb-storage "usb-storage"

# RULE10:
sec_audit_report_pass 10 "unused filesystem module review deferred to per-module checks (RULE1-RULE7)"

# RULE62:
if grep -rq 'automount=false' /etc/dconf/db/gdm.d/ 2>/dev/null; then
    sec_audit_report_pass 62 "GDM automount of removable media is disabled"
else
    sec_audit_report_fail 62 "GDM automount not disabled"
fi

# RULE63:
if [[ -f /etc/dconf/db/gdm.d/locks/00-screensaver ]] && grep -q automount /etc/dconf/db/gdm.d/locks/00-screensaver 2>/dev/null; then
    sec_audit_report_pass 63 "GDM automount setting is locked"
else
    sec_audit_report_fail 63 "GDM automount lock missing"
fi

# RULE278:
sec_audit__audit_rules_files_ensure
sec_audit__auditctl_l_ensure
if sec_audit_audit_rules_files_grep -q 'modules' 2>/dev/null && sec_audit_auditctl_rules_grep -q 'modules' 2>/dev/null; then
    sec_audit_report_pass 278 "audit collects events matching 'modules' (disk and loaded)"
else
    sec_audit_report_fail 278 "audit rule for 'modules' missing on disk or not loaded"
fi
}

sec_audit_run_filesystem_partitions() {
    # RULE11-36

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
    sec_audit_report_fail 12 "nodev is not set on /tmp (path not resolvable / not explicit mount)"
else
    sec_audit_report_fail 12 "nodev is not set on /tmp partition"
fi

# RULE13:
if sec_audit_findmnt_path_resolvable /tmp && sec_audit_findmnt_has_mnt_option /tmp nosuid; then
    sec_audit_report_pass 13 "nosuid option set on /tmp partition"
elif ! sec_audit_findmnt_path_resolvable /tmp; then
    sec_audit_report_fail 13 "nosuid is not set on /tmp (path not resolvable / not explicit mount)"
else
    sec_audit_report_fail 13 "nosuid is not set on /tmp partition"
fi

# RULE14:
if sec_audit_findmnt_path_resolvable /tmp && sec_audit_findmnt_has_mnt_option /tmp noexec; then
    sec_audit_report_pass 14 "noexec option set on /tmp partition"
elif ! sec_audit_findmnt_path_resolvable /tmp; then
    sec_audit_report_fail 14 "noexec is not set on /tmp (path not resolvable / not explicit mount)"
else
    sec_audit_report_fail 14 "noexec is not set on /tmp partition"
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
    sec_audit_report_fail 16 "nodev is not set on /dev/shm (path not resolvable / not explicit mount)"
else
    sec_audit_report_fail 16 "nodev is not set on /dev/shm partition"
fi

# RULE17:
if sec_audit_findmnt_path_resolvable /dev/shm && sec_audit_findmnt_has_mnt_option /dev/shm nosuid; then
    sec_audit_report_pass 17 "nosuid option set on /dev/shm partition"
elif ! sec_audit_findmnt_path_resolvable /dev/shm; then
    sec_audit_report_fail 17 "nosuid is not set on /dev/shm (path not resolvable / not explicit mount)"
else
    sec_audit_report_fail 17 "nosuid is not set on /dev/shm partition"
fi

# RULE18:
if sec_audit_findmnt_path_resolvable /dev/shm && sec_audit_findmnt_has_mnt_option /dev/shm noexec; then
    sec_audit_report_pass 18 "noexec option set on /dev/shm partition"
elif ! sec_audit_findmnt_path_resolvable /dev/shm; then
    sec_audit_report_fail 18 "noexec is not set on /dev/shm (path not resolvable / not explicit mount)"
else
    sec_audit_report_fail 18 "noexec is not set on /dev/shm partition"
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
    sec_audit_report_fail 20 "nodev is not set on /home (path not resolvable / not explicit mount)"
else
    sec_audit_report_fail 20 "nodev is not set on /home partition"
fi

# RULE21:
if sec_audit_findmnt_path_resolvable /home && sec_audit_findmnt_has_mnt_option /home nosuid; then
    sec_audit_report_pass 21 "nosuid option set on /home partition"
elif ! sec_audit_findmnt_path_resolvable /home; then
    sec_audit_report_fail 21 "nosuid is not set on /home (path not resolvable / not explicit mount)"
else
    sec_audit_report_fail 21 "nosuid is not set on /home partition"
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
    sec_audit_report_fail 23 "nodev is not set on /var (path not resolvable / not explicit mount)"
else
    sec_audit_report_fail 23 "nodev is not set on /var partition"
fi

# RULE24:
if sec_audit_findmnt_path_resolvable /var && sec_audit_findmnt_has_mnt_option /var nosuid; then
    sec_audit_report_pass 24 "nosuid option set on /var partition"
elif ! sec_audit_findmnt_path_resolvable /var; then
    sec_audit_report_fail 24 "nosuid is not set on /var (path not resolvable / not explicit mount)"
else
    sec_audit_report_fail 24 "nosuid is not set on /var partition"
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
    sec_audit_report_fail 26 "nodev is not set on /var/tmp (path not resolvable / not explicit mount)"
else
    sec_audit_report_fail 26 "nodev is not set on /var/tmp partition"
fi

# RULE27:
if sec_audit_findmnt_path_resolvable /var/tmp && sec_audit_findmnt_has_mnt_option /var/tmp nosuid; then
    sec_audit_report_pass 27 "nosuid option set on /var/tmp partition"
elif ! sec_audit_findmnt_path_resolvable /var/tmp; then
    sec_audit_report_fail 27 "nosuid is not set on /var/tmp (path not resolvable / not explicit mount)"
else
    sec_audit_report_fail 27 "nosuid is not set on /var/tmp partition"
fi

# RULE28:
if sec_audit_findmnt_path_resolvable /var/tmp && sec_audit_findmnt_has_mnt_option /var/tmp noexec; then
    sec_audit_report_pass 28 "noexec option set on /var/tmp partition"
elif ! sec_audit_findmnt_path_resolvable /var/tmp; then
    sec_audit_report_fail 28 "noexec is not set on /var/tmp (path not resolvable / not explicit mount)"
else
    sec_audit_report_fail 28 "noexec is not set on /var/tmp partition"
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
    sec_audit_report_fail 30 "nodev is not set on /var/log (path not resolvable / not explicit mount)"
else
    sec_audit_report_fail 30 "nodev is not set on /var/log partition"
fi

# RULE31:
if sec_audit_findmnt_path_resolvable /var/log && sec_audit_findmnt_has_mnt_option /var/log nosuid; then
    sec_audit_report_pass 31 "nosuid option set on /var/log partition"
elif ! sec_audit_findmnt_path_resolvable /var/log; then
    sec_audit_report_fail 31 "nosuid is not set on /var/log (path not resolvable / not explicit mount)"
else
    sec_audit_report_fail 31 "nosuid is not set on /var/log partition"
fi

# RULE32:
if sec_audit_findmnt_path_resolvable /var/log && sec_audit_findmnt_has_mnt_option /var/log noexec; then
    sec_audit_report_pass 32 "noexec option set on /var/log partition"
elif ! sec_audit_findmnt_path_resolvable /var/log; then
    sec_audit_report_fail 32 "noexec is not set on /var/log (path not resolvable / not explicit mount)"
else
    sec_audit_report_fail 32 "noexec is not set on /var/log partition"
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
    sec_audit_report_fail 34 "nodev is not set on /var/log/audit (path not resolvable / not explicit mount)"
else
    sec_audit_report_fail 34 "nodev is not set on /var/log/audit partition"
fi

# RULE35:
if sec_audit_findmnt_path_resolvable /var/log/audit && sec_audit_findmnt_has_mnt_option /var/log/audit nosuid; then
    sec_audit_report_pass 35 "nosuid option set on /var/log/audit partition"
elif ! sec_audit_findmnt_path_resolvable /var/log/audit; then
    sec_audit_report_fail 35 "nosuid is not set on /var/log/audit (path not resolvable / not explicit mount)"
else
    sec_audit_report_fail 35 "nosuid is not set on /var/log/audit partition"
fi

# RULE36:
if sec_audit_findmnt_path_resolvable /var/log/audit && sec_audit_findmnt_has_mnt_option /var/log/audit noexec; then
    sec_audit_report_pass 36 "noexec option set on /var/log/audit partition"
elif ! sec_audit_findmnt_path_resolvable /var/log/audit; then
    sec_audit_report_fail 36 "noexec is not set on /var/log/audit (path not resolvable / not explicit mount)"
else
    sec_audit_report_fail 36 "noexec is not set on /var/log/audit partition"
fi
}

sec_audit_run_accounts() {
    # RULE37-312

# RULE37:
if find /etc/apt/trusted.gpg.d/ -name '*.gpg' 2>/dev/null | grep -q . ||    find /etc/apt/keyrings/ -type f 2>/dev/null | grep -q . ||    sec_audit_apt_gpg_keys_configured; then
    sec_audit_report_pass 37 "APT GPG keys are configured"
else
    sec_audit_report_fail 37 "no trusted APT GPG keys found"
fi

# RULE38:
if sec_audit_apt_sources_configured; then
    sec_audit_report_pass 38 "APT sources.list or sources.list.d entries are configured"
else
    sec_audit_report_fail 38 "no APT repository sources configured"
fi

# RULE39:
upgradable=$(apt-get -s upgrade 2>/dev/null | grep -c "^Inst " || true)
if [ "${upgradable:-0}" -eq 0 ]; then
    sec_audit_report_pass 39 "no pending package updates (apt-get -s upgrade)"
else
    sec_audit_report_fail 39 "${upgradable} package updates pending"
fi

# RULE46:
_aslr=$(sec_audit_sysctl_key_runtime kernel.randomize_va_space)
if sec_audit_sysctl_runtime_equals kernel.randomize_va_space 2; then
    sec_audit_report_pass 46 "kernel.randomize_va_space=2 (ASLR enabled)${_aslr:+ }$(sec_audit_sysctl_runtime_disk_hint kernel.randomize_va_space 2)"
else
    sec_audit_report_fail 46 "kernel.randomize_va_space is '${_aslr:-<unset>}', expected 2$(sec_audit_sysctl_runtime_disk_hint kernel.randomize_va_space 2)"
fi

# RULE50:
if sec_audit_apport_disabled; then
    sec_audit_report_pass 50 "Automatic Error Reporting (apport) is not enabled"
else
    sec_audit_report_fail 50 "apport is installed and enabled"
fi

# RULE66:
if ! grep -qE '^\s*Enable\s*=\s*true' /etc/gdm3/custom.conf 2>/dev/null; then
    sec_audit_report_pass 66 "XDCMP is not enabled"
else
    sec_audit_report_fail 66 "XDCMP (Enable=true) found in /etc/gdm3/custom.conf"
fi

# RULE69:
if ! (sec_audit_dpkg_installed openbsd-inetd && systemctl is-active openbsd-inetd 2>/dev/null | grep -q '^active$') && \
   ! (sec_audit_dpkg_installed xinetd && systemctl is-active xinetd 2>/dev/null | grep -q '^active$'); then
    sec_audit_report_pass 69 "chargen/inetd services are not in use"
else
    sec_audit_report_fail 69 "chargen-related inetd/xinetd service is active"
fi

# RULE70:
sec_audit_assert_service_unused 70 bind "dns server services are not in use" "dns server services are installed and enabled or actively running" "named.service"

# RULE71:
sec_audit_assert_service_unused 71 dnsmasq "dnsmasq services are not in use" "dnsmasq services are installed and enabled or actively running" "dnsmasq.service"

# RULE72:
sec_audit_assert_service_unused 72 vsftpd "ftp server services are not in use" "ftp server services are installed and enabled or actively running" "vsftpd.service"

# RULE73:
if ! sec_audit_dpkg_installed slapd; then
    sec_audit_report_pass 73 "LDAP server (slapd) is not installed"
else
    sec_audit_report_fail 73 "LDAP server (slapd) package is installed"
fi

# RULE75:
sec_audit_assert_service_unused 75 nfs-utils "network file system services are not in use" "network file system services are installed and enabled or actively running" "nfs-server.service"

# RULE76:
if ! sec_audit_dpkg_installed nis; then
    sec_audit_report_pass 76 "NIS server is not installed"
else
    sec_audit_report_fail 76 "NIS server package is installed"
fi

# RULE77:
sec_audit_assert_service_unused 77 cups "print server services are not in use" "print server services are installed and enabled or actively running" "cups.socket" "cups.service"

# RULE78:
sec_audit_assert_service_unused 78 rpcbind "rpcbind services are not in use" "rpcbind services are installed and enabled or actively running" "rpcbind.socket" "rpcbind.service"

# RULE79:
sec_audit_assert_service_unused 79 rsync-daemon "rsync services are not in use" "rsync services are installed and enabled or actively running" "rsyncd.socket" "rsyncd.service"

# RULE80:
sec_audit_assert_service_unused 80 samba "samba file server services are not in use" "samba file server services are installed and enabled or actively running" "smb.service"

# RULE81:
sec_audit_assert_service_unused 81 net-snmp "snmp services are not in use" "snmp services are installed and enabled or actively running" "snmpd.service"

# RULE83:
sec_audit_assert_service_unused 83 squid "web proxy server services are not in use" "web proxy server services are installed and enabled or actively running" "squid.service"

# RULE87:
if sec_audit_mail_local_only; then
    sec_audit_report_pass 87 "mail transfer agent is local-only or not listening on :25"
else
    sec_audit_report_fail 87 "MTA listens on non-loopback interface"
fi

# RULE94:
if ! sec_audit_dpkg_installed ftp; then
    sec_audit_report_pass 94 "FTP client is not installed"
else
    sec_audit_report_fail 94 "FTP client package is installed"
fi

# RULE112:
if sec_audit_have_bin nmcli && nmcli radio wifi 2>/dev/null | grep -q disabled; then
    sec_audit_report_pass 112 "wireless interfaces are disabled (nmcli)"
elif ! sec_audit_have_bin nmcli; then
    sec_audit_report_pass 112 "nmcli not available (verify wireless disabled manually)"
else
    sec_audit_report_fail 112 "wireless may still be enabled"
fi

# RULE124:
sec_audit_sysctl_multi_rule 124 "reverse path filtering enabled" "rp_filter not enabled" \
    net.ipv4.conf.all.rp_filter 1 net.ipv4.conf.default.rp_filter 1

# RULE184:
if ! grep -qE '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
    sec_audit_report_pass 184 "no NOPASSWD in sudoers"
else
    sec_audit_report_fail 184 "NOPASSWD entries found"
fi

# RULE187:
if grep -q pam_wheel /etc/pam.d/su 2>/dev/null && [[ -f /etc/security/access.conf ]]; then
    sec_audit_report_pass 187 "su restricted (pam_wheel)"
else
    sec_audit_report_fail 187 "su not restricted via pam_wheel"
fi

# RULE196:
sec_audit__sshd_t_ensure
lg=$(sec_audit_sshd_t_grep -i logingracetime 2>/dev/null | awk '{print $2}' | head -n1)
if [[ -n $lg && $lg -le 60 ]]; then sec_audit_report_pass 196 "LoginGraceTime $lg"; else sec_audit_report_fail 196 "LoginGraceTime >60"; fi

# RULE198:
if grep -q difok /etc/security/pwquality.conf /etc/pam.d/common-password 2>/dev/null; then sec_audit_report_pass 198 "difok configured"; else sec_audit_report_fail 198 "difok missing"; fi

# RULE201:
if grep -q maxrepeat /etc/security/pwquality.conf 2>/dev/null; then sec_audit_report_pass 201 "maxrepeat configured"; else sec_audit_report_fail 201 "maxrepeat missing"; fi

# RULE202:
if grep -q pam_pwquality /etc/pam.d/common-password 2>/dev/null && grep -qE '^[[:space:]]*minlen[[:space:]]*=' /etc/security/pwquality.conf 2>/dev/null; then
    sec_audit_report_pass 202 "password creation requirements configured"
else
    sec_audit_report_fail 202 "pam_pwquality/minlen missing"
fi

# RULE203:
if grep -q dictcheck /etc/security/pwquality.conf 2>/dev/null; then sec_audit_report_pass 203 "dictcheck enabled"; else sec_audit_report_fail 203 "dictcheck missing"; fi

# RULE213:
if grep -q pam_pwquality /etc/pam.d/common-password 2>/dev/null && grep -qE '^[[:space:]]*minlen[[:space:]]*=' /etc/security/pwquality.conf 2>/dev/null; then
    sec_audit_report_pass 213 "password creation requirements configured"
else
    sec_audit_report_fail 213 "pam_pwquality/minlen missing"
fi

# RULE214:
if grep -Psi '^\h*PASS_MIN_DAYS\h+([1-9]|[1-9][0-9]+)\b' /etc/login.defs 2>/dev/null; then
    sec_audit_report_pass 214 "PASS_MIN_DAYS configured in /etc/login.defs"
else
    sec_audit_report_fail 214 "PASS_MIN_DAYS not configured in /etc/login.defs"
fi

# RULE215:
v=$(grep -E '^PASS_WARN_AGE' /etc/login.defs | awk '{print $2}' | head -n1)
if [[ -n $v && $v -ge 7 ]]; then sec_audit_report_pass 215 "PASS_WARN_AGE $v"; else sec_audit_report_fail 215 "PASS_WARN_AGE <7"; fi

# RULE217:
inac=$(useradd -D 2>/dev/null | awk -F= '/INACTIVE/{print $2}')
if [[ -n $inac && $inac -le 30 ]]; then sec_audit_report_pass 217 "INACTIVE $inac"; else sec_audit_report_fail 217 "inactive lock >30 days"; fi

# RULE218:
if [ ! -r /etc/shadow ]; then
    sec_audit_report_skip 218 "cannot read /etc/shadow (needs root)"
else
fail=0
while IFS=: read -r u _ lc _; do
    [[ -n $lc && $lc -gt 0 ]] 2>/dev/null || continue
    now=$(date +%s); lcs=$((lc * 86400))
    [[ $lcs -gt $now ]] && fail=1
done < /etc/shadow
if [ $fail -eq 0 ]; then sec_audit_report_pass 218 "password change dates not in future"; else sec_audit_report_fail 218 "future password change date found"; fi
fi

# RULE219:
if [ "$(awk -F: '($3==0){c++} END{print c+0}' /etc/passwd)" -eq 1 ]; then sec_audit_report_pass 219 "only one UID 0 account"; else sec_audit_report_fail 219 "multiple UID 0 accounts"; fi

# RULE220:
if [ "$(awk -F: '($3==0){c++} END{print c+0}' /etc/passwd)" -eq 1 ]; then sec_audit_report_pass 220 "only one GID 0 account"; else sec_audit_report_fail 220 "multiple GID 0 accounts"; fi

# RULE221:
if [ "$(awk -F: '($3==0){c++} END{print c+0}' /etc/group)" -eq 1 ]; then sec_audit_report_pass 221 "only root GID 0 group"; else sec_audit_report_fail 221 "multiple GID 0 groups"; fi

# RULE222:
if grep -qE '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so' /etc/pam.d/su 2>/dev/null; then sec_audit_report_pass 222 "root/su access controlled"; else sec_audit_report_fail 222 "pam_wheel not restricting su"; fi

# RULE224:
if grep -qE '^[[:space:]]*umask[[:space:]]+0?27' /root/.bashrc /root/.profile 2>/dev/null; then sec_audit_report_pass 224 "root umask 027"; else sec_audit_report_fail 224 "root umask not 027"; fi

# RULE225:
if awk -F: '($1!~/^(root|sync|halt|shutdown)$/ && $3<1000 && $7!~/nologin|false/){exit 1}' /etc/passwd; then sec_audit_report_pass 225 "system accounts use nologin shells"; else sec_audit_report_fail 225 "system accounts with login shells"; fi

# RULE226:
if [ ! -r /etc/shadow ]; then sec_audit_report_skip 226 "cannot read /etc/shadow (needs root)"; elif awk -F: '($2=="" || $2=="!"){c++} END{exit(c?0:1)}' /etc/shadow; then sec_audit_report_pass 226 "accounts without shell locked in shadow"; else sec_audit_report_fail 226 "unlocked accounts without valid shell"; fi

# RULE227:
if ! grep -E '/(nologin|false)$' /etc/shells 2>/dev/null | grep -q .; then
    sec_audit_report_pass 227 "nologin not in /etc/shells"
else
    sec_audit_report_fail 227 "nologin listed in /etc/shells"
fi

# RULE228:
if grep -rE '^[[:space:]]*TMOUT=' /etc/profile /etc/profile.d/*.sh 2>/dev/null | grep -q .; then
    sec_audit_report_pass 228 "TMOUT configured"
else
    sec_audit_report_fail 228 "TMOUT not configured"
fi

# RULE229:
if grep -rE '^[[:space:]]*TMOUT=' /etc/profile /etc/profile.d/*.sh 2>/dev/null | grep -q .; then
    sec_audit_report_pass 229 "TMOUT configured"
else
    sec_audit_report_fail 229 "TMOUT not configured"
fi

# RULE231:
if grep -Ers '^([^#]+\s+)?(/usr/s?bin/|^[[:space:]]*)aide([[:space:]]|$)' /etc/cron.* /etc/crontab /var/spool/cron /etc/cron.d 2>/dev/null | grep -q .; then
    sec_audit_report_pass 231 "filesystem integrity is regularly checked (cron)"
elif systemctl is-enabled aidecheck.timer 2>/dev/null | grep -q enabled; then
    sec_audit_report_pass 231 "aidecheck.timer is enabled"
else
    sec_audit_report_fail 231 "no regular AIDE check schedule found"
fi

# RULE232:
if sec_audit_have_bin debsums && debsums -c auditd 2>/dev/null | grep -q .; then
    sec_audit_report_fail 232 "auditd package files changed (verify integrity)"
else
    sec_audit_report_pass 232 "audit tool package integrity OK (or debsums unavailable)"
fi

# RULE261:
sec_audit__audit_rules_files_ensure
sec_audit__auditctl_l_ensure
if sec_audit_audit_rules_files_grep -q 'execve' 2>/dev/null && sec_audit_auditctl_rules_grep -q 'execve' 2>/dev/null; then
    sec_audit_report_pass 261 "audit collects events matching 'execve' (disk and loaded)"
else
    sec_audit_report_fail 261 "audit rule for 'execve' missing on disk or not loaded"
fi

# RULE263:
sec_audit__audit_rules_files_ensure
sec_audit__auditctl_l_ensure
if sec_audit_audit_rules_files_grep -q 'time-change' 2>/dev/null && sec_audit_auditctl_rules_grep -q 'time-change' 2>/dev/null; then
    sec_audit_report_pass 263 "audit collects events matching 'time-change' (disk and loaded)"
else
    sec_audit_report_fail 263 "audit rule for 'time-change' missing on disk or not loaded"
fi

# RULE265:
sec_audit__audit_rules_files_ensure
sec_audit__auditctl_l_ensure
if sec_audit_audit_rules_files_grep -q 'privileged' 2>/dev/null && sec_audit_auditctl_rules_grep -q 'privileged' 2>/dev/null; then
    sec_audit_report_pass 265 "audit collects events matching 'privileged' (disk and loaded)"
else
    sec_audit_report_fail 265 "audit rule for 'privileged' missing on disk or not loaded"
fi

# RULE266:
sec_audit__audit_rules_files_ensure
sec_audit__auditctl_l_ensure
if sec_audit_audit_rules_files_grep -q 'access' 2>/dev/null && sec_audit_auditctl_rules_grep -q 'access' 2>/dev/null; then
    sec_audit_report_pass 266 "audit collects events matching 'access' (disk and loaded)"
else
    sec_audit_report_fail 266 "audit rule for 'access' missing on disk or not loaded"
fi

# RULE267:
sec_audit__audit_rules_files_ensure
sec_audit__auditctl_l_ensure
if sec_audit_audit_rules_files_grep -q 'identity' 2>/dev/null && sec_audit_auditctl_rules_grep -q 'identity' 2>/dev/null; then
    sec_audit_report_pass 267 "audit collects events matching 'identity' (disk and loaded)"
else
    sec_audit_report_fail 267 "audit rule for 'identity' missing on disk or not loaded"
fi

# RULE268:
sec_audit__audit_rules_files_ensure
sec_audit__auditctl_l_ensure
if sec_audit_audit_rules_files_grep -q 'perm_mod' 2>/dev/null && sec_audit_auditctl_rules_grep -q 'perm_mod' 2>/dev/null; then
    sec_audit_report_pass 268 "audit collects events matching 'perm_mod' (disk and loaded)"
else
    sec_audit_report_fail 268 "audit rule for 'perm_mod' missing on disk or not loaded"
fi

# RULE269:
sec_audit__audit_rules_files_ensure
sec_audit__auditctl_l_ensure
if sec_audit_audit_rules_files_grep -q 'mounts' 2>/dev/null && sec_audit_auditctl_rules_grep -q 'mounts' 2>/dev/null; then
    sec_audit_report_pass 269 "audit collects events matching 'mounts' (disk and loaded)"
else
    sec_audit_report_fail 269 "audit rule for 'mounts' missing on disk or not loaded"
fi

# RULE270:
sec_audit__audit_rules_files_ensure
sec_audit__auditctl_l_ensure
if sec_audit_audit_rules_files_grep -q 'session' 2>/dev/null && sec_audit_auditctl_rules_grep -q 'session' 2>/dev/null; then
    sec_audit_report_pass 270 "audit collects events matching 'session' (disk and loaded)"
else
    sec_audit_report_fail 270 "audit rule for 'session' missing on disk or not loaded"
fi

# RULE271:
sec_audit__audit_rules_files_ensure
sec_audit__auditctl_l_ensure
if sec_audit_audit_rules_files_grep -q 'logins' 2>/dev/null && sec_audit_auditctl_rules_grep -q 'logins' 2>/dev/null; then
    sec_audit_report_pass 271 "audit collects events matching 'logins' (disk and loaded)"
else
    sec_audit_report_fail 271 "audit rule for 'logins' missing on disk or not loaded"
fi

# RULE272:
sec_audit__audit_rules_files_ensure
sec_audit__auditctl_l_ensure
if sec_audit_audit_rules_files_grep -q 'delete' 2>/dev/null && sec_audit_auditctl_rules_grep -q 'delete' 2>/dev/null; then
    sec_audit_report_pass 272 "audit collects events matching 'delete' (disk and loaded)"
else
    sec_audit_report_fail 272 "audit rule for 'delete' missing on disk or not loaded"
fi

# RULE273:
sec_audit__audit_rules_files_ensure
sec_audit__auditctl_l_ensure
if sec_audit_audit_rules_files_grep -q 'MAC-policy' 2>/dev/null && sec_audit_auditctl_rules_grep -q 'MAC-policy' 2>/dev/null; then
    sec_audit_report_pass 273 "audit collects events matching 'MAC-policy' (disk and loaded)"
else
    sec_audit_report_fail 273 "audit rule for 'MAC-policy' missing on disk or not loaded"
fi

# RULE274:
sec_audit__audit_rules_files_ensure
sec_audit__auditctl_l_ensure
if sec_audit_audit_rules_files_grep -q 'chcon' 2>/dev/null && sec_audit_auditctl_rules_grep -q 'chcon' 2>/dev/null; then
    sec_audit_report_pass 274 "audit collects events matching 'chcon' (disk and loaded)"
else
    sec_audit_report_fail 274 "audit rule for 'chcon' missing on disk or not loaded"
fi

# RULE275:
sec_audit__audit_rules_files_ensure
sec_audit__auditctl_l_ensure
if sec_audit_audit_rules_files_grep -q 'setfacl' 2>/dev/null && sec_audit_auditctl_rules_grep -q 'setfacl' 2>/dev/null; then
    sec_audit_report_pass 275 "audit collects events matching 'setfacl' (disk and loaded)"
else
    sec_audit_report_fail 275 "audit rule for 'setfacl' missing on disk or not loaded"
fi

# RULE276:
sec_audit__audit_rules_files_ensure
sec_audit__auditctl_l_ensure
if sec_audit_audit_rules_files_grep -q 'chacl' 2>/dev/null && sec_audit_auditctl_rules_grep -q 'chacl' 2>/dev/null; then
    sec_audit_report_pass 276 "audit collects events matching 'chacl' (disk and loaded)"
else
    sec_audit_report_fail 276 "audit rule for 'chacl' missing on disk or not loaded"
fi

# RULE277:
sec_audit__audit_rules_files_ensure
sec_audit__auditctl_l_ensure
if sec_audit_audit_rules_files_grep -q 'usermod' 2>/dev/null && sec_audit_auditctl_rules_grep -q 'usermod' 2>/dev/null; then
    sec_audit_report_pass 277 "audit collects events matching 'usermod' (disk and loaded)"
else
    sec_audit_report_fail 277 "audit rule for 'usermod' missing on disk or not loaded"
fi

# RULE280:
sec_audit__auditctl_l_ensure
sec_audit__audit_rules_files_ensure
_diff=$(diff <(printf '%s\n' "$_auditctl_l_cache" | sort) <(augenrules --check 2>/dev/null | sort) 2>/dev/null | head -5)
if [ -z "$_diff" ] && [ -n "$_auditctl_l_cache" ]; then
    sec_audit_report_pass 280 "running audit rules match augenrules on-disk configuration"
else
    sec_audit_report_fail 280 "running vs on-disk audit rules differ"
fi

# RULE303:
n=$(sec_audit__find_perm_count "-type f \( -perm -4000 -o -perm -2000 \)")
if [ "${n:-0}" -eq 0 ]; then
    sec_audit_report_pass 303 "no SUID/SGID files found (sample scan)"
else
    sec_audit_report_fail 303 "found ${n} SUID/SGID files requiring review"
fi

# RULE304:
if ! awk -F: '($2 != "x"){exit 1}' /etc/passwd; then sec_audit_report_pass 304 "shadowed passwords"; else sec_audit_report_fail 304 "non-shadowed passwd entries"; fi

# RULE305:
if [ ! -r /etc/shadow ]; then sec_audit_report_skip 305 "cannot read /etc/shadow (needs root)"; elif ! awk -F: '($2==""){print}' /etc/shadow | grep -q .; then sec_audit_report_pass 305 "no empty shadow passwords"; else sec_audit_report_fail 305 "empty shadow password fields"; fi

# RULE306:
fail=0
for g in $(awk -F: '{print $4}' /etc/passwd | sort -u); do grep -q ":$g:" /etc/group || fail=1; done
if [ $fail -eq 0 ]; then sec_audit_report_pass 306 "all passwd groups exist"; else sec_audit_report_fail 306 "orphan group IDs in passwd"; fi

# RULE307:
if ! awk -F: '($1=="shadow"){print $NF}' /etc/group | grep -q .; then sec_audit_report_pass 307 "shadow group empty"; else sec_audit_report_fail 307 "shadow group has members"; fi

# RULE308:
if ! cut -f3 -d: /etc/passwd | sort | uniq -d | grep -q .; then sec_audit_report_pass 308 "no duplicate UIDs"; else sec_audit_report_fail 308 "duplicate UIDs"; fi

# RULE309:
if ! cut -f3 -d: /etc/group | sort | uniq -d | grep -q .; then sec_audit_report_pass 309 "no duplicate GIDs"; else sec_audit_report_fail 309 "duplicate GIDs"; fi

# RULE312:
fail=0
while IFS=: read -r u _ uid _ home shell; do
    [[ $uid -ge 1000 ]] || continue
    [[ $shell == *nologin* || $shell == *false* ]] && continue
    [[ -d $home ]] || fail=1
done < /etc/passwd
if [ $fail -eq 0 ]; then sec_audit_report_pass 312 "interactive user home dirs exist"; else sec_audit_report_fail 312 "missing home directories"; fi
}

sec_audit_run_apparmor() {
    # RULE40-43

# RULE40:
if sec_audit_dpkg_installed apparmor || sec_audit_dpkg_installed apparmor-utils; then
    sec_audit_report_pass 40 "AppArmor packages are installed"
else
    sec_audit_report_fail 40 "AppArmor packages are not installed"
fi

# RULE41:
if sec_audit_apparmor_bootloader_enabled; then
    sec_audit_report_pass 41 "AppArmor enabled in bootloader (apparmor=1 security=apparmor)"
else
    sec_audit_report_fail 41 "AppArmor not enabled in bootloader configuration"
fi

# RULE42:
if sec_audit_apparmor_profiles_enforce_or_complain; then
    sec_audit_report_pass 42 "all AppArmor profiles are in enforce or complain mode"
else
    sec_audit_report_fail 42 "some AppArmor profiles are not in enforce or complain mode"
fi

# RULE43:
if sec_audit_apparmor_all_enforcing; then
    sec_audit_report_pass 43 "all AppArmor profiles are enforcing"
else
    sec_audit_report_fail 43 "not all AppArmor profiles are in enforce mode"
fi
}

sec_audit_run_bootloader() {
    # RULE44-45

# RULE44:
if sec_audit_grub_cfg_grep '^[[:space:]]*set superusers' && sec_audit_grub_cfg_grep 'password_pbkdf2'; then
    sec_audit_report_pass 44 "bootloader password is set (grub.cfg under /boot/grub2 or EFI)"
else
    sec_audit_report_fail 44 "GRUB bootloader superuser/password_pbkdf2 is not configured as required in grub.cfg"
fi

# RULE45:
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
    sec_audit_report_pass 45 "access to bootloader config is configured"
else
    sec_audit_report_fail 45 "/boot/grub2/grub.cfg (or EFI grub.cfg) owner/mode is not root:root with mode 600"
fi
}

sec_audit_run_process_hardening() {
    # RULE47-49

# RULE47:
_ptrace=$(sec_audit_sysctl_key_runtime kernel.yama.ptrace_scope)
if sec_audit_sysctl_runtime_matches_regex kernel.yama.ptrace_scope '^[123]$'; then
    sec_audit_report_pass 47 "kernel.yama.ptrace_scope is restricted (${_ptrace})$(sec_audit_sysctl_runtime_disk_hint kernel.yama.ptrace_scope 1)"
else
    sec_audit_report_fail 47 "kernel.yama.ptrace_scope is '${_ptrace:-<unset>}', expected 1, 2, or 3"
fi

# RULE48:
if sec_audit_limits_core_zero_and_systemd_ok && sec_audit_sysctl_runtime_equals fs.suid_dumpable 0; then
    sec_audit_report_pass 48 "core dumps restricted (* hard core 0 and fs.suid_dumpable=0)"
else
    sec_audit_report_fail 48 "core dumps not fully restricted"
fi

# RULE49:
if ! sec_audit_dpkg_installed prelink; then
    sec_audit_report_pass 49 "prelink is not installed"
else
    sec_audit_report_fail 49 "prelink package is installed"
fi
}

sec_audit_run_banners() {
    # RULE51-61

# RULE51:
if grep -Psi "(\\v|\\r|\\m|\\s|$(grep ^ID= /etc/os-release 2>/dev/null | cut -d= -f2 | sed 's/"//g'))" /etc/motd 2>/dev/null | grep -q .; then
    sec_audit_report_pass 51 "login warning banner configured in /etc/motd"
else
    sec_audit_report_fail 51 "/etc/motd missing required banner content"
fi

# RULE52:
if grep -Psi "(\\v|\\r|\\m|\\s|$(grep ^ID= /etc/os-release 2>/dev/null | cut -d= -f2 | sed 's/"//g'))" /etc/issue 2>/dev/null | grep -q .; then
    sec_audit_report_pass 52 "login warning banner configured in /etc/issue"
else
    sec_audit_report_fail 52 "/etc/issue missing required banner content"
fi

# RULE53:
if grep -Psi "(\\v|\\r|\\m|\\s|$(grep ^ID= /etc/os-release 2>/dev/null | cut -d= -f2 | sed 's/"//g'))" /etc/issue.net 2>/dev/null | grep -q .; then
    sec_audit_report_pass 53 "login warning banner configured in /etc/issue.net"
else
    sec_audit_report_fail 53 "/etc/issue.net missing required banner content"
fi

# RULE54:
p=$(stat -c %a /etc/motd 2>/dev/null); o=$(stat -c %U /etc/motd 2>/dev/null); g=$(stat -c %G /etc/motd 2>/dev/null)
if [[ -n $p && $p -le 644 && $o == root && $g == root ]]; then
    sec_audit_report_pass 54 "/etc/motd permissions $p root:root"
else
    sec_audit_report_fail 54 "/etc/motd permissions/ownership incorrect ($p $o:$g)"
fi

# RULE55:
p=$(stat -c %a /etc/issue 2>/dev/null); o=$(stat -c %U /etc/issue 2>/dev/null); g=$(stat -c %G /etc/issue 2>/dev/null)
if [[ -n $p && $p -le 644 && $o == root && $g == root ]]; then
    sec_audit_report_pass 55 "/etc/issue permissions $p root:root"
else
    sec_audit_report_fail 55 "/etc/issue permissions/ownership incorrect ($p $o:$g)"
fi

# RULE56:
p=$(stat -c %a /etc/issue.net 2>/dev/null); o=$(stat -c %U /etc/issue.net 2>/dev/null); g=$(stat -c %G /etc/issue.net 2>/dev/null)
if [[ -n $p && $p -le 644 && $o == root && $g == root ]]; then
    sec_audit_report_pass 56 "/etc/issue.net permissions $p root:root"
else
    sec_audit_report_fail 56 "/etc/issue.net permissions/ownership incorrect ($p $o:$g)"
fi

# RULE57:
if ! sec_audit_dpkg_installed gdm3 && ! sec_audit_dpkg_installed gdm; then
    sec_audit_report_pass 57 "GNOME Display Manager is not installed"
else
    sec_audit_report_fail 57 "GDM package is still installed"
fi

# RULE58:
if grep -qE '^\[daemon\]' /etc/gdm3/greeter.dconf-defaults 2>/dev/null && \
   grep -qE 'banner-message-enable=true' /etc/gdm3/greeter.dconf-defaults 2>/dev/null; then
    sec_audit_report_pass 58 "GDM login banner is configured"
else
    sec_audit_report_fail 58 "GDM login banner not configured in greeter.dconf-defaults"
fi

# RULE59:
if grep -rq 'disable-user-list=true' /etc/dconf/db/gdm.d/ /etc/gdm3/ 2>/dev/null; then
    sec_audit_report_pass 59 "GDM disable-user-list is enabled"
else
    sec_audit_report_fail 59 "GDM disable-user-list not enabled"
fi

# RULE60:
if grep -q 'idle-delay=uint32 900' /etc/gdm3/greeter.dconf-defaults 2>/dev/null || \
   grep -rq 'idle-delay' /etc/dconf/db/gdm.d/ 2>/dev/null; then
    sec_audit_report_pass 60 "GDM screen locks when user is idle"
else
    sec_audit_report_fail 60 "GDM idle-delay not configured (900s)"
fi

# RULE61:
if grep -rq 'lock-enabled=true' /etc/dconf/db/gdm.d/ 2>/dev/null; then
    sec_audit_report_pass 61 "GDM screen lock cannot be overridden"
else
    sec_audit_report_fail 61 "GDM lock-enabled not set in dconf gdm database"
fi
}

sec_audit_run_gdm() {
    # RULE64-65

# RULE64:
if grep -rq 'autorun-never=true' /etc/dconf/db/gdm.d/ 2>/dev/null; then
    sec_audit_report_pass 64 "GDM autorun-never is enabled"
else
    sec_audit_report_fail 64 "GDM autorun-never not enabled"
fi

# RULE65:
if [[ -f /etc/dconf/db/gdm.d/locks/00-screensaver ]] && grep -q autorun-never /etc/dconf/db/gdm.d/locks/00-screensaver 2>/dev/null; then
    sec_audit_report_pass 65 "GDM autorun-never is locked"
else
    sec_audit_report_fail 65 "GDM autorun-never lock missing"
fi
}

sec_audit_run_unused_services() {
    # RULE67-239

# RULE67:
sec_audit_assert_service_unused 67 autofs "autofs services are not in use" "autofs services are installed and enabled or actively running" "autofs.service"

# RULE68:
sec_audit_assert_service_unused 68 avahi "avahi daemon services are not in use" "avahi daemon services are installed and enabled or actively running" "avahi-daemon.socket" "avahi-daemon.service"

# RULE74:
if sec_audit_pkg_any_installed dovecot cyrus-imapd; then
    if sec_audit_systemd_unit_enabled_or_active dovecot.socket dovecot.service cyrus-imapd.service; then
        sec_audit_report_fail 74 "message access server services are installed and enabled or actively running"
    else
        sec_audit_report_pass 74 "message access server services are not in use (package present but units masked/disabled/inactive)"
    fi
else
    sec_audit_report_pass 74 "message access server services are not in use"
fi

# RULE84:
if sec_audit_pkg_any_installed httpd nginx; then
    if sec_audit_systemd_unit_enabled_or_active httpd.service nginx.service; then
        sec_audit_report_fail 84 "web server services are installed and enabled or actively running"
    else
        sec_audit_report_pass 84 "web server services are not in use (package present but units masked/disabled/inactive)"
    fi
else
    sec_audit_report_pass 84 "web server services are not in use"
fi

# RULE85:
if ! sec_audit_dpkg_installed xinetd; then
    sec_audit_report_pass 85 "xinetd is not installed"
else
    sec_audit_report_fail 85 "xinetd package is installed"
fi

# RULE86:
if ! dpkg-query -W 'xserver-xorg*' 2>/dev/null | grep -q 'install ok installed'; then
    sec_audit_report_pass 86 "X Window System is not installed"
else
    sec_audit_report_fail 86 "X Window System packages are installed"
fi

# RULE88:
_cnt=$(ss -lntu 2>/dev/null | tail -n +2 | wc -l)
if [ "${_cnt:-0}" -gt 0 ]; then
    sec_audit_report_pass 88 "listening services enumerated (${_cnt} sockets)"
else
    sec_audit_report_fail 88 "cannot enumerate listening services"
fi

# RULE113:
sec_audit_assert_service_unused 113 bluez "bluetooth services are not in use" "bluetooth services are installed and enabled or actively running" "bluetooth.service"

# RULE131:
if sec_audit_dpkg_installed nftables && systemctl is-active nftables 2>/dev/null | grep -q '^active$'; then
    sec_audit_report_fail 131 "nftables is active alongside iptables path"
else
    sec_audit_report_pass 131 "nftables is not active with iptables"
fi

# RULE132:
if sec_audit_dpkg_installed iptables-persistent; then sec_audit_report_fail 132 "iptables-persistent installed with ufw"; else sec_audit_report_pass 132 "iptables-persistent not installed with ufw"; fi

# RULE149:
if sec_audit_dpkg_installed nftables && systemctl is-active nftables 2>/dev/null | grep -q '^active$'; then
    sec_audit_report_fail 149 "nftables is active alongside iptables path"
else
    sec_audit_report_pass 149 "nftables is not active with iptables"
fi

# RULE150:
if sec_audit_dpkg_installed nftables && systemctl is-active nftables 2>/dev/null | grep -q '^active$'; then
    sec_audit_report_fail 150 "nftables is active alongside iptables path"
else
    sec_audit_report_pass 150 "nftables is not active with iptables"
fi

# RULE239:
if ! systemctl is-active systemd-journal-remote.socket 2>/dev/null | grep -q '^active$'; then
    sec_audit_report_pass 239 "systemd-journal-remote socket is not active"
else
    sec_audit_report_fail 239 "systemd-journal-remote socket is active"
fi
}

sec_audit_run_network_stack() {
    # RULE82-264

# RULE82:
sec_audit_assert_service_unused 82 tftp-server "tftp server services are not in use" "tftp server services are installed and enabled or actively running" "tftp.socket" "tftp.service"

# RULE111:
if [ -f /proc/sys/net/ipv6/conf/all/disable_ipv6 ]; then
    _v=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null)
    sec_audit_report_pass 111 "IPv6 status identified (disable_ipv6=${_v})"
else
    sec_audit_report_fail 111 "cannot determine IPv6 status"
fi

# RULE114:
sec_audit_check_kernel_mod_rule 114 dccp "dccp.ko*"

# RULE115:
sec_audit_check_kernel_mod_rule 115 sctp "sctp.ko*"

# RULE116:
sec_audit_check_kernel_mod_rule 116 rds "rds.ko*"

# RULE117:
sec_audit_check_kernel_mod_rule 117 tipc "tipc.ko*"

# RULE118:
sec_audit_assert_sysctl_equals 118 net.ipv4.ip_forward 0

# RULE119:
sec_audit_sysctl_multi_rule 119 "packet redirect sending disabled" "send_redirects not disabled" \
    net.ipv4.conf.all.send_redirects 0 net.ipv4.conf.default.send_redirects 0

# RULE120:
sec_audit_assert_sysctl_equals 120 net.ipv4.icmp_ignore_bogus_error_responses 1

# RULE121:
sec_audit_assert_sysctl_equals 121 net.ipv4.icmp_echo_ignore_broadcasts 1

# RULE122:
sec_audit_sysctl_multi_rule 122 "ICMP redirects not accepted" "accept_redirects not disabled" \
    net.ipv4.conf.all.accept_redirects 0 net.ipv4.conf.default.accept_redirects 0

# RULE125:
sec_audit_sysctl_multi_rule 125 "source routed packets not accepted" "accept_source_route not disabled" \
    net.ipv4.conf.all.accept_source_route 0 net.ipv4.conf.default.accept_source_route 0

# RULE126:
sec_audit_sysctl_multi_rule 126 "suspicious packets logged" "log_martians not enabled" \
    net.ipv4.conf.all.log_martians 1 net.ipv4.conf.default.log_martians 1

# RULE127:
sec_audit_assert_sysctl_equals 127 net.ipv4.tcp_syncookies 1

# RULE128:
sec_audit_sysctl_multi_rule 128 "IPv6 router advertisements not accepted" "IPv6 accept_ra not disabled" \
    net.ipv6.conf.all.accept_ra 0 net.ipv6.conf.default.accept_ra 0

# RULE264:
sec_audit__audit_rules_files_ensure
sec_audit__auditctl_l_ensure
if sec_audit_audit_rules_files_grep -q 'network' 2>/dev/null && sec_audit_auditctl_rules_grep -q 'network' 2>/dev/null; then
    sec_audit_report_pass 264 "audit collects events matching 'network' (disk and loaded)"
else
    sec_audit_report_fail 264 "audit rule for 'network' missing on disk or not loaded"
fi
}

sec_audit_run_client_tools() {
    # RULE89-93

# RULE89:
if systemctl is-active "ypbind" &>/dev/null 2>&1 || sec_audit_dpkg_installed nis; then
    sec_audit_report_fail 89 "NIS Client is installed or active"
else
    sec_audit_report_pass 89 "NIS Client is not in use"
fi

# RULE90:
if systemctl is-active "rsh" &>/dev/null 2>&1 || sec_audit_dpkg_installed rsh-client; then
    sec_audit_report_fail 90 "rsh client is installed or active"
else
    sec_audit_report_pass 90 "rsh client is not in use"
fi

# RULE91:
if systemctl is-active "talk" &>/dev/null 2>&1 || sec_audit_dpkg_installed talk; then
    sec_audit_report_fail 91 "talk client is installed or active"
else
    sec_audit_report_pass 91 "talk client is not in use"
fi

# RULE92:
if systemctl is-active "telnet" &>/dev/null 2>&1 || sec_audit_dpkg_installed telnet; then
    sec_audit_report_fail 92 "telnet client is installed or active"
else
    sec_audit_report_pass 92 "telnet client is not in use"
fi

# RULE93:
if systemctl is-active "ldap" &>/dev/null 2>&1 || sec_audit_dpkg_installed ldap-utils; then
    sec_audit_report_fail 93 "LDAP client is installed or active"
else
    sec_audit_report_pass 93 "LDAP client is not in use"
fi
}

sec_audit_run_chrony() {
    # RULE95-100

# RULE95:
_ts=0
for u in systemd-timesyncd chrony ntp; do
    systemctl is-active "$u" 2>/dev/null | grep -q '^active$' && _ts=$((_ts + 1))
done
if [ "$_ts" -eq 1 ]; then
    sec_audit_report_pass 95 "exactly one time synchronization daemon is active"
else
    sec_audit_report_fail 95 "expected one active time sync daemon, found $_ts active"
fi

# RULE96:
if grep -qE '^NTP=' /etc/systemd/timesyncd.conf 2>/dev/null; then
    sec_audit_report_pass 96 "systemd-timesyncd NTP servers configured"
elif ! systemctl is-active systemd-timesyncd &>/dev/null; then
    sec_audit_report_pass 96 "systemd-timesyncd not active"
else
    sec_audit_report_fail 96 "systemd-timesyncd active but NTP= not set"
fi

# RULE97:
if systemctl is-enabled systemd-timesyncd 2>/dev/null | grep -q enabled && systemctl is-active systemd-timesyncd 2>/dev/null | grep -q '^active$'; then
    sec_audit_report_pass 97 "systemd-timesyncd is enabled and running"
elif ! sec_audit_dpkg_installed systemd-timesyncd; then
    sec_audit_report_pass 97 "systemd-timesyncd not installed (another time sync stack may be used)"
else
    sec_audit_report_fail 97 "systemd-timesyncd is not enabled and active"
fi

# RULE98:
if grep -qE '^(server|pool)' /etc/chrony/chrony.conf 2>/dev/null; then
    sec_audit_report_pass 98 "chrony configured with server/pool"
elif ! sec_audit_dpkg_installed chrony; then
    sec_audit_report_pass 98 "chrony not installed"
else
    sec_audit_report_fail 98 "no chrony server/pool in /etc/chrony/chrony.conf"
fi

# RULE99:
if id chrony &>/dev/null && ps -o user= -C chronyd 2>/dev/null | grep -qx chrony; then
    sec_audit_report_pass 99 "chrony is running as user chrony"
else
    sec_audit_report_fail 99 "chronyd not running as chrony (or chrony not in use)"
fi

# RULE100:
if systemctl is-enabled chrony 2>/dev/null | grep -q enabled && systemctl is-active chrony 2>/dev/null | grep -q '^active$'; then
    sec_audit_report_pass 100 "chrony is enabled and running"
elif ! sec_audit_dpkg_installed chrony; then
    sec_audit_report_pass 100 "chrony not installed (another NTP stack may be in use)"
else
    sec_audit_report_fail 100 "chrony is not enabled and active"
fi
}

sec_audit_run_cron_at() {
    # RULE101-180

# RULE101:
if systemctl is-enabled cron 2>/dev/null | grep -q enabled && systemctl is-active cron 2>/dev/null | grep -q '^active$'; then
    sec_audit_report_pass 101 "cron daemon enabled and active"
else
    sec_audit_report_fail 101 "cron not enabled/active"
fi

# RULE102:
p=$(stat -c %a /etc/crontab 2>/dev/null); o=$(stat -c %U /etc/crontab 2>/dev/null)
if [[ -n $p && $p -le 600 && $o == root ]]; then sec_audit_report_pass 102 "/etc/crontab permissions $p"; else sec_audit_report_fail 102 "/etc/crontab permissions ($p)"; fi

# RULE103:
p=$(stat -c %a /etc/cron.hourly 2>/dev/null); o=$(stat -c %U /etc/cron.hourly 2>/dev/null)
if [[ -n $p && $p -le 700 && $o == root ]]; then sec_audit_report_pass 103 "/etc/cron.hourly permissions $p"; else sec_audit_report_fail 103 "/etc/cron.hourly permissions ($p)"; fi

# RULE104:
p=$(stat -c %a /etc/cron.daily 2>/dev/null); o=$(stat -c %U /etc/cron.daily 2>/dev/null)
if [[ -n $p && $p -le 700 && $o == root ]]; then sec_audit_report_pass 104 "/etc/cron.daily permissions $p"; else sec_audit_report_fail 104 "/etc/cron.daily permissions ($p)"; fi

# RULE105:
p=$(stat -c %a /etc/cron.weekly 2>/dev/null); o=$(stat -c %U /etc/cron.weekly 2>/dev/null)
if [[ -n $p && $p -le 700 && $o == root ]]; then sec_audit_report_pass 105 "/etc/cron.weekly permissions $p"; else sec_audit_report_fail 105 "/etc/cron.weekly permissions ($p)"; fi

# RULE106:
p=$(stat -c %a /etc/cron.monthly 2>/dev/null); o=$(stat -c %U /etc/cron.monthly 2>/dev/null)
if [[ -n $p && $p -le 700 && $o == root ]]; then sec_audit_report_pass 106 "/etc/cron.monthly permissions $p"; else sec_audit_report_fail 106 "/etc/cron.monthly permissions ($p)"; fi

# RULE107:
p=$(stat -c %a /etc/cron.yearly 2>/dev/null); o=$(stat -c %U /etc/cron.yearly 2>/dev/null)
if [[ -d /etc/cron.yearly ]]; then
  if [[ -n $p && $p -le 700 && $o == root ]]; then sec_audit_report_pass 107 "/etc/cron.yearly permissions $p"; else sec_audit_report_fail 107 "/etc/cron.yearly permissions ($p)"; fi
else
  sec_audit_report_pass 107 "/etc/cron.yearly not present (not used on this system)"
fi

# RULE108:
p=$(stat -c %a /etc/cron.d 2>/dev/null); o=$(stat -c %U /etc/cron.d 2>/dev/null)
if [[ -n $p && $p -le 700 && $o == root ]]; then sec_audit_report_pass 108 "/etc/cron.d permissions $p"; else sec_audit_report_fail 108 "/etc/cron.d permissions ($p)"; fi

# RULE109:
if [[ -f /etc/cron.allow ]] && [[ ! -f /etc/cron.deny ]]; then
    sec_audit_report_pass 109 "cron restricted via cron.allow"
else
    sec_audit_report_fail 109 "cron.allow missing or cron.deny present"
fi

# RULE110:
if [[ -f /etc/at.allow ]] && [[ ! -f /etc/at.deny ]]; then
    sec_audit_report_pass 110 "at restricted via at.allow"
else
    sec_audit_report_fail 110 "at.allow missing or at.deny present"
fi

# RULE159:
p=$(stat -c %a /etc/ssh/sshd_config 2>/dev/null)
if [[ -n $p && $p -le 600 ]]; then sec_audit_report_pass 159 "sshd_config permissions $p"; else sec_audit_report_fail 159 "sshd_config too permissive"; fi

# RULE160:
bad=0
for f in /etc/ssh/ssh_host_*_key; do
    [[ -f $f ]] || continue
    p=$(stat -c %a "$f" 2>/dev/null)
    [[ -n $p && $p -le 600 ]] || bad=1
done
if [ $bad -eq 0 ]; then sec_audit_report_pass 160 "SSH private host keys mode <=600"; else sec_audit_report_fail 160 "SSH host private key permissions"; fi

# RULE161:
bad=0
for f in /etc/ssh/ssh_host_*_key; do
    [[ -f $f ]] || continue
    p=$(stat -c %a "$f" 2>/dev/null)
    [[ -n $p && $p -le 600 ]] || bad=1
done
if [ $bad -eq 0 ]; then sec_audit_report_pass 161 "SSH private host keys mode <=600"; else sec_audit_report_fail 161 "SSH host private key permissions"; fi

if ! sec_audit_sshd_effective_usable; then
    for _sshn in 162 163 164 165 166 167 168 169 170 171 172 173 174 175 176 177 178 179 180; do
        sec_audit_report_fail "$_sshn" "unable_to_evaluate: sshd -T produced no effective configuration"
    done
else
# RULE162:
sec_audit__sshd_t_ensure
if sec_audit_sshd_t_grep -iE '^(allowusers|allowgroups|denyusers|denygroups)\s' 2>/dev/null | grep -q .; then
    sec_audit_report_pass 162 "sshd AllowUsers/DenyUsers or groups configured"
else
    sec_audit_report_fail 162 "sshd access restriction (Allow/Deny) not configured"
fi
# RULE163:
sec_audit__sshd_t_ensure
if sec_audit_sshd_t_grep -i banner 2>/dev/null | awk '{print $2}' | grep -q .; then sec_audit_report_pass 163 "sshd Banner set"; else sec_audit_report_fail 163 "sshd Banner not set"; fi
# RULE164:
sec_audit__sshd_t_ensure
if sec_audit_sshd_effective_not_weak_token ciphers '(3des-cbc|aes128-cbc|aes192-cbc|aes256-cbc|arcfour|blowfish-cbc)'; then
    sec_audit_report_pass 164 "sshd Ciphers exclude weak algorithms"
else
    sec_audit_report_fail 164 "sshd uses weak ciphers"
fi
# RULE165:
sec_audit__sshd_t_ensure
ci=$(sec_audit_sshd_t_grep -i clientaliveinterval 2>/dev/null | awk '{print $2}' | head -n1)
cc=$(sec_audit_sshd_t_grep -i clientalivecountmax 2>/dev/null | awk '{print $2}' | head -n1)
if [[ -n $ci && $ci -le 900 && -n $cc && $cc -le 3 ]]; then sec_audit_report_pass 165 "ClientAliveInterval/CountMax OK"; else sec_audit_report_fail 165 "ClientAlive not configured"; fi
# RULE166:
sec_audit__sshd_t_ensure
if sec_audit_sshd_effective_equals disableforwarding yes || sec_audit_sshd_effective_equals allowtcpforwarding no; then
    sec_audit_report_pass 166 "sshd forwarding disabled"
else
    sec_audit_report_fail 166 "sshd forwarding not disabled"
fi
# RULE167:
sec_audit__sshd_t_ensure
if sec_audit_sshd_effective_equals gssapiauthentication no; then sec_audit_report_pass 167 "GSSAPIAuthentication disabled"; else sec_audit_report_fail 167 "GSSAPIAuthentication not no"; fi
# RULE168:
sec_audit__sshd_t_ensure
if sec_audit_sshd_effective_equals hostbasedauthentication no; then sec_audit_report_pass 168 "HostbasedAuthentication disabled"; else sec_audit_report_fail 168 "HostbasedAuthentication not no"; fi
# RULE169:
sec_audit__sshd_t_ensure
if sec_audit_sshd_effective_equals ignorerhosts yes; then sec_audit_report_pass 169 "IgnoreRhosts enabled"; else sec_audit_report_fail 169 "IgnoreRhosts not yes"; fi
# RULE170:
sec_audit__sshd_t_ensure
if sec_audit_sshd_effective_not_weak_token kexalgorithms '(diffie-hellman-group1-sha1|diffie-hellman-group14-sha1)'; then
    sec_audit_report_pass 170 "sshd KexAlgorithms exclude weak DH"
else
    sec_audit_report_fail 170 "weak KexAlgorithms present"
fi
# RULE171:
sec_audit__sshd_t_ensure
lg=$(sec_audit_sshd_t_grep -i logingracetime 2>/dev/null | awk '{print $2}' | head -n1)
if [[ -n $lg && $lg -le 60 ]]; then sec_audit_report_pass 171 "LoginGraceTime $lg"; else sec_audit_report_fail 171 "LoginGraceTime >60"; fi
# RULE172:
sec_audit__sshd_t_ensure
lv=$(sec_audit_sshd_t_grep -i loglevel 2>/dev/null | awk '{print $2}' | head -n1 | tr '[:upper:]' '[:lower:]')
case "$lv" in info|verbose) sec_audit_report_pass 172 "LogLevel $lv" ;; *) sec_audit_report_fail 172 "LogLevel not INFO/VERBOSE ($lv)" ;; esac
# RULE173:
sec_audit__sshd_t_ensure
if sec_audit_sshd_effective_not_weak_token macs '(hmac-md5|hmac-sha1|umac-64@openssh.com)'; then sec_audit_report_pass 173 "sshd MACs OK"; else sec_audit_report_fail 173 "weak MACs"; fi
# RULE174:
sec_audit__sshd_t_ensure
ma=$(sec_audit_sshd_t_grep -i maxauthtries 2>/dev/null | awk '{print $2}' | head -n1)
if [[ -n $ma && $ma -le 4 ]]; then sec_audit_report_pass 174 "MaxAuthTries $ma"; else sec_audit_report_fail 174 "MaxAuthTries >4"; fi
# RULE175:
sec_audit__sshd_t_ensure
ms=$(sec_audit_sshd_t_grep -i maxsessions 2>/dev/null | awk '{print $2}' | head -n1)
if [[ -n $ms && $ms -le 10 ]]; then sec_audit_report_pass 175 "MaxSessions $ms"; else sec_audit_report_fail 175 "MaxSessions >10"; fi
# RULE176:
sec_audit__sshd_t_ensure
if sec_audit_sshd_t_grep -i maxstartups 2>/dev/null | grep -q .; then sec_audit_report_pass 176 "MaxStartups configured"; else sec_audit_report_fail 176 "MaxStartups not set"; fi
# RULE177:
sec_audit__sshd_t_ensure
if sec_audit_sshd_effective_equals permitemptypasswords no; then sec_audit_report_pass 177 "PermitEmptyPasswords no"; else sec_audit_report_fail 177 "PermitEmptyPasswords not no"; fi
# RULE178:
sec_audit__sshd_t_ensure
if sec_audit_sshd_effective_equals permitrootlogin no; then sec_audit_report_pass 178 "PermitRootLogin no"; else sec_audit_report_fail 178 "PermitRootLogin not no"; fi
# RULE179:
sec_audit__sshd_t_ensure
if sec_audit_sshd_effective_equals permituserenvironment no; then sec_audit_report_pass 179 "PermitUserEnvironment no"; else sec_audit_report_fail 179 "PermitUserEnvironment not no"; fi
# RULE180:
sec_audit__sshd_t_ensure
if sec_audit_sshd_effective_equals usepam yes; then sec_audit_report_pass 180 "UsePAM yes"; else sec_audit_report_fail 180 "UsePAM not yes"; fi

fi
}

sec_audit_run_logging() {
    # RULE123-251

# RULE123:
sec_audit_sysctl_multi_rule 123 "secure ICMP redirects not accepted" "secure_redirects not disabled" \
    net.ipv4.conf.all.secure_redirects 0 net.ipv4.conf.default.secure_redirects 0

# RULE233:
if systemctl is-active systemd-journald 2>/dev/null | grep -q '^active$' && systemctl is-enabled systemd-journald 2>/dev/null | grep -qE '^(enabled|static)$'; then
    sec_audit_report_pass 233 "systemd-journald is enabled and running"
else
    sec_audit_report_fail 233 "systemd-journald is not enabled or not running"
fi

# RULE234:
if [ -d /var/log/journal ]; then
    _p=$(stat -c '%a' /var/log/journal 2>/dev/null)
    if [ "$_p" = "755" ] || [ "$_p" = "750" ]; then
        sec_audit_report_pass 234 "journal directory permissions ${_p}"
    else
        sec_audit_report_fail 234 "journal directory permissions ${_p:-?}"
    fi
else
    sec_audit_report_pass 234 "persistent journal directory absent"
fi

# RULE235:
if grep -qE '^SystemMaxUse=|^SystemMaxFileSize=' /etc/systemd/journald.conf 2>/dev/null; then
    sec_audit_report_pass 235 "journald rotation/size limits configured"
else
    sec_audit_report_fail 235 "journald SystemMaxUse/SystemMaxFileSize not set"
fi

# RULE236:
if sec_audit_dpkg_installed systemd-journal-remote; then sec_audit_report_pass 236 "systemd-journal-remote installed"; else sec_audit_report_fail 236 "systemd-journal-remote package missing"; fi

# RULE237:
if [ -f /etc/systemd/journal-upload.conf ] && grep -qE '^URL=' /etc/systemd/journal-upload.conf 2>/dev/null; then
    sec_audit_report_pass 237 "journal-upload URL configured"
else
    sec_audit_report_fail 237 "journal-upload URL not configured"
fi

# RULE238:
if systemctl is-enabled systemd-journal-upload 2>/dev/null | grep -q enabled && systemctl is-active systemd-journal-upload 2>/dev/null | grep -q '^active$'; then
    sec_audit_report_pass 238 "systemd-journal-upload enabled and active"
elif ! sec_audit_dpkg_installed systemd-journal-remote; then
    sec_audit_report_pass 238 "journal-upload package not installed"
else
    sec_audit_report_fail 238 "systemd-journal-upload not enabled/active"
fi

# RULE240:
if grep -qE '^[[:space:]]*ForwardToSyslog[[:space:]]*=[[:space:]]*no[[:space:]]*$' /etc/systemd/journald.conf 2>/dev/null || \
   grep -rqE '^[[:space:]]*ForwardToSyslog[[:space:]]*=[[:space:]]*no[[:space:]]*$' /etc/systemd/journald.conf.d/ 2>/dev/null; then
    sec_audit_report_pass 240 "journald ForwardToSyslog is disabled (no)"
else
    sec_audit_report_fail 240 "journald ForwardToSyslog is not set to no"
fi

# RULE241:
if grep -qE '^[[:space:]]*Compress[[:space:]]*=[[:space:]]*yes' /etc/systemd/journald.conf 2>/dev/null; then
    sec_audit_report_pass 241 "journald Compress=yes"
else
    sec_audit_report_fail 241 "journald Compress not set to yes"
fi

# RULE242:
if grep -qE '^[[:space:]]*Storage[[:space:]]*=[[:space:]]*persistent' /etc/systemd/journald.conf 2>/dev/null; then
    sec_audit_report_pass 242 "journald Storage=persistent"
else
    sec_audit_report_fail 242 "journald Storage not set to persistent"
fi

# RULE243:
if systemctl is-enabled rsyslog 2>/dev/null | grep -q enabled && systemctl is-active rsyslog 2>/dev/null | grep -q '^active$'; then
    sec_audit_report_pass 243 "rsyslog is enabled and active"
else
    sec_audit_report_fail 243 "rsyslog is not enabled and active"
fi

# RULE244:
if sec_audit_dpkg_installed rsyslog; then sec_audit_report_pass 244 "rsyslog installed"; else sec_audit_report_fail 244 "rsyslog not installed"; fi

# RULE245:
if grep -qE '^[[:space:]]*ForwardToSyslog[[:space:]]*=[[:space:]]*yes' /etc/systemd/journald.conf 2>/dev/null; then
    sec_audit_report_pass 245 "journald forwards to syslog (ForwardToSyslog=yes)"
else
    sec_audit_report_fail 245 "ForwardToSyslog is not yes in journald.conf"
fi

# RULE246:
if grep -rE '^\$FileCreateMode[[:space:]]+0[0-2][0-4]0' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null | grep -q .; then
    sec_audit_report_pass 246 "rsyslog FileCreateMode configured"
else
    sec_audit_report_fail 246 "rsyslog FileCreateMode missing or too permissive"
fi

# RULE247:
if [ -f /etc/rsyslog.conf ] && grep -v '^#' /etc/rsyslog.conf 2>/dev/null | grep -qE '^\*\.|^auth,|^mail,|^cron'; then
    sec_audit_report_pass 247 "rsyslog logging rules configured"
else
    sec_audit_report_fail 247 "rsyslog logging rules not configured"
fi

# RULE248:
if grep -rE '@@?[^@[:space:]]' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -qvE '@127\.0\.0\.1|@localhost'; then
    sec_audit_report_pass 248 "rsyslog remote log forwarding configured"
else
    sec_audit_report_fail 248 "rsyslog not configured to forward logs remotely"
fi

# RULE249:
if ! grep -rE '^\$ModLoad imtcp|^\$InputTCPServerRun' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null | grep -q .; then
    sec_audit_report_pass 249 "rsyslog not receiving remote logs"
else
    sec_audit_report_fail 249 "rsyslog listens for remote logs"
fi

# RULE250:
if ls /etc/logrotate.d/* 2>/dev/null | grep -q .; then
    sec_audit_report_pass 250 "logrotate drop-in configurations present"
else
    sec_audit_report_fail 250 "no logrotate configurations in /etc/logrotate.d"
fi

# RULE251:
fail=0
for f in $(find /var/log -type f 2>/dev/null | head -300); do
    p=$(stat -c %a "$f" 2>/dev/null)
    [[ -n $p && $p -le 640 ]] || fail=1
done
if [ $fail -eq 0 ]; then sec_audit_report_pass 251 "sampled /var/log files mode <=640"; else sec_audit_report_fail 251 "log file permissions too open"; fi
}

sec_audit_run_firewall() {
    # RULE129-158

# RULE129:
_fw=0
sec_audit_dpkg_installed ufw && _fw=$((_fw+1))
sec_audit_dpkg_installed nftables && systemctl is-enabled nftables 2>/dev/null | grep -q enabled && _fw=$((_fw+1))
(sec_audit_dpkg_installed iptables || sec_audit_dpkg_installed iptables-persistent) && ! sec_audit_ufw_active_enabled && _fw=$((_fw+1))
if [ "$_fw" -eq 1 ]; then
    sec_audit_report_pass 129 "a single firewall configuration utility is in use"
else
    sec_audit_report_fail 129 "zero or multiple firewall stacks appear active (count=$_fw)"
fi

# RULE130:
if sec_audit_dpkg_installed ufw; then sec_audit_report_pass 130 "ufw is installed"; else sec_audit_report_fail 130 "ufw not installed"; fi

# RULE133:
if sec_audit_ufw_active_enabled; then sec_audit_report_pass 133 "ufw enabled and active"; else sec_audit_report_fail 133 "ufw not enabled/active"; fi

# RULE134:
if ufw status verbose 2>/dev/null | grep -qE 'Anywhere on lo.*ALLOW IN' && ufw status verbose 2>/dev/null | grep -qE '127\.0\.0\.0/8.*DENY IN'; then
    sec_audit_report_pass 134 "ufw loopback traffic configured"
else
    sec_audit_report_fail 134 "ufw loopback rules missing"
fi

# RULE135:
if ufw status 2>/dev/null | grep -qE 'Default:.*deny.*outgoing'; then
    sec_audit_report_pass 135 "ufw default deny outgoing policy configured"
elif ufw status numbered 2>/dev/null | grep -qE '^\[.*\].*ALLOW OUT'; then
    sec_audit_report_pass 135 "ufw outbound rules are defined"
else
    sec_audit_report_fail 135 "ufw outbound policy/rules not verified"
fi

# RULE136:
_open=$(ss -lntu 2>/dev/null | awk 'NR>1{split($5,a,":"); print a[2]}' | sort -u)
_ufw=$(ufw status 2>/dev/null | awk '/^[0-9]+/{print $1}' | sort -u)
if [ "$(comm -23 <(echo "$_open") <(echo "$_ufw") 2>/dev/null | wc -l)" -eq 0 ]; then
    sec_audit_report_pass 136 "ufw rules exist for open ports"
else
    sec_audit_report_fail 136 "some listening ports lack ufw rules"
fi

# RULE137:
if ufw status verbose 2>/dev/null | grep -E '^Default:' | grep -q 'deny (incoming)'; then
    sec_audit_report_pass 137 "ufw default deny incoming"
else
    sec_audit_report_fail 137 "ufw default incoming policy not deny"
fi

# RULE138:
if sec_audit_dpkg_installed nftables; then sec_audit_report_pass 138 "nftables installed"; else sec_audit_report_fail 138 "nftables not installed"; fi

# RULE139:
if ! sec_audit_ufw_active_enabled || ! sec_audit_dpkg_installed ufw; then sec_audit_report_pass 139 "ufw disabled or not active with nftables path"; else sec_audit_report_fail 139 "ufw still active alongside nftables"; fi

# RULE140:
if sec_audit_nftables_service_ok; then
    if iptables -L 2>/dev/null | grep -qE '^Chain'; then
        _c=$(iptables -L 2>/dev/null | wc -l)
        [ "${_c:-0}" -le 8 ] && sec_audit_report_pass 140 "iptables minimal when nftables primary" || sec_audit_report_fail 140 "iptables rules present while nftables is primary"
    else
        sec_audit_report_pass 140 "iptables flushed or empty while nftables is primary"
    fi
else
    sec_audit_report_pass 140 "nftables not primary firewall (iptables check skipped)"
fi

# RULE141:
if sec_audit_have_bin nft && nft list tables 2>/dev/null | grep -q .; then sec_audit_report_pass 141 "nftables table exists"; else sec_audit_report_fail 141 "no nftables tables"; fi

# RULE142:
if sec_audit_have_bin nft && nft list ruleset 2>/dev/null | grep -qE 'type filter hook input'; then
    sec_audit_report_pass 142 "nftables base chains exist"
else
    sec_audit_report_fail 142 "nftables input/forward/output base chains missing"
fi

# RULE143:
if sec_audit_have_bin nft && nft list ruleset 2>/dev/null | grep -qE 'iif "lo".*accept'; then
    sec_audit_report_pass 143 "nftables loopback configured"
else
    sec_audit_report_fail 143 "nftables loopback rules missing"
fi

# RULE144:
if nft list ruleset 2>/dev/null | grep -qE 'hook output'; then
    sec_audit_report_pass 144 "nftables output hook rules configured"
else
    sec_audit_report_fail 144 "nftables output hook rules not found"
fi

# RULE145:
if nft list ruleset 2>/dev/null | grep -qiE 'policy drop|drop;'; then
    sec_audit_report_pass 145 "nftables default deny/drop policy present"
else
    sec_audit_report_fail 145 "nftables default deny policy not verified"
fi

# RULE146:
if systemctl is-enabled nftables 2>/dev/null | grep -q enabled; then sec_audit_report_pass 146 "nftables service enabled"; else sec_audit_report_fail 146 "nftables service not enabled"; fi

# RULE147:
if [[ -f /etc/nftables.conf ]] && [[ -s /etc/nftables.conf ]]; then sec_audit_report_pass 147 "nftables rules in /etc/nftables.conf"; else sec_audit_report_fail 147 "/etc/nftables.conf missing or empty"; fi

# RULE148:
if sec_audit_dpkg_installed iptables || sec_audit_dpkg_installed iptables-persistent; then
    sec_audit_report_pass 148 "iptables packages are installed"
else
    sec_audit_report_fail 148 "iptables packages are not installed"
fi

# RULE151:
if sec_audit_have_bin ip6tables && ip6tables -L INPUT 2>/dev/null | grep -qE 'policy (DROP|REJECT)'; then
    sec_audit_report_pass 151 "ip6tables INPUT default DROP/REJECT"
else
    sec_audit_report_fail 151 "ip6tables INPUT default policy not DROP/REJECT"
fi

# RULE152:
if sec_audit_have_bin ip6tables && ip6tables -L INPUT -v -n 2>/dev/null | grep -qE 'lo.*ACCEPT'; then
    sec_audit_report_pass 152 "ip6tables loopback configured"
else
    sec_audit_report_fail 152 "ip6tables loopback rule missing"
fi

# RULE153:
if iptables -L OUTPUT 2>/dev/null | grep -qE 'ACCEPT|DROP|REJECT'; then
    sec_audit_report_pass 153 "iptables OUTPUT chain has rules"
else
    sec_audit_report_fail 153 "iptables OUTPUT chain has no policy rules"
fi

# RULE154:
_open6=$(ss -lntu 2>/dev/null | awk 'NR>1 && $1 ~ /tcp|udp/ {split($5,a,":"); print a[2]}' | sort -u)
_missing6=0
if sec_audit_have_bin ip6tables; then
    for p in $_open6; do
        [[ -n $p ]] || continue
        ip6tables -L INPUT -n 2>/dev/null | grep -qE "\b${p}\b" || _missing6=1
    done
fi
if [ "${_missing6:-1}" -eq 0 ]; then
    sec_audit_report_pass 154 "ip6tables rules reference open ports"
else
    sec_audit_report_fail 154 "ip6tables missing rules for some listening ports"
fi

# RULE155:
if sec_audit_have_bin ip6tables && ip6tables -L INPUT 2>/dev/null | grep -qE 'policy (DROP|REJECT)'; then
    sec_audit_report_pass 155 "ip6tables INPUT default DROP/REJECT"
else
    sec_audit_report_fail 155 "ip6tables INPUT default policy not DROP/REJECT"
fi

# RULE156:
if sec_audit_have_bin ip6tables && ip6tables -L INPUT -v -n 2>/dev/null | grep -qE 'lo.*ACCEPT'; then
    sec_audit_report_pass 156 "ip6tables loopback configured"
else
    sec_audit_report_fail 156 "ip6tables loopback rule missing"
fi

# RULE157:
if ip6tables -L OUTPUT 2>/dev/null | grep -qE 'ACCEPT|DROP|REJECT'; then
    sec_audit_report_pass 157 "ip6tables OUTPUT chain has rules"
else
    sec_audit_report_fail 157 "ip6tables OUTPUT chain has no policy rules"
fi

# RULE158:
_open6=$(ss -lntu 2>/dev/null | awk 'NR>1 && $1 ~ /tcp|udp/ {split($5,a,":"); print a[2]}' | sort -u)
_missing6=0
if sec_audit_have_bin ip6tables; then
    for p in $_open6; do
        [[ -n $p ]] || continue
        ip6tables -L INPUT -n 2>/dev/null | grep -qE "\b${p}\b" || _missing6=1
    done
fi
if [ "${_missing6:-1}" -eq 0 ]; then
    sec_audit_report_pass 158 "ip6tables rules reference open ports"
else
    sec_audit_report_fail 158 "ip6tables missing rules for some listening ports"
fi
}

sec_audit_run_sudo_su() {
    # RULE181-262

# RULE181:
if sec_audit_dpkg_installed sudo; then sec_audit_report_pass 181 "sudo installed"; else sec_audit_report_fail 181 "sudo not installed"; fi

# RULE182:
if grep -rq 'pam_pty.so' /etc/sudoers /etc/sudoers.d/ 2>/dev/null || grep -q 'use_pty' /etc/sudoers 2>/dev/null; then
    sec_audit_report_pass 182 "sudo use_pty configured"
else
    sec_audit_report_fail 182 "sudo pty/requirement missing"
fi

# RULE183:
if grep -qE '^[[:space:]]*Defaults[[:space:]]+logfile=' /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
    sec_audit_report_pass 183 "sudo log file configured"
else
    sec_audit_report_fail 183 "sudo logfile Defaults missing"
fi

# RULE185:
if ! grep -q '!authenticate' /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
    sec_audit_report_pass 185 "re-authentication not disabled globally"
else
    sec_audit_report_fail 185 "!authenticate disables re-auth"
fi

# RULE186:
to=$(grep -hr 'timestamp_timeout' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -oE '[0-9]+' | head -n1)
if [[ -n $to && $to -le 15 ]]; then sec_audit_report_pass 186 "sudo timestamp_timeout $to"; else sec_audit_report_fail 186 "timestamp_timeout >15 or unset"; fi

# RULE260:
sec_audit__audit_rules_files_ensure
sec_audit__auditctl_l_ensure
if sec_audit_audit_rules_files_grep -q 'sudoers' 2>/dev/null && sec_audit_auditctl_rules_grep -q 'sudoers' 2>/dev/null; then
    sec_audit_report_pass 260 "audit collects events matching 'sudoers' (disk and loaded)"
else
    sec_audit_report_fail 260 "audit rule for 'sudoers' missing on disk or not loaded"
fi

# RULE262:
sec_audit__audit_rules_files_ensure
sec_audit__auditctl_l_ensure
if sec_audit_audit_rules_files_grep -q 'sudo.log' 2>/dev/null && sec_audit_auditctl_rules_grep -q 'sudo.log' 2>/dev/null; then
    sec_audit_report_pass 262 "audit collects events matching 'sudo.log' (disk and loaded)"
else
    sec_audit_report_fail 262 "audit rule for 'sudo.log' missing on disk or not loaded"
fi
}

sec_audit_run_pam_auth() {
    # RULE188-216

# RULE188:
if sec_audit_dpkg_installed libpam0g; then sec_audit_report_pass 188 "pam package installed"; else sec_audit_report_fail 188 "libpam0g not installed"; fi

# RULE189:
if sec_audit_dpkg_installed libpam-modules; then sec_audit_report_pass 189 "libpam-modules installed"; else sec_audit_report_fail 189 "libpam-modules not installed"; fi

# RULE190:
if sec_audit_dpkg_installed libpam-pwquality; then sec_audit_report_pass 190 "libpam-pwquality installed"; else sec_audit_report_fail 190 "libpam-pwquality not installed"; fi

# RULE191:
if grep -q pam_unix /etc/pam.d/common-password 2>/dev/null; then sec_audit_report_pass 191 "pam_unix enabled in common-password"; else sec_audit_report_fail 191 "pam_unix missing"; fi

# RULE192:
if grep -q pam_faillock /etc/pam.d/common-auth 2>/dev/null; then sec_audit_report_pass 192 "pam_faillock enabled"; else sec_audit_report_fail 192 "pam_faillock missing in common-auth"; fi

# RULE193:
if grep -q pam_pwquality /etc/pam.d/common-password 2>/dev/null; then sec_audit_report_pass 193 "pam_pwquality enabled"; else sec_audit_report_fail 193 "pam_pwquality missing"; fi

# RULE194:
if grep -q pam_pwhistory /etc/pam.d/common-password 2>/dev/null; then sec_audit_report_pass 194 "pam_pwhistory enabled"; else sec_audit_report_fail 194 "pam_pwhistory missing"; fi

# RULE195:
if grep -q pam_faillock /etc/pam.d/common-auth 2>/dev/null; then sec_audit_report_pass 195 "password lockout configured"; else sec_audit_report_fail 195 "pam_faillock lockout missing"; fi

# RULE197:
if grep -q pam_faillock /etc/pam.d/common-auth 2>/dev/null && grep -q even_deny_root /etc/security/faillock.conf 2>/dev/null; then
    sec_audit_report_pass 197 "faillock includes root"
else
    sec_audit_report_fail 197 "root not included in faillock policy"
fi

# RULE199:
v=$(grep -E '^PASS_MIN_DAYS' /etc/login.defs | awk '{print $2}' | head -n1)
if [[ -n $v && $v -ge 1 ]]; then sec_audit_report_pass 199 "PASS_MIN_DAYS $v"; else sec_audit_report_fail 199 "PASS_MIN_DAYS <1"; fi

# RULE200:
if grep -Psi '^\h*(minclass|[dulo]credit)\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null; then
    sec_audit_report_pass 200 "password complexity configured in pwquality"
else
    sec_audit_report_fail 200 "password complexity (minclass/credits) not configured"
fi

# RULE204:
if grep -q dictcheck /etc/security/pwquality.conf 2>/dev/null; then sec_audit_report_pass 204 "dictcheck enabled"; else sec_audit_report_fail 204 "dictcheck missing"; fi

# RULE205:
if grep -q enforce_for_root /etc/security/pwquality.conf 2>/dev/null; then sec_audit_report_pass 205 "pwquality enforced for root"; else sec_audit_report_fail 205 "enforce_for_root missing"; fi

# RULE206:
if grep -q pam_pwhistory /etc/pam.d/common-password 2>/dev/null; then sec_audit_report_pass 206 "password history configured"; else sec_audit_report_fail 206 "pam_pwhistory missing"; fi

# RULE207:
if grep -q enforce_for_root /etc/security/pwhistory.conf 2>/dev/null || grep -q pam_pwhistory /etc/pam.d/common-password 2>/dev/null; then
    sec_audit_report_pass 207 "password history policy present for root"
else
    sec_audit_report_fail 207 "root password history not enforced"
fi

# RULE208:
if grep -q use_authtok /etc/pam.d/common-password 2>/dev/null; then sec_audit_report_pass 208 "pam_pwhistory uses use_authtok"; else sec_audit_report_fail 208 "use_authtok missing for pwhistory"; fi

# RULE209:
if ! grep -q nullok /etc/pam.d/common-password 2>/dev/null; then sec_audit_report_pass 209 "pam_unix without nullok"; else sec_audit_report_fail 209 "nullok present in pam_unix"; fi

# RULE210:
if ! grep pam_unix /etc/pam.d/common-password 2>/dev/null | grep -q remember; then sec_audit_report_pass 210 "pam_unix without remember"; else sec_audit_report_fail 210 "remember in pam_unix"; fi

# RULE211:
if grep -qE 'pam_unix\.so.*(sha512|yescrypt)' /etc/pam.d/common-password 2>/dev/null; then sec_audit_report_pass 211 "strong hashing in pam_unix"; else sec_audit_report_fail 211 "weak/missing hash in pam_unix"; fi

# RULE212:
if grep pam_unix /etc/pam.d/common-password 2>/dev/null | grep -q use_authtok; then sec_audit_report_pass 212 "pam_unix use_authtok"; else sec_audit_report_fail 212 "use_authtok missing in pam_unix"; fi

# RULE216:
if grep -qE 'pam_unix\.so.*sha512|yescrypt' /etc/pam.d/common-password 2>/dev/null; then
    sec_audit_report_pass 216 "strong hashing in common-password"
else
    sec_audit_report_fail 216 "sha512/yescrypt not in pam_unix"
fi
}

sec_audit_run_aide() {
    # RULE223-230

# RULE223:
if echo "$PATH" | grep -q '::' || echo "$PATH" | grep -q ':$'; then sec_audit_report_fail 223 "root PATH contains empty segment"; else sec_audit_report_pass 223 "root PATH integrity OK"; fi

# RULE230:
if sec_audit_dpkg_installed aide || sec_audit_dpkg_installed aide-common; then
    sec_audit_report_pass 230 "AIDE is installed"
else
    sec_audit_report_fail 230 "AIDE package is not installed"
fi
}

sec_audit_run_auditd() {
    # RULE252-290

# RULE252:
if sec_audit_dpkg_installed auditd; then sec_audit_report_pass 252 "auditd installed"; else sec_audit_report_fail 252 "auditd not installed"; fi

# RULE253:
if systemctl is-enabled auditd 2>/dev/null | grep -q enabled && systemctl is-active auditd 2>/dev/null | grep -q '^active$'; then
    sec_audit_report_pass 253 "auditd enabled and active"
else
    sec_audit_report_fail 253 "auditd not enabled/active"
fi

# RULE254:
if grep -q 'audit=1' /etc/default/grub 2>/dev/null; then sec_audit_report_pass 254 "audit=1 in grub"; else sec_audit_report_fail 254 "audit=1 missing from grub"; fi

# RULE255:
if grep -q 'audit_backlog_limit' /etc/default/grub 2>/dev/null; then sec_audit_report_pass 255 "audit_backlog_limit in grub"; else sec_audit_report_fail 255 "audit_backlog_limit missing"; fi

# RULE256:
if grep -qi '^[[:space:]]*max_log_file[[:space:]]*=' /etc/audit/auditd.conf 2>/dev/null; then
    sec_audit_report_pass 256 "max_log_file set in auditd.conf"
else
    sec_audit_report_fail 256 "max_log_file not configured"
fi

# RULE257:
if grep -qi '^[[:space:]]*max_log_file_action[[:space:]]*=' /etc/audit/auditd.conf 2>/dev/null; then
    sec_audit_report_pass 257 "max_log_file_action set in auditd.conf"
else
    sec_audit_report_fail 257 "max_log_file_action not configured"
fi

# RULE258:
if grep -qi '^[[:space:]]*disk_full_action[[:space:]]*=' /etc/audit/auditd.conf 2>/dev/null; then
    sec_audit_report_pass 258 "disk_full_action set in auditd.conf"
else
    sec_audit_report_fail 258 "disk_full_action not configured"
fi

# RULE259:
if grep -qi '^[[:space:]]*space_left_action[[:space:]]*=' /etc/audit/auditd.conf 2>/dev/null; then
    sec_audit_report_pass 259 "space_left_action set in auditd.conf"
else
    sec_audit_report_fail 259 "space_left_action not configured"
fi

# RULE279:
if sec_audit_audit_rule_loaded_and_on_disk -- '-e 2'; then
    sec_audit_report_pass 279 "the audit configuration is immutable (-e 2 loaded and on disk)"
elif sec_audit_audit_rules_files_grep -q -- '-e 2'; then
    sec_audit_report_fail 279 "Immutable rule (-e 2) is on disk but not loaded (auditctl -l)"
elif sec_audit_auditctl_rules_grep -q -- '-e 2'; then
    sec_audit_report_fail 279 "Immutable rule (-e 2) is loaded but missing from on-disk audit rules"
else
    sec_audit_report_fail 279 "Immutable rule (-e 2) is missing from loaded and on-disk audit rules"
fi

# RULE281:
p=$(stat -c %a /var/log/audit 2>/dev/null)
if [[ -n $p && $p -le 750 ]]; then sec_audit_report_pass 281 "/var/log/audit permissions $p"; else sec_audit_report_fail 281 "/var/log/audit permissions $p"; fi

# RULE282:
fail=0
for f in $(find /var/log/audit -type f 2>/dev/null | head -50); do
    o=$(stat -c %U "$f" 2>/dev/null); [[ $o == root ]] || fail=1
done
if [ $fail -eq 0 ]; then sec_audit_report_pass 282 "audit log files owned by root"; else sec_audit_report_fail 282 "audit log file owner"; fi

# RULE283:
fail=0
for f in $(find /var/log/audit -type f 2>/dev/null | head -50); do
    g=$(stat -c %G "$f" 2>/dev/null); [[ $g == root ]] || fail=1
done
if [ $fail -eq 0 ]; then sec_audit_report_pass 283 "audit log files group root"; else sec_audit_report_fail 283 "audit log file group"; fi

# RULE284:
p=$(stat -c %a /var/log/audit 2>/dev/null)
if [[ -n $p && $p -le 750 ]]; then sec_audit_report_pass 284 "audit log directory mode $p"; else sec_audit_report_fail 284 "audit log directory mode"; fi

# RULE285:
if find /etc/audit -type f 2>/dev/null | while read f; do
    p=$(stat -c '%a' "$f"); echo "$p" | grep -qE '^[0-6][0-4]0$' || exit 1
done; then sec_audit_report_pass 285 "audit config files mode <=640"; else sec_audit_report_fail 285 "audit config file mode"; fi

# RULE286:
if find /etc/audit -type f 2>/dev/null | while read f; do
    o=$(stat -c '%U' "$f"); [[ $o == root ]] || exit 1
done; then sec_audit_report_pass 286 "audit config files owned by root"; else sec_audit_report_fail 286 "audit config file owner"; fi

# RULE287:
if find /etc/audit -type f 2>/dev/null | while read f; do
    g=$(stat -c '%G' "$f"); [[ $g == root ]] || exit 1
done; then sec_audit_report_pass 287 "audit config files group root"; else sec_audit_report_fail 287 "audit config file group"; fi

# RULE288:
for t in /sbin/auditctl /sbin/auditd /sbin/ausearch; do
    [[ -f $t ]] || continue
    p=$(stat -c %a "$t" 2>/dev/null); [[ -n $p && $p -le 755 ]] || { sec_audit_report_fail 288 "$t mode $p"; return 0; }
done
sec_audit_report_pass 288 "audit tools mode <=755"

# RULE289:
for t in /sbin/auditctl /sbin/auditd /sbin/ausearch; do
    [[ -f $t ]] || continue
    o=$(stat -c %U "$t" 2>/dev/null); [[ $o == root ]] || { sec_audit_report_fail 289 "$t owner $o"; return 0; }
done
sec_audit_report_pass 289 "audit tools owned by root"

# RULE290:
for t in /sbin/auditctl /sbin/auditd /sbin/ausearch; do
    [[ -f $t ]] || continue
    g=$(stat -c %G "$t" 2>/dev/null); [[ $g == root ]] || { sec_audit_report_fail 290 "$t group $g"; return 0; }
done
sec_audit_report_pass 290 "audit tools group owner root"
}

sec_audit_run_identity_files() {
    # RULE291-300

# RULE291:
p=$(stat -c %a /etc/passwd 2>/dev/null); o=$(stat -c %U /etc/passwd 2>/dev/null); g=$(stat -c %G /etc/passwd 2>/dev/null)
if [[ ! -f /etc/passwd ]]; then sec_audit_report_pass 291 "/etc/passwd not present";
elif [[ -n $p && $p -le 644 && $o == root && $g == root ]]; then sec_audit_report_pass 291 "/etc/passwd $p root:root";
else sec_audit_report_fail 291 "/etc/passwd perms $p $o:$g"; fi

# RULE292:
p=$(stat -c %a /etc/passwd- 2>/dev/null); o=$(stat -c %U /etc/passwd- 2>/dev/null); g=$(stat -c %G /etc/passwd- 2>/dev/null)
if [[ ! -f /etc/passwd- ]]; then sec_audit_report_pass 292 "/etc/passwd- not present";
elif [[ -n $p && $p -le 644 && $o == root && $g == root ]]; then sec_audit_report_pass 292 "/etc/passwd- $p root:root";
else sec_audit_report_fail 292 "/etc/passwd- perms $p $o:$g"; fi

# RULE293:
p=$(stat -c %a /etc/group 2>/dev/null); o=$(stat -c %U /etc/group 2>/dev/null); g=$(stat -c %G /etc/group 2>/dev/null)
if [[ ! -f /etc/group ]]; then sec_audit_report_pass 293 "/etc/group not present";
elif [[ -n $p && $p -le 644 && $o == root && $g == root ]]; then sec_audit_report_pass 293 "/etc/group $p root:root";
else sec_audit_report_fail 293 "/etc/group perms $p $o:$g"; fi

# RULE294:
p=$(stat -c %a /etc/group- 2>/dev/null); o=$(stat -c %U /etc/group- 2>/dev/null); g=$(stat -c %G /etc/group- 2>/dev/null)
if [[ ! -f /etc/group- ]]; then sec_audit_report_pass 294 "/etc/group- not present";
elif [[ -n $p && $p -le 644 && $o == root && $g == root ]]; then sec_audit_report_pass 294 "/etc/group- $p root:root";
else sec_audit_report_fail 294 "/etc/group- perms $p $o:$g"; fi

# RULE295:
p=$(stat -c %a /etc/shadow 2>/dev/null); o=$(stat -c %U /etc/shadow 2>/dev/null); g=$(stat -c %G /etc/shadow 2>/dev/null)
if [[ ! -f /etc/shadow ]]; then sec_audit_report_pass 295 "/etc/shadow not present";
elif [[ -n $p && $p -le 640 && $o == root && $g == root ]]; then sec_audit_report_pass 295 "/etc/shadow $p root:root";
else sec_audit_report_fail 295 "/etc/shadow perms $p $o:$g"; fi

# RULE296:
p=$(stat -c %a /etc/shadow- 2>/dev/null); o=$(stat -c %U /etc/shadow- 2>/dev/null); g=$(stat -c %G /etc/shadow- 2>/dev/null)
if [[ ! -f /etc/shadow- ]]; then sec_audit_report_pass 296 "/etc/shadow- not present";
elif [[ -n $p && $p -le 640 && $o == root && $g == root ]]; then sec_audit_report_pass 296 "/etc/shadow- $p root:root";
else sec_audit_report_fail 296 "/etc/shadow- perms $p $o:$g"; fi

# RULE297:
p=$(stat -c %a /etc/gshadow 2>/dev/null); o=$(stat -c %U /etc/gshadow 2>/dev/null); g=$(stat -c %G /etc/gshadow 2>/dev/null)
if [[ ! -f /etc/gshadow ]]; then sec_audit_report_pass 297 "/etc/gshadow not present";
elif [[ -n $p && $p -le 640 && $o == root && $g == root ]]; then sec_audit_report_pass 297 "/etc/gshadow $p root:root";
else sec_audit_report_fail 297 "/etc/gshadow perms $p $o:$g"; fi

# RULE298:
p=$(stat -c %a /etc/gshadow- 2>/dev/null); o=$(stat -c %U /etc/gshadow- 2>/dev/null); g=$(stat -c %G /etc/gshadow- 2>/dev/null)
if [[ ! -f /etc/gshadow- ]]; then sec_audit_report_pass 298 "/etc/gshadow- not present";
elif [[ -n $p && $p -le 640 && $o == root && $g == root ]]; then sec_audit_report_pass 298 "/etc/gshadow- $p root:root";
else sec_audit_report_fail 298 "/etc/gshadow- perms $p $o:$g"; fi

# RULE299:
p=$(stat -c %a /etc/shells 2>/dev/null); o=$(stat -c %U /etc/shells 2>/dev/null); g=$(stat -c %G /etc/shells 2>/dev/null)
if [[ ! -f /etc/shells ]]; then sec_audit_report_pass 299 "/etc/shells not present";
elif [[ -n $p && $p -le 644 && $o == root && $g == root ]]; then sec_audit_report_pass 299 "/etc/shells $p root:root";
else sec_audit_report_fail 299 "/etc/shells perms $p $o:$g"; fi

# RULE300:
p=$(stat -c %a /etc/security/opasswd 2>/dev/null); o=$(stat -c %U /etc/security/opasswd 2>/dev/null); g=$(stat -c %G /etc/security/opasswd 2>/dev/null)
if [[ ! -f /etc/security/opasswd ]]; then sec_audit_report_pass 300 "/etc/security/opasswd not present";
elif [[ -n $p && $p -le 600 && $o == root && $g == root ]]; then sec_audit_report_pass 300 "/etc/security/opasswd $p root:root";
else sec_audit_report_fail 300 "/etc/security/opasswd perms $p $o:$g"; fi
}

sec_audit_run_filesystem_integrity() {
    # RULE301-313

# RULE301:
CRITICAL_PATHS="/bin /sbin /usr/bin /usr/sbin /etc /var /home"
if sec_audit_find_hit_timeout sec_audit_soft_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type f -perm -0002 -print; then
    sec_audit_report_fail 301 "incomplete_scan: world-writable file search timed out under critical paths"
elif sec_audit_find_hit_timeout sec_audit_soft_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type d -perm -0002 -print; then
    sec_audit_report_fail 301 "incomplete_scan: world-writable directory search timed out under critical paths"
else
    WW_FILES=$(sec_audit_soft_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type f -perm -0002 -print 2>/dev/null | wc -l)
    WW_DIRS=$(sec_audit_soft_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type d -perm -0002 -print 2>/dev/null | wc -l)
    if [ "$WW_FILES" -eq 0 ] && [ "$WW_DIRS" -eq 0 ]; then
        sec_audit_report_pass 301 "No critical world writable files or directories found"
    else
        sec_audit_report_fail 301 "Found potential world-writable items ($WW_FILES files, $WW_DIRS dirs)"
    fi
fi

# RULE302:
n=$(sec_audit__find_perm_count "\( -nouser -o -nogroup \)")
if [ "${n:-0}" -eq 0 ]; then sec_audit_report_pass 302 "no unowned objects"; else sec_audit_report_fail 302 "found $n unowned/ungrouped objects"; fi

# RULE310:
if ! cut -f1 -d: /etc/passwd | sort | uniq -d | grep -q .; then sec_audit_report_pass 310 "no duplicate usernames"; else sec_audit_report_fail 310 "duplicate usernames"; fi

# RULE311:
if ! cut -f1 -d: /etc/group | sort | uniq -d | grep -q .; then sec_audit_report_pass 311 "no duplicate group names"; else sec_audit_report_fail 311 "duplicate group names"; fi

# RULE313:
fail=0
while IFS=: read -r u _ uid _ home shell; do
    [[ $uid -ge 1000 ]] || continue
    [[ -d $home ]] || continue
    for df in "$home"/.[A-Za-z]*; do
        [[ -f $df ]] || continue
        p=$(stat -c %a "$df" 2>/dev/null)
        [[ $((p & 077)) -eq 0 ]] || fail=1
    done
done < /etc/passwd
if [ $fail -eq 0 ]; then sec_audit_report_pass 313 "dot files not group/world accessible"; else sec_audit_report_fail 313 "insecure dot file permissions"; fi

return 0
}

sec_audit_main() {
    sec_audit_run_kernel_modules
    sec_audit_run_filesystem_partitions
    sec_audit_run_accounts
    sec_audit_run_apparmor
    sec_audit_run_bootloader
    sec_audit_run_process_hardening
    sec_audit_run_banners
    sec_audit_run_gdm
    sec_audit_run_unused_services
    sec_audit_run_network_stack
    sec_audit_run_client_tools
    sec_audit_run_chrony
    sec_audit_run_cron_at
    sec_audit_run_logging
    sec_audit_run_firewall
    sec_audit_run_sudo_su
    sec_audit_run_pam_auth
    sec_audit_run_aide
    sec_audit_run_auditd
    sec_audit_run_identity_files
    sec_audit_run_filesystem_integrity
    exit 0
}

sec_audit_main "$@"
