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

DEB13_FIND_CAP="${DEB13_FIND_CAP:-20}"
DEB13_CMD_CAP="${DEB13_CMD_CAP:-12}"
DEB13_APT_CAP="${DEB13_APT_CAP:-30}"
DEB13_ALLOW_CONTAINER_KMOD="${DEB13_ALLOW_CONTAINER_KMOD:-${DEB13_ALLOW_CONTAINER_MODULES:-0}}"

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

sec_audit_pkg_is_installed() {
    local pkg
    if sec_audit_have_bin dpkg-query; then
        for pkg in "$@"; do
            dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'install ok installed' && return 0
        done
    fi
    if sec_audit_have_bin dpkg; then
        for pkg in "$@"; do
            dpkg -l "$pkg" 2>/dev/null | grep -qE '^ii[[:space:]]' && return 0
        done
    fi
    if sec_audit_have_bin rpm; then
        for pkg in "$@"; do
            rpm -q "$pkg" &>/dev/null && return 0
        done
    fi
    return 1
}

sec_audit_pkg_any_installed() { sec_audit_pkg_is_installed "$@"; }

sec_audit_pkg_every_installed() {
    local pkg
    for pkg in "$@"; do
        sec_audit_pkg_is_installed "$pkg" || return 1
    done
    return 0
}

sec_audit_rpm_any_installed() { sec_audit_pkg_any_installed "$@"; }
sec_audit_rpm_every_installed() { sec_audit_pkg_every_installed "$@"; }

sec_audit_apt_conf_option() {
    local key="$1" v=""
    if sec_audit_have_bin apt-config; then
        v=$(sec_audit_exec_with_timeout "${DEB13_APT_CAP:-30}" apt-config dump --format '%v%n' "$key" 2>/dev/null | head -n1 || true)
        printf '%s' "$(sec_audit_trim_ws "$v")"
        return 0
    fi
    printf '%s' ""
}

sec_audit_apt_allow_unauthenticated_false() {
    local v
    v=$(sec_audit_apt_conf_option 'APT::Get::AllowUnauthenticated')
    case "$(sec_audit_to_lower "$v")" in
        0|false|no|off|'') return 0 ;;
        *) return 1 ;;
    esac
}

sec_audit_grub_cmdline_param_present() {
    local pat="$1"
    grep -Eq "$pat" /proc/cmdline 2>/dev/null && return 0
    grep -Eq "$pat" /etc/default/grub 2>/dev/null
}

sec_audit_apparmor_bootloader_enabled() {
    sec_audit_grub_cmdline_param_present 'apparmor=1' && sec_audit_grub_cmdline_param_present 'security=apparmor'
}

sec_audit_apparmor_status_output() {
    if sec_audit_have_bin aa-status; then
        aa-status 2>/dev/null
    elif sec_audit_have_bin apparmor_status; then
        apparmor_status 2>/dev/null
    else
        return 1
    fi
}

sec_audit_apparmor_profiles_enforce_or_complain_ok() {
    local out
    out=$(sec_audit_apparmor_status_output) || return 1
    echo "$out" | grep -qi 'profiles are in' || return 1
    ! echo "$out" | grep -Eiq '([1-9][0-9]* profiles are in kill mode|[1-9][0-9]* processes? are unconfined)'
}

sec_audit_apparmor_profiles_all_enforcing_ok() {
    local out
    out=$(sec_audit_apparmor_status_output) || return 1
    echo "$out" | grep -Eiq '[1-9][0-9]* profiles are in enforce mode' || return 1
    ! echo "$out" | grep -Eiq '([1-9][0-9]* profiles are in (complain|kill) mode|[1-9][0-9]* processes? are unconfined)'
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
    n=$(sec_audit_exec_with_timeout "$DEB13_APT_CAP" dnf -q repolist enabled 2>/dev/null | awk '
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
    local pattern="$1" cap="${2:-$DEB13_FIND_CAP}" rc=0 out=""
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
            [[ "${DEB13_ALLOW_CONTAINER_KMOD}" == "1" ]]
            ;;
        *) return 1 ;;
    esac
}

sec_audit_assert_kmod_disabled() {
    local num="$1" label="$2" mod="$3" ko_pattern="$4"
    shift 4
    local alias loaded=0 a
    if sec_audit_kmod_container_exception "$mod"; then
        sec_audit_report_pass "$num" "${label} (waived: DEB13_ALLOW_CONTAINER_KMOD=1)"
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
    for f in /etc/pam.d/common-password /etc/pam.d/password-auth /etc/pam.d/system-auth; do
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
    for f in /etc/pam.d/common-auth /etc/pam.d/common-account /etc/pam.d/password-auth /etc/pam.d/system-auth /etc/pam.d/su /etc/pam.d/sshd; do
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

sec_audit_gdm_installed() { sec_audit_pkg_any_installed gdm gdm3; }

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
    if sec_audit_pkg_is_installed "$pkg"; then
        sec_audit_report_fail "$num" "$fail_msg"
    else
        sec_audit_report_pass "$num" "$pass_msg"
    fi
}

# --- compatibility aliases used by preserved Debian RULE bodies ---
sec_audit_dnf_main_last_value() { sec_audit_dnf_main_option "$@"; }
sec_audit_dnf_val_is_false() { sec_audit_truthy_false "$@"; }
sec_audit_dnf_val_is_true() { sec_audit_truthy_true "$@"; }
sec_audit_low_impact_find() { sec_audit_soft_find "$@"; }
sec_audit_low_impact_find_timed_out() { sec_audit_find_hit_timeout "$@"; }
sec_audit_safe_find_roots() { sec_audit_local_fs_roots; }
sec_audit_pkg_installed() { sec_audit_pkg_is_installed "$@"; }
sec_audit_is_package_installed() { sec_audit_pkg_is_installed "$@"; }
sec_audit_kernel_mod_in_modules_load() { sec_audit_kmod_autoload_listed "$@"; }
sec_audit_kernel_mod_lsmod_name_loaded() { sec_audit_kmod_is_loaded "$@"; }
sec_audit_kernel_mod_ko_scan() { sec_audit_kmod_object_exists "$@"; }
sec_audit_kernel_mod_refuses_load() { sec_audit_kmod_is_blocked "$@"; }
sec_audit_kernel_mod_cre_waiver() { sec_audit_kmod_container_exception "$@"; }
sec_audit_systemd_unit_enabled_or_active() { sec_audit_systemd_unit_live "$@"; }
sec_audit_mount_persisted() { sec_audit_mount_is_persisted "$@"; }
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
sec_audit_grub_cfg_paths() { sec_audit_list_grub_cfg_paths; }
sec_audit_grub_cfg_grep() { sec_audit_grub_cfg_matches "$@"; }
sec_audit_sysctl_key_runtime() { sec_audit_sysctl_runtime "$@"; }
sec_audit__yum_repo_list_explicit_gpgcheck0() { sec_audit_list_repos_gpgcheck_disabled; }
sec_audit_sshd_effective_dump() { sec_audit_sshd_effective_config; }
sec_audit_sshd_t_grep() { sec_audit_sshd_config_grep "$@"; }
sec_audit_sshd_t_awk() { sec_audit_sshd_config_awk "$@"; }
sec_audit_sshd_effective_usable() {
    sec_audit_cache_sshd_config
    [ -n "${_SSHD_DUMP:-}" ]
}

sec_audit_auditctl_rules_grep() { sec_audit_auditctl_list_grep "$@"; }
sec_audit_audit_rules_files_grep() { sec_audit_audit_rules_file_grep "$@"; }
sec_audit_audit_rule_loaded_and_on_disk() { sec_audit_audit_rule_on_disk_and_loaded "$@"; }

sec_audit_pam_stack_paths_password_system() {
    local f p
    for f in /etc/pam.d/common-password /etc/pam.d/password-auth /etc/pam.d/system-auth; do
        [[ -e $f ]] || continue
        if sec_audit_have_bin readlink; then
            p=$(readlink -f "$f" 2>/dev/null || echo "$f")
        else
            p=$f
        fi
        printf '%s\n' "$p"
    done | sort -u
}

sec_audit_pam_password_line_has_module() {
    local mod="$1" p stacks
    stacks="$(sec_audit_pam_stack_paths_password_system)"
    [ -n "$stacks" ] || stacks="$(sec_audit_pam_password_stack_paths)"
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

sec_audit_pam_password_pwquality_before_unix_all_stacks() {
    local p any=0 stacks
    stacks="$(sec_audit_pam_stack_paths_password_system)"
    [ -n "$stacks" ] || stacks="$(sec_audit_pam_password_stack_paths)"
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

sec_audit_limits_core_zero_and_systemd_ok() {
    if ! grep -Psi '^\*\s+hard\s+core\s+0\b' /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null | grep -q .; then
        return 1
    fi
    if grep -rPi '^\h*DefaultLimitCORE\h*=\h*(infinity|unlimited|[1-9])' \
        /etc/systemd/system.conf /etc/systemd/user.conf \
        /etc/systemd/system.conf.d/*.conf /etc/systemd/user.conf.d/*.conf 2>/dev/null | grep -q .; then
        return 1
    fi
    return 0
}

# =============================================================================
# Rule section runners (RULE1 .. RULE284)
# =============================================================================

sec_audit_run_kernel_modules() {
    # RULE1
    sec_audit_assert_kmod_disabled 1 "cramfs kernel module" cramfs cramfs.ko* "cramfs"

    # RULE2
    sec_audit_assert_kmod_disabled 2 "freevxfs kernel module" freevxfs freevxfs.ko* "freevxfs"

    # RULE3
    sec_audit_assert_kmod_disabled 3 "hfs kernel module" hfs hfs.ko* "hfs"

    # RULE4
    sec_audit_assert_kmod_disabled 4 "hfsplus kernel module" hfsplus hfsplus.ko* "hfsplus"

    # RULE5
    sec_audit_assert_kmod_disabled 5 "jffs2 kernel module" jffs2 jffs2.ko* "jffs2"

    # RULE6
    sec_audit_assert_kmod_disabled 6 "overlay kernel module" overlay overlay.ko* "overlay"

    # RULE7
    sec_audit_assert_kmod_disabled 7 "squashfs kernel module" squashfs squashfs.ko* "squashfs"

    # RULE8
    sec_audit_assert_kmod_disabled 8 "udf kernel module" udf udf.ko* "udf"

    # RULE9
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

    # RULE10
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
    # RULE11
    if sec_audit_findmnt_tmp_sec_ok; then
    if sec_audit_mount_persisted /tmp; then
        sec_audit_report_pass 11 "/tmp is tmpfs or a separate partition"
    else
        sec_audit_report_fail 11 "/tmp is tmpfs or a separate partition is runtime-only (missing fstab or systemd .mount persistence)"
    fi
    else
    sec_audit_report_fail 11 "/tmp does not meet tmpfs or separate-partition requirement"
    fi

    # RULE12
    if sec_audit_findmnt_path_resolvable /tmp && sec_audit_findmnt_has_mnt_option /tmp nodev; then
    sec_audit_report_pass 12 "nodev option set on /tmp partition"
    elif ! sec_audit_findmnt_path_resolvable /tmp; then
    sec_audit_report_fail 12 "nodev is not set on /tmp (or path not resolvable / not an explicit mount per policy)"
    else
    sec_audit_report_fail 12 "nodev is not set on /tmp (or path not resolvable / not an explicit mount per policy)"
    fi

    # RULE13
    if sec_audit_findmnt_path_resolvable /tmp && sec_audit_findmnt_has_mnt_option /tmp nosuid; then
    sec_audit_report_pass 13 "nosuid option set on /tmp partition"
    elif ! sec_audit_findmnt_path_resolvable /tmp; then
    sec_audit_report_fail 13 "nosuid is not set on /tmp (or path not resolvable / not an explicit mount per policy)"
    else
    sec_audit_report_fail 13 "nosuid is not set on /tmp (or path not resolvable / not an explicit mount per policy)"
    fi

    # RULE14
    if sec_audit_findmnt_path_resolvable /tmp && sec_audit_findmnt_has_mnt_option /tmp noexec; then
    sec_audit_report_pass 14 "noexec option set on /tmp partition"
    elif ! sec_audit_findmnt_path_resolvable /tmp; then
    sec_audit_report_fail 14 "noexec is not set on /tmp (or path not resolvable / not an explicit mount per policy)"
    else
    sec_audit_report_fail 14 "noexec is not set on /tmp (or path not resolvable / not an explicit mount per policy)"
    fi

    # RULE15
    if sec_audit_findmnt_shm_sec_ok; then
    if sec_audit_mount_persisted /dev/shm; then
        sec_audit_report_pass 15 "/dev/shm is tmpfs or a separate partition"
    else
        sec_audit_report_fail 15 "/dev/shm is tmpfs or a separate partition is runtime-only (missing fstab or systemd .mount persistence)"
    fi
    else
    sec_audit_report_fail 15 "/dev/shm does not meet tmpfs or separate-partition requirement"
    fi

    # RULE16
    if sec_audit_findmnt_path_resolvable /dev/shm && sec_audit_findmnt_has_mnt_option /dev/shm nodev; then
    sec_audit_report_pass 16 "nodev option set on /dev/shm partition"
    elif ! sec_audit_findmnt_path_resolvable /dev/shm; then
    sec_audit_report_fail 16 "nodev is not set on /dev/shm (or path not resolvable / not an explicit mount per policy)"
    else
    sec_audit_report_fail 16 "nodev is not set on /dev/shm (or path not resolvable / not an explicit mount per policy)"
    fi

    # RULE17
    if sec_audit_findmnt_path_resolvable /dev/shm && sec_audit_findmnt_has_mnt_option /dev/shm nosuid; then
    sec_audit_report_pass 17 "nosuid option set on /dev/shm partition"
    elif ! sec_audit_findmnt_path_resolvable /dev/shm; then
    sec_audit_report_fail 17 "nosuid is not set on /dev/shm (or path not resolvable / not an explicit mount per policy)"
    else
    sec_audit_report_fail 17 "nosuid is not set on /dev/shm (or path not resolvable / not an explicit mount per policy)"
    fi

    # RULE18
    if sec_audit_findmnt_path_resolvable /dev/shm && sec_audit_findmnt_has_mnt_option /dev/shm noexec; then
    sec_audit_report_pass 18 "noexec option set on /dev/shm partition"
    elif ! sec_audit_findmnt_path_resolvable /dev/shm; then
    sec_audit_report_fail 18 "noexec is not set on /dev/shm (or path not resolvable / not an explicit mount per policy)"
    else
    sec_audit_report_fail 18 "noexec is not set on /dev/shm (or path not resolvable / not an explicit mount per policy)"
    fi

    # RULE19
    if sec_audit_findmnt_separate_partition_ok /home; then
    if sec_audit_mount_persisted /home; then
        sec_audit_report_pass 19 "separate partition exists for /home"
    else
        sec_audit_report_fail 19 "dedicated mount for /home is runtime-only (missing fstab or systemd .mount persistence)"
    fi
    else
    sec_audit_report_fail 19 "no compliant dedicated mount for /home"
    fi

    # RULE20
    if sec_audit_findmnt_path_resolvable /home && sec_audit_findmnt_has_mnt_option /home nodev; then
    sec_audit_report_pass 20 "nodev option set on /home partition"
    elif ! sec_audit_findmnt_path_resolvable /home; then
    sec_audit_report_fail 20 "nodev is not set on /home (or path not resolvable / not an explicit mount per policy)"
    else
    sec_audit_report_fail 20 "nodev is not set on /home (or path not resolvable / not an explicit mount per policy)"
    fi

    # RULE21
    if sec_audit_findmnt_path_resolvable /home && sec_audit_findmnt_has_mnt_option /home nosuid; then
    sec_audit_report_pass 21 "nosuid option set on /home partition"
    elif ! sec_audit_findmnt_path_resolvable /home; then
    sec_audit_report_fail 21 "nosuid is not set on /home (or path not resolvable / not an explicit mount per policy)"
    else
    sec_audit_report_fail 21 "nosuid is not set on /home (or path not resolvable / not an explicit mount per policy)"
    fi

    # RULE22
    if sec_audit_findmnt_separate_partition_ok /var; then
    if sec_audit_mount_persisted /var; then
        sec_audit_report_pass 22 "separate partition exists for /var"
    else
        sec_audit_report_fail 22 "dedicated mount for /var is runtime-only (missing fstab or systemd .mount persistence)"
    fi
    else
    sec_audit_report_fail 22 "no compliant dedicated mount for /var"
    fi

    # RULE23
    if sec_audit_findmnt_path_resolvable /var && sec_audit_findmnt_has_mnt_option /var nodev; then
    sec_audit_report_pass 23 "nodev option set on /var partition"
    elif ! sec_audit_findmnt_path_resolvable /var; then
    sec_audit_report_fail 23 "nodev is not set on /var (or path not resolvable / not an explicit mount per policy)"
    else
    sec_audit_report_fail 23 "nodev is not set on /var (or path not resolvable / not an explicit mount per policy)"
    fi

    # RULE24
    if sec_audit_findmnt_path_resolvable /var && sec_audit_findmnt_has_mnt_option /var nosuid; then
    sec_audit_report_pass 24 "nosuid option set on /var partition"
    elif ! sec_audit_findmnt_path_resolvable /var; then
    sec_audit_report_fail 24 "nosuid is not set on /var (or path not resolvable / not an explicit mount per policy)"
    else
    sec_audit_report_fail 24 "nosuid is not set on /var (or path not resolvable / not an explicit mount per policy)"
    fi

    # RULE25
    if sec_audit_findmnt_separate_partition_ok /var/tmp; then
    if sec_audit_mount_persisted /var/tmp; then
        sec_audit_report_pass 25 "separate partition exists for /var/tmp"
    else
        sec_audit_report_fail 25 "dedicated mount for /var/tmp is runtime-only (missing fstab or systemd .mount persistence)"
    fi
    else
    sec_audit_report_fail 25 "no compliant dedicated mount for /var/tmp"
    fi

    # RULE26
    if sec_audit_findmnt_path_resolvable /var/tmp && sec_audit_findmnt_has_mnt_option /var/tmp nodev; then
    sec_audit_report_pass 26 "nodev option set on /var/tmp partition"
    elif ! sec_audit_findmnt_path_resolvable /var/tmp; then
    sec_audit_report_fail 26 "nodev is not set on /var/tmp (or path not resolvable / not an explicit mount per policy)"
    else
    sec_audit_report_fail 26 "nodev is not set on /var/tmp (or path not resolvable / not an explicit mount per policy)"
    fi

    # RULE27
    if sec_audit_findmnt_path_resolvable /var/tmp && sec_audit_findmnt_has_mnt_option /var/tmp nosuid; then
    sec_audit_report_pass 27 "nosuid option set on /var/tmp partition"
    elif ! sec_audit_findmnt_path_resolvable /var/tmp; then
    sec_audit_report_fail 27 "nosuid is not set on /var/tmp (or path not resolvable / not an explicit mount per policy)"
    else
    sec_audit_report_fail 27 "nosuid is not set on /var/tmp (or path not resolvable / not an explicit mount per policy)"
    fi

    # RULE28
    if sec_audit_findmnt_path_resolvable /var/tmp && sec_audit_findmnt_has_mnt_option /var/tmp noexec; then
    sec_audit_report_pass 28 "noexec option set on /var/tmp partition"
    elif ! sec_audit_findmnt_path_resolvable /var/tmp; then
    sec_audit_report_fail 28 "noexec is not set on /var/tmp (or path not resolvable / not an explicit mount per policy)"
    else
    sec_audit_report_fail 28 "noexec is not set on /var/tmp (or path not resolvable / not an explicit mount per policy)"
    fi

    # RULE29
    if sec_audit_findmnt_separate_partition_ok /var/log; then
    if sec_audit_mount_persisted /var/log; then
        sec_audit_report_pass 29 "separate partition exists for /var/log"
    else
        sec_audit_report_fail 29 "dedicated mount for /var/log is runtime-only (missing fstab or systemd .mount persistence)"
    fi
    else
    sec_audit_report_fail 29 "no compliant dedicated mount for /var/log"
    fi

    # RULE30
    if sec_audit_findmnt_path_resolvable /var/log && sec_audit_findmnt_has_mnt_option /var/log nodev; then
    sec_audit_report_pass 30 "nodev option set on /var/log partition"
    elif ! sec_audit_findmnt_path_resolvable /var/log; then
    sec_audit_report_fail 30 "nodev is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
    else
    sec_audit_report_fail 30 "nodev is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
    fi

    # RULE31
    if sec_audit_findmnt_path_resolvable /var/log && sec_audit_findmnt_has_mnt_option /var/log nosuid; then
    sec_audit_report_pass 31 "nosuid option set on /var/log partition"
    elif ! sec_audit_findmnt_path_resolvable /var/log; then
    sec_audit_report_fail 31 "nosuid is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
    else
    sec_audit_report_fail 31 "nosuid is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
    fi

    # RULE32
    if sec_audit_findmnt_path_resolvable /var/log && sec_audit_findmnt_has_mnt_option /var/log noexec; then
    sec_audit_report_pass 32 "noexec option set on /var/log partition"
    elif ! sec_audit_findmnt_path_resolvable /var/log; then
    sec_audit_report_fail 32 "noexec is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
    else
    sec_audit_report_fail 32 "noexec is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
    fi

    # RULE33
    if sec_audit_findmnt_separate_partition_ok /var/log/audit; then
    if sec_audit_mount_persisted /var/log/audit; then
        sec_audit_report_pass 33 "separate partition exists for /var/log/audit"
    else
        sec_audit_report_fail 33 "dedicated mount for /var/log/audit is runtime-only (missing fstab or systemd .mount persistence)"
    fi
    else
    sec_audit_report_fail 33 "no compliant dedicated mount for /var/log/audit"
    fi

    # RULE34
    if sec_audit_findmnt_path_resolvable /var/log/audit && sec_audit_findmnt_has_mnt_option /var/log/audit nodev; then
    sec_audit_report_pass 34 "nodev option set on /var/log/audit partition"
    elif ! sec_audit_findmnt_path_resolvable /var/log/audit; then
    sec_audit_report_fail 34 "nodev is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
    else
    sec_audit_report_fail 34 "nodev is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
    fi

    # RULE35
    if sec_audit_findmnt_path_resolvable /var/log/audit && sec_audit_findmnt_has_mnt_option /var/log/audit nosuid; then
    sec_audit_report_pass 35 "nosuid option set on /var/log/audit partition"
    elif ! sec_audit_findmnt_path_resolvable /var/log/audit; then
    sec_audit_report_fail 35 "nosuid is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
    else
    sec_audit_report_fail 35 "nosuid is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
    fi

    # RULE36
    if sec_audit_findmnt_path_resolvable /var/log/audit && sec_audit_findmnt_has_mnt_option /var/log/audit noexec; then
    sec_audit_report_pass 36 "noexec option set on /var/log/audit partition"
    elif ! sec_audit_findmnt_path_resolvable /var/log/audit; then
    sec_audit_report_fail 36 "noexec is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
    else
    sec_audit_report_fail 36 "noexec is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
    fi

}

sec_audit_run_package_security() {
    # RULE37
    if [[ -f /etc/apt/sources.list ]] || compgen -G '/etc/apt/sources.list.d/*' >/dev/null 2>&1; then
        if sec_audit_apt_allow_unauthenticated_false; then
            sec_audit_report_pass 37 "apt sources present and APT::Get::AllowUnauthenticated is not enabled"
        else
            sec_audit_report_fail 37 "APT::Get::AllowUnauthenticated is enabled (unauthenticated packages allowed)"
        fi
    else
        sec_audit_report_fail 37 "/etc/apt/sources.list and sources.list.d are missing or empty"
    fi

}

sec_audit_run_apparmor() {
    # RULE38
    if sec_audit_pkg_is_installed apparmor; then
        sec_audit_report_pass 38 "AppArmor package is installed"
    else
        sec_audit_report_fail 38 "AppArmor package is not installed"
    fi

    # RULE39
    if sec_audit_apparmor_bootloader_enabled; then
        sec_audit_report_pass 39 "AppArmor enabled in bootloader (apparmor=1 and security=apparmor)"
    else
        sec_audit_report_fail 39 "AppArmor is not enabled in bootloader configuration"
    fi

    # RULE40
    if sec_audit_apparmor_profiles_enforce_or_complain_ok; then
        sec_audit_report_pass 40 "all AppArmor profiles are in enforce or complain mode"
    else
        sec_audit_report_fail 40 "some AppArmor profiles are unconfined or AppArmor status is unavailable"
    fi

    # RULE41
    if sec_audit_apparmor_profiles_all_enforcing_ok; then
        sec_audit_report_pass 41 "all AppArmor profiles are in enforce mode"
    else
        sec_audit_report_fail 41 "some AppArmor profiles are not in enforce mode"
    fi

}

sec_audit_run_bootloader() {
    # RULE42
    if sec_audit_grub_cfg_grep '^[[:space:]]*set superusers' && sec_audit_grub_cfg_grep 'password_pbkdf2'; then
    sec_audit_report_pass 42 "bootloader password is set (grub.cfg under /boot/grub2 or EFI)"
    else
    sec_audit_report_fail 42 "GRUB bootloader superuser/password_pbkdf2 is not configured as required in grub.cfg"
    fi

}

sec_audit_run_process_hardening() {
    # RULE43
    if sec_audit_limits_core_zero_and_systemd_ok; then
    sec_audit_report_pass 43 "limits * hard core 0 present and systemd DefaultLimitCORE does not allow unlimited core dumps"
    elif grep -Psi '^\*\s+hard\s+core\s+0\b' /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null; then
    sec_audit_report_fail 43 "limits.conf sets hard core 0 but systemd DefaultLimitCORE contradicts (check system.conf / user.conf drop-ins)"
    else
    sec_audit_report_fail 43 "core file size limits are not configured (limits * hard core 0 not found)"
    fi

    # RULE44
    sec_audit_assert_sysctl_equals 44 fs.protected_hardlinks 1

    # RULE45
    sec_audit_assert_sysctl_equals 45 fs.protected_symlinks 1

    # RULE46
    sec_audit_assert_sysctl_equals 46 fs.suid_dumpable 0

    # RULE47
    sec_audit_assert_sysctl_equals 47 kernel.dmesg_restrict 1

    # RULE48
    sec_audit_assert_sysctl_equals 48 kernel.kptr_restrict 2

    # RULE49
    sec_audit_assert_sysctl_equals 49 kernel.yama.ptrace_scope 1

    # RULE50
    sec_audit_assert_sysctl_equals 50 kernel.randomize_va_space 2

    # RULE51
    _rule59_cat=$(systemd-analyze cat-config systemd/coredump.conf 2>/dev/null)
    _rule59_corep=$(sec_audit_sysctl_key_runtime kernel.core_pattern)
    if builtin printf '%s\n' "$_rule59_cat" | grep -Pq '^\h*ProcessSizeMax=\h*0\b'; then
    if [[ "$_rule59_corep" == *systemd-coredump* ]] || [[ "$_rule59_corep" == *coredump* ]]; then
        sec_audit_report_pass 51 "merged coredump.conf sets ProcessSizeMax=0; kernel.core_pattern uses systemd-coredump"
    else
        sec_audit_report_pass 51 "merged coredump.conf sets ProcessSizeMax=0 (kernel.core_pattern='${_rule59_corep:-?}' may omit systemd-coredump text)"
    fi
    else
    sec_audit_report_fail 51 "merged systemd/coredump.conf does not set ProcessSizeMax=0"
    fi

    # RULE52
    CORE_LIMIT=$(ulimit -c 2>/dev/null)
    if grep -Psi '^\h*\*\h+hard\h+core\h+0\b' /etc/security/limits.conf /etc/security/limits.d/*.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 52 "core file size is configured (hard limit core=0)"
    elif [ "$CORE_LIMIT" = "0" ]; then
    sec_audit_report_pass 52 "core file size is configured (ulimit -c is 0)"
    else
    sec_audit_report_fail 52 "core file hard limit is not set to 0 in /etc/security/limits.conf"
    fi

}

sec_audit_run_banners() {
    # RULE53
    if grep -Pi '^\h*LEGACY\b' /etc/crypto-policies/config 2>/dev/null; then
    sec_audit_report_fail 53 "System-wide crypto policy is LEGACY in /etc/crypto-policies/config"
    else
    sec_audit_report_pass 53 "system wide crypto policy is not set to legacy"
    fi

    # RULE54
    if grep -Pqs "(\\\v|\\\r|\\\m|\\\s|\b$(grep ^ID= /etc/os-release 2>/dev/null | cut -d= -f2 | sed -e 's/"//g')\b)" /etc/issue 2>/dev/null; then
    sec_audit_report_fail 54 "/etc/issue contains system info escape sequences"
    else
    sec_audit_report_pass 54 "/etc/issue is configured"
    fi

    # RULE55
    if grep -Pi '(^\h*mac\h*=\h*([^#\n\r]+)?-128|hmac-sha1)' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null; then
    sec_audit_report_fail 55 "Weak MAC algorithms still present in /etc/crypto-policies/state/CURRENT.pol"
    else
    sec_audit_report_pass 55 "system wide crypto policy macs are configured"
    fi

}

sec_audit_run_gdm() {
    # RULE56
    if grep -Pqs "(\\\v|\\\r|\\\m|\\\s|\b$(grep ^ID= /etc/os-release 2>/dev/null | cut -d= -f2 | sed -e 's/"//g')\b)" /etc/motd 2>/dev/null; then
    sec_audit_report_fail 56 "/etc/motd is missing or does not contain required banner content"
    else
    sec_audit_report_pass 56 "/etc/motd is configured"
    fi

}

sec_audit_run_unused_services() {
    # RULE57
    sec_audit_assert_service_unused 57 autofs "autofs services are not in use" "autofs services are installed and enabled or actively running" "autofs.service"

    # RULE58
    sec_audit_assert_service_unused 58 avahi "avahi daemon services are not in use" "avahi daemon services are installed and enabled or actively running" "avahi-daemon.socket" "avahi-daemon.service"

    # RULE59
    sec_audit_assert_service_unused 59 cockpit-ws "cockpit web services are not in use" "cockpit web services are installed and enabled or actively running" "cockpit.socket" "cockpit.service"

    # RULE60
    sec_audit_assert_service_unused 60 dhcp-server "dhcp server services are not in use" "dhcp server services are installed and enabled or actively running" "dhcpd.service" "dhcpd6.service"

    # RULE61
    sec_audit_assert_service_unused 61 bind "dns server services are not in use" "dns server services are installed and enabled or actively running" "named.service"

    # RULE62
    sec_audit_assert_service_unused 62 dnsmasq "dnsmasq services are not in use" "dnsmasq services are installed and enabled or actively running" "dnsmasq.service"

    # RULE63
    sec_audit_assert_service_unused 63 vsftpd "ftp server services are not in use" "ftp server services are installed and enabled or actively running" "vsftpd.service"

    # RULE64
    if sec_audit_pkg_any_installed dovecot cyrus-imapd; then
    if sec_audit_systemd_unit_enabled_or_active dovecot.socket dovecot.service cyrus-imapd.service; then
        sec_audit_report_fail 64 "message access server services are installed and enabled or actively running"
    else
        sec_audit_report_pass 64 "message access server services are not in use (package present but units masked/disabled/inactive)"
    fi
    else
    sec_audit_report_pass 64 "message access server services are not in use"
    fi

    # RULE65
    sec_audit_assert_service_unused 65 nfs-utils "network file system services are not in use" "network file system services are installed and enabled or actively running" "nfs-server.service"

    # RULE66
    sec_audit_assert_service_unused 66 cups "print server services are not in use" "print server services are installed and enabled or actively running" "cups.socket" "cups.service"

    # RULE67
    sec_audit_assert_service_unused 67 rpcbind "rpcbind services are not in use" "rpcbind services are installed and enabled or actively running" "rpcbind.socket" "rpcbind.service"

    # RULE68
    sec_audit_assert_service_unused 68 rsync-daemon "rsync services are not in use" "rsync services are installed and enabled or actively running" "rsyncd.socket" "rsyncd.service"

    # RULE69
    sec_audit_assert_service_unused 69 samba "samba file server services are not in use" "samba file server services are installed and enabled or actively running" "smb.service"

    # RULE70
    sec_audit_assert_service_unused 70 net-snmp "snmp services are not in use" "snmp services are installed and enabled or actively running" "snmpd.service"

    # RULE71
    sec_audit_assert_service_unused 71 telnet-server "telnet server services are not in use" "telnet server services are installed and enabled or actively running" "telnet.socket"

    # RULE72
    sec_audit_assert_service_unused 72 tftp-server "tftp server services are not in use" "tftp server services are installed and enabled or actively running" "tftp.socket" "tftp.service"

    # RULE73
    sec_audit_assert_service_unused 73 squid "web proxy server services are not in use" "web proxy server services are installed and enabled or actively running" "squid.service"

    # RULE74
    if sec_audit_pkg_any_installed httpd nginx; then
    if sec_audit_systemd_unit_enabled_or_active httpd.service nginx.service; then
        sec_audit_report_fail 74 "web server services are installed and enabled or actively running"
    else
        sec_audit_report_pass 74 "web server services are not in use (package present but units masked/disabled/inactive)"
    fi
    else
    sec_audit_report_pass 74 "web server services are not in use"
    fi

    # RULE75
    if sec_audit_pkg_is_installed gdm || systemctl is-enabled gdm 2>/dev/null | grep -q 'enabled' || systemctl is-active gdm 2>/dev/null | grep -q '^active'; then
    sec_audit_report_fail 75 "GNOME Display Manager (gdm) package is still installed"
    else
    sec_audit_report_pass 75 "GNOME Display Manager is removed"
    fi

    # RULE76
    if sec_audit_pkg_is_installed xorg-x11-server-Xwayland; then
    sec_audit_report_fail 76 "X window server services are installed and enabled or actively running"
    else
    sec_audit_report_pass 76 "X window server services are not in use"
    fi

}

sec_audit_run_client_tools() {
    # RULE77
    if sec_audit_pkg_is_installed xserver-xorg-core || sec_audit_pkg_is_installed xorg; then
    sec_audit_report_fail 77 "X window server package (xserver-xorg-core or xorg) is installed"
    else
    sec_audit_report_pass 77 "X window server services are not in use"
    fi

    # RULE78
    if ss -lntu 2>/dev/null | grep -E ':25\b' | grep -qvE '127\.0\.0\.1:25|::1:25|\[::1\]:25'; then
    sec_audit_report_fail 78 "mail transfer agent is listening on a non-loopback interface (port 25)"
    elif ss -lntu 2>/dev/null | grep -qE ':25\b'; then
    sec_audit_report_pass 78 "mail transfer agents are configured for local-only mode"
    else
    sec_audit_report_pass 78 "mail transfer agents are configured for local-only mode (no MTA listening)"
    fi

    # RULE79
    if sec_audit_pkg_is_installed ftp; then
    sec_audit_report_fail 79 "ftp client package is installed"
    else
    sec_audit_report_pass 79 "ftp client is not installed"
    fi

    # RULE80
    if sec_audit_pkg_is_installed rsh || sec_audit_pkg_is_installed rsh; then
    sec_audit_report_fail 80 "package rsh is installed"
    else
    sec_audit_report_pass 80 "package rsh is not installed"
    fi

    # RULE81
    if sec_audit_pkg_is_installed talk || sec_audit_pkg_is_installed talk; then
    sec_audit_report_fail 81 "package talk is installed"
    else
    sec_audit_report_pass 81 "package talk is not installed"
    fi

    # RULE82
    if sec_audit_pkg_is_installed telnet || sec_audit_pkg_is_installed telnet; then
    sec_audit_report_fail 82 "package telnet is installed"
    else
    sec_audit_report_pass 82 "package telnet is not installed"
    fi

    # RULE83
    if sec_audit_pkg_is_installed ldap-utils || sec_audit_pkg_is_installed libldap-common; then
    sec_audit_report_fail 83 "ldap client package is installed"
    else
    sec_audit_report_pass 83 "ldap client is not installed"
    fi

    # RULE84
    if sec_audit_pkg_is_installed ftp || sec_audit_pkg_is_installed lftp; then
    sec_audit_report_fail 84 "ftp client package is installed"
    else
    sec_audit_report_pass 84 "ftp client is not installed"
    fi

}

sec_audit_run_time_sync() {
    # RULE85
    NTP_COUNT=0
    systemctl is-active chronyd.service &>/dev/null && NTP_COUNT=$((NTP_COUNT+1))
    systemctl is-active systemd-timesyncd.service &>/dev/null && NTP_COUNT=$((NTP_COUNT+1))
    systemctl is-active ntp.service &>/dev/null && NTP_COUNT=$((NTP_COUNT+1))
    if [ "$NTP_COUNT" -eq 1 ]; then
    sec_audit_report_pass 85 "a single time synchronization daemon is in use"
    elif [ "$NTP_COUNT" -eq 0 ]; then
    sec_audit_report_fail 85 "no time synchronization daemon is active"
    else
    sec_audit_report_fail 85 "multiple time synchronization daemons are active ($NTP_COUNT)"
    fi

    # RULE86
    if systemctl is-enabled systemd-timesyncd.service 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active systemd-timesyncd.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_pass 86 "systemd-timesyncd is enabled and running"
    else
        sec_audit_report_fail 86 "systemd-timesyncd is enabled but not active"
    fi
    else
    sec_audit_report_fail 86 "systemd-timesyncd is not enabled (may be using chrony instead - check RULE85)"
    fi

    # RULE87
    if systemctl is-active chronyd.service &>/dev/null; then
    CHRONY_USER=$(ps -eo user:20,comm 2>/dev/null | awk '$2~/^chronyd?$/{print $1}' | head -1)
    if [ "$CHRONY_USER" = "_chrony" ] || [ "$CHRONY_USER" = "chrony" ]; then
        sec_audit_report_pass 87 "chrony is running as user $CHRONY_USER"
    else
        sec_audit_report_fail 87 "chrony is not running as _chrony (running as: ${CHRONY_USER:-unknown})"
    fi
    else
    sec_audit_report_pass 87 "chrony is not active (not applicable)"
    fi

    # RULE88
    if systemctl is-enabled chronyd.service 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active chronyd.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_pass 88 "chrony is enabled and running"
    else
        sec_audit_report_fail 88 "chronyd service is enabled but not active"
    fi
    else
    sec_audit_report_fail 88 "chronyd service is not enabled (may be using systemd-timesyncd instead)"
    fi

}

sec_audit_run_cron_at() {
    # RULE89
    if systemctl is-enabled crond.service 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active crond.service 2>/dev/null | grep -q 'active'; then
        sec_audit_report_pass 89 "cron daemon is enabled and active"
    else
        sec_audit_report_fail 89 "crond service is not enabled or not active"
    fi
    else
    sec_audit_report_fail 89 "crond service is not enabled or not active"
    fi

}

sec_audit_run_network_stack() {
    # RULE90
    if compgen -G "/sys/class/net/*/wireless" >/dev/null; then
    sec_audit_report_fail 90 "Wireless interfaces are present under /sys/class/net"
    else
    sec_audit_report_pass 90 "wireless interfaces are not available"
    fi

    # RULE91
    sec_audit_assert_service_unused 91 bluez "bluetooth services are not in use" "bluetooth services are installed and enabled or actively running" "bluetooth.service"

    # RULE92
    sec_audit_assert_kmod_disabled 92 "atm kernel module" atm atm.ko* "atm"

    # RULE93
    sec_audit_assert_kmod_disabled 93 "can kernel module" can can.ko* "can"

    # RULE94
    sec_audit_assert_kmod_disabled 94 "dccp kernel module" dccp dccp.ko* "dccp"

    # RULE95
    sec_audit_assert_kmod_disabled 95 "tipc kernel module" tipc tipc.ko* "tipc"

    # RULE96
    sec_audit_assert_kmod_disabled 96 "rds kernel module" rds rds.ko* "rds"

    # RULE97
    sec_audit_assert_kmod_disabled 97 "sctp kernel module" sctp sctp.ko* "sctp"

    # RULE98
    sec_audit_assert_sysctl_equals 98 net.ipv4.ip_forward 0

    # RULE99
    sec_audit_assert_sysctl_equals 99 net.ipv4.conf.all.forwarding 0

    # RULE100
    sec_audit_assert_sysctl_equals 100 net.ipv4.conf.default.forwarding 0

    # RULE101
    sec_audit_assert_sysctl_equals 101 net.ipv4.conf.all.send_redirects 0

    # RULE102
    sec_audit_assert_sysctl_equals 102 net.ipv4.conf.default.send_redirects 0

    # RULE103
    sec_audit_assert_sysctl_equals 103 net.ipv4.icmp_ignore_bogus_error_responses 1

    # RULE104
    sec_audit_assert_sysctl_equals 104 net.ipv4.icmp_echo_ignore_broadcasts 1

    # RULE105
    sec_audit_assert_sysctl_equals 105 net.ipv4.conf.all.accept_redirects 0

    # RULE106
    sec_audit_assert_sysctl_equals 106 net.ipv4.conf.default.accept_redirects 0

    # RULE107
    sec_audit_assert_sysctl_equals 107 net.ipv4.conf.all.secure_redirects 0

    # RULE108
    sec_audit_assert_sysctl_equals 108 net.ipv4.conf.default.secure_redirects 0

    # RULE109
    sec_audit_assert_sysctl_equals 109 net.ipv4.conf.all.rp_filter 1

    # RULE110
    sec_audit_assert_sysctl_equals 110 net.ipv4.conf.default.rp_filter 1

    # RULE111
    sec_audit_assert_sysctl_equals 111 net.ipv4.conf.all.accept_source_route 0

    # RULE112
    sec_audit_assert_sysctl_equals 112 net.ipv4.conf.default.accept_source_route 0

    # RULE113
    sec_audit_assert_sysctl_equals 113 net.ipv4.conf.all.log_martians 1

    # RULE114
    sec_audit_assert_sysctl_equals 114 net.ipv4.conf.default.log_martians 1

    # RULE115
    sec_audit_assert_sysctl_equals 115 net.ipv4.tcp_syncookies 1

    # RULE116
    sec_audit_assert_sysctl_equals 116 net.ipv6.conf.all.forwarding 0

    # RULE117
    sec_audit_assert_sysctl_equals 117 net.ipv6.conf.default.forwarding 0

    # RULE118
    sec_audit_assert_sysctl_equals 118 net.ipv6.conf.all.accept_redirects 0

    # RULE119
    sec_audit_assert_sysctl_equals 119 net.ipv6.conf.default.accept_redirects 0

    # RULE120
    sec_audit_assert_sysctl_equals 120 net.ipv6.conf.all.accept_source_route 0

    # RULE121
    sec_audit_assert_sysctl_equals 121 net.ipv6.conf.default.accept_source_route 0

    # RULE122
    sec_audit_assert_sysctl_equals 122 net.ipv6.conf.all.accept_ra 0

    # RULE123
    sec_audit_assert_sysctl_equals 123 net.ipv6.conf.default.accept_ra 0

}

sec_audit_run_firewall() {
    # RULE124
    if sec_audit_pkg_is_installed firewalld; then
    sec_audit_report_pass 124 "firewalld is installed"
    else
    sec_audit_report_fail 124 "firewalld package is not installed"
    fi

    # RULE125
    if grep -Psi 'FirewallBackend\h*=\h*nftables\b' /etc/firewalld/firewalld.conf 2>/dev/null; then
    _fw140_be=""
    if sec_audit_have_bin firewall-cmd && firewall-cmd --state 2>/dev/null | grep -qi running; then
        _fw140_be=$(firewall-cmd --get-backend 2>/dev/null)
        if [[ "$_fw140_be" == "nftables" ]]; then
            sec_audit_report_pass 125 "firewalld.conf uses nftables and runtime backend is nftables"
        else
            sec_audit_report_pass 125 "firewalld.conf uses nftables (runtime backend reports '${_fw140_be:-?}')"
        fi
    else
        sec_audit_report_pass 125 "firewalld.conf uses nftables (firewalld not running; runtime backend not verified)"
    fi
    else
    sec_audit_report_fail 125 "firewalld backend is not configured (FirewallBackend=nftables missing in firewalld.conf)"
    fi

    # RULE126
    if systemctl is-enabled firewalld.service 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active firewalld.service 2>/dev/null | grep -q 'active'; then
        _fw141_nft=""
        if sec_audit_have_bin nft && nft list ruleset 2>/dev/null | grep -q .; then
            _fw141_nft="; nftables ruleset is non-empty"
        fi
        sec_audit_report_pass 126 "firewalld.service is enabled and active${_fw141_nft}"
    else
        sec_audit_report_fail 126 "firewalld.service is not enabled or not active"
    fi
    else
    sec_audit_report_fail 126 "firewalld.service is not enabled or not active"
    fi

    # RULE127
    if systemctl is-active firewalld &>/dev/null; then
    ACTIVE_ZONE=$(firewall-cmd --get-default-zone 2>/dev/null)
    ZONE_TARGET=$(firewall-cmd --zone="$ACTIVE_ZONE" --get-target 2>/dev/null)
    _fw142_if=$(firewall-cmd --zone="$ACTIVE_ZONE" --list-interfaces 2>/dev/null | wc -w)
    if [ "$ZONE_TARGET" = "DROP" ] || [ "$ZONE_TARGET" = "REJECT" ]; then
        sec_audit_report_pass 127 "firewalld default zone '$ACTIVE_ZONE' target is $ZONE_TARGET (${_fw142_if:-0} interface(s) assigned)"
    else
        sec_audit_report_fail 127 "firewalld active zone target is not secure (current: $ZONE_TARGET)"
    fi
    else
    sec_audit_report_fail 127 "firewalld is not active"
    fi

    # RULE128
    if systemctl is-active firewalld &>/dev/null; then
    if firewall-cmd --list-rich-rules 2>/dev/null | grep -Eiq 'lo|loopback|127\.0\.0\.1|interface\s*=\s*\"lo\"|interface\s*=\s*lo\b'; then
        sec_audit_report_pass 128 "firewalld rich rules mention loopback / lo / localhost"
    else
        sec_audit_report_fail 128 "firewalld loopback traffic is not configured"
    fi
    else
    sec_audit_report_fail 128 "firewalld is not active"
    fi

}

sec_audit_run_sshd() {
    # RULE129
    if stat -Lc '%a' /etc/ssh/sshd_config 2>/dev/null | grep -q '^600$'; then
    if stat -Lc '%U:%G' /etc/ssh/sshd_config 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 129 "access to /etc/ssh/sshd_config is configured"
    else
        sec_audit_report_fail 129 "File /etc/ssh/sshd_config permissions or ownership not correct"
    fi
    else
    sec_audit_report_fail 129 "File /etc/ssh/sshd_config permissions or ownership not correct"
    fi

    if ! sec_audit_sshd_effective_usable; then
    for _sshn in 130 131 132 133 134 135 136 137 138 139 140 141 142 143 144 145 146 147 148 149 150 151; do
        sec_audit_report_fail "$_sshn" "unable_to_evaluate: sshd -T produced no effective configuration"
    done
    else

    # RULE130
    PRIV_KEYS=$(sec_audit_sshd_effective_dump | awk '$1=="hostkey" {print $2}')
    FAIL130=0
    for key in $PRIV_KEYS; do
    if [ -f "$key" ]; then
        if ! stat -Lc '%a' "$key" 2>/dev/null | grep -q '^600$'; then
            FAIL130=1
        fi
        if ! stat -Lc '%U:%G' "$key" 2>/dev/null | grep -q '^root:root$'; then
            FAIL130=1
        fi
    else
        FAIL130=1
    fi
    done
    if [ $FAIL130 -eq 0 ]; then
    sec_audit_report_pass 130 "access to SSH private host key files is configured"
    else
    sec_audit_report_fail 130 "File SSH private host key files permissions or ownership not correct"
    fi

    # RULE131
    PUB_KEYS=$(sec_audit_sshd_effective_dump | awk '$1=="hostkey" {print $2".pub"}')
    FAIL131=0
    for key in $PUB_KEYS; do
    if [ -f "$key" ]; then
        if ! stat -Lc '%a' "$key" 2>/dev/null | grep -qE '^[0-6]44$'; then
            FAIL131=1
        fi
        if ! stat -Lc '%U:%G' "$key" 2>/dev/null | grep -q '^root:root$'; then
            FAIL131=1
        fi
    else
        FAIL131=1
    fi
    done
    if [ $FAIL131 -eq 0 ]; then
    sec_audit_report_pass 131 "access to SSH public host key files is configured"
    else
    sec_audit_report_fail 131 "File SSH public host key files permissions or ownership not correct"
    fi

    # RULE132
    if sec_audit_sshd_t_grep -Piq '^\h*(allow|deny)(users|groups)\h+\H+'; then
    sec_audit_report_pass 132 "sshd access is configured"
    else
    sec_audit_report_fail 132 "sshd access controls (AllowUsers/DenyUsers/AllowGroups/DenyGroups) are not set as required"
    fi

    # RULE133
    if sec_audit_sshd_t_grep -Piq '^banner\h+\/\H+'; then
    sec_audit_report_pass 133 "sshd Banner is configured"
    else
    sec_audit_report_fail 133 "sshd Banner does not meet the required policy (see sshd -T)"
    fi

    # RULE134
    if sec_audit_sshd_t_grep -Piq '^ciphers\h+\"?([^#\n\r]+,)?((3des|blowfish|cast128|aes(128|192|256))-cbc|arcfour(128|256)?|rijndael-cbc@lysator\.liu\.se)\b'; then
    sec_audit_report_fail 134 "sshd Ciphers allow weak or legacy algorithms (see sshd -T)"
    else
    sec_audit_report_pass 134 "sshd Ciphers are configured"
    fi

    # RULE135
    if sec_audit_sshd_t_grep -Piq 'clientaliveinterval\s+([1-9]|[1-9][0-9]+)'; then
    if sec_audit_sshd_t_grep -Piq 'clientalivecountmax\s+([1-9]|[1-9][0-9]+)'; then
        sec_audit_report_pass 135 "sshd ClientAliveInterval and ClientAliveCountMax are configured"
    else
        sec_audit_report_fail 135 "sshd ClientAliveInterval and ClientAliveCountMax are not configured as required (see sshd -T)"
    fi
    else
    sec_audit_report_fail 135 "sshd ClientAliveInterval and ClientAliveCountMax are not configured as required (see sshd -T)"
    fi

    # RULE136
    if sec_audit_sshd_t_grep -iq 'disableforwarding yes'; then
    sec_audit_report_pass 136 "sshd DisableForwarding is enabled"
    else
    sec_audit_report_fail 136 "sshd DisableForwarding is not enabled in effective sshd -T output"
    fi

    # RULE137
    if sec_audit_sshd_t_grep -iq 'gssapiauthentication no'; then
    sec_audit_report_pass 137 "sshd GSSAPIAuthentication is disabled"
    else
    sec_audit_report_fail 137 "sshd GSSAPIAuthentication is not disabled in effective sshd -T output"
    fi

    # RULE138
    if sec_audit_sshd_t_grep -iq 'hostbasedauthentication no'; then
    sec_audit_report_pass 138 "sshd HostbasedAuthentication is disabled"
    else
    sec_audit_report_fail 138 "sshd HostbasedAuthentication is not disabled in effective sshd -T output"
    fi

    # RULE139
    if sec_audit_sshd_t_grep -iq 'ignorerhosts yes'; then
    sec_audit_report_pass 139 "sshd IgnoreRhosts is enabled"
    else
    sec_audit_report_fail 139 "sshd IgnoreRhosts is not enabled in effective sshd -T output"
    fi

    # RULE140
    if sec_audit_sshd_t_grep -Piq 'kexalgorithms\h+([^#\n\r]+,)?(diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1)\b'; then
    sec_audit_report_fail 140 "sshd KexAlgorithms does not meet the required policy (see sshd -T)"
    else
    sec_audit_report_pass 140 "sshd KexAlgorithms is configured"
    fi

    # RULE141
    if sec_audit_sshd_t_grep -Piq 'logingracetime\s+([1-9]|[1-5][0-9]|60)\b'; then
    sec_audit_report_pass 141 "sshd LoginGraceTime is configured"
    else
    sec_audit_report_fail 141 "sshd LoginGraceTime does not meet the required policy (see sshd -T)"
    fi

    # RULE142
    if sec_audit_sshd_t_grep -iq 'loglevel VERBOSE\|loglevel INFO'; then
    sec_audit_report_pass 142 "sshd LogLevel is configured"
    else
    sec_audit_report_fail 142 "sshd LogLevel does not meet the required policy (see sshd -T)"
    fi

    # RULE143
    if sec_audit_sshd_t_grep -Piq 'macs\h+([^#\n\r]+,)?(hmac-md5|hmac-md5-96|hmac-ripemd160|hmac-sha1-96|umac-64@openssh\.com|hmac-md5-etm@openssh\.com|hmac-md5-96-etm@openssh\.com|hmac-ripemd160-etm@openssh\.com|hmac-sha1-96-etm@openssh\.com|umac-64-etm@openssh\.com|umac-128-etm@openssh\.com)\b'; then
    sec_audit_report_fail 143 "sshd MACs allow weak or legacy algorithms (see sshd -T)"
    else
    sec_audit_report_pass 143 "sshd MACs are configured"
    fi

    # RULE144
    if sec_audit_sshd_t_grep -Piq 'maxauthtries\s+[1-4]\b'; then
    sec_audit_report_pass 144 "sshd MaxAuthTries is configured"
    else
    sec_audit_report_fail 144 "sshd MaxAuthTries does not meet the required policy (see sshd -T)"
    fi

    # RULE145
    if sec_audit_sshd_t_awk '$1 ~ /^\s*maxstartups/{split($2, a, ":");{if(a[1] <= 10 && a[2] <= 30 && a[3] <= 60) print "ok"}}' | grep -q "ok"; then
    sec_audit_report_pass 145 "sshd MaxStartups is configured"
    else
    sec_audit_report_fail 145 "sshd MaxStartups does not meet the required policy (see sshd -T)"
    fi

    # RULE146
    if sec_audit_sshd_t_grep -Piq 'maxsessions\s+([1-9]|10)\b'; then
    sec_audit_report_pass 146 "sshd MaxSessions is configured"
    else
    sec_audit_report_fail 146 "sshd MaxSessions does not meet the required policy (see sshd -T)"
    fi

    # RULE147
    if sec_audit_sshd_t_grep -iq 'permitemptypasswords no'; then
    sec_audit_report_pass 147 "sshd PermitEmptyPasswords is disabled"
    else
    sec_audit_report_fail 147 "sshd PermitEmptyPasswords is not disabled in effective sshd -T output"
    fi

    # RULE148
    if sec_audit_sshd_t_grep -iq 'permitrootlogin no'; then
    sec_audit_report_pass 148 "sshd PermitRootLogin is disabled"
    else
    sec_audit_report_fail 148 "sshd PermitRootLogin is not disabled in effective sshd -T output"
    fi

    # RULE149
    if sec_audit_sshd_t_grep -iq 'permituserenvironment no'; then
    sec_audit_report_pass 149 "sshd PermitUserEnvironment is disabled"
    else
    sec_audit_report_fail 149 "sshd PermitUserEnvironment is not disabled in effective sshd -T output"
    fi

    # RULE150
    if sec_audit_sshd_t_grep -iq 'usepam yes'; then
    sec_audit_report_pass 150 "sshd UsePAM is enabled"
    else
    sec_audit_report_fail 150 "sshd UsePAM is not enabled in effective sshd -T output"
    fi

    # RULE151
    if sec_audit_sshd_t_grep -iq 'usepam yes' 2>/dev/null; then
    sec_audit_report_pass 151 "sshd UsePAM is enabled"
    else
    sec_audit_report_fail 151 "sshd UsePAM is not enabled in effective sshd -T output"
    fi

    fi

}

sec_audit_run_sudo_su() {
    # RULE152
    if sec_audit_pkg_is_installed sudo; then
    sec_audit_report_pass 152 "sudo is installed"
    else
    sec_audit_report_fail 152 "sudo package is not installed"
    fi

    # RULE153
    if grep -rPqs '^\h*Defaults\h+([^#\n\r]+,\h*)?use_pty\b' /etc/sudoers* 2>/dev/null; then
    if ! grep -rPqs '^\h*Defaults\h+([^#\n\r]+,\h*)?!use_pty\b' /etc/sudoers* 2>/dev/null; then
        sec_audit_report_pass 153 "sudo commands use pty"
    else
        sec_audit_report_fail 153 "sudo is not configured to require a pseudo-terminal (use_pty)"
    fi
    else
    sec_audit_report_fail 153 "sudo is not configured to require a pseudo-terminal (use_pty)"
    fi

    # RULE154
    if grep -rPqs "^\h*Defaults\h+([^#]+,\h*)?logfile\h*=\h*(\"|\')?\H+(\"|\')?(,\h*\H+\h*)*\h*(#.*)?$" /etc/sudoers* 2>/dev/null; then
    sec_audit_report_pass 154 "sudo log file exists"
    else
    sec_audit_report_fail 154 "sudo log file is missing or not configured"
    fi

    # RULE155
    if grep -rq "^[^#].*NOPASSWD" /etc/sudoers* 2>/dev/null; then
    sec_audit_report_fail 155 "NOPASSWD or password-less sudo rules violate escalation policy"
    else
    sec_audit_report_pass 155 "users must provide password for escalation"
    fi

    # RULE156
    if grep -rPi '^\h*Defaults\h+([^#\n\r]+,\h*)?!authenticate\b' /etc/sudoers* 2>/dev/null | grep -q .; then
    sec_audit_report_fail 156 "sudo re-authentication is globally disabled (!authenticate found in sudoers)"
    else
    sec_audit_report_pass 156 "re-authentication for privilege escalation is not disabled globally"
    fi

    # RULE157
    TIMEOUT=$(sudo -V 2>/dev/null | grep "Authentication timestamp timeout:" | awk '{print $4}')
    TIMEOUT_INT=${TIMEOUT%%.*}
    if [ -n "$TIMEOUT_INT" ]; then
    if [ "$TIMEOUT_INT" -ge 0 ] && [ "$TIMEOUT_INT" -le 15 ]; then
        sec_audit_report_pass 157 "sudo timestamp_timeout is configured"
    else
        sec_audit_report_fail 157 "sudo timestamp_timeout is not set within the required range"
    fi
    else
    sec_audit_report_pass 157 "sudo timestamp_timeout is configured"
    fi

    # RULE158
    if grep -Pi '^\h*auth\h+(?:required|requisite)\h+pam_wheel\.so\h+(?:[^#\n\r]+\h+)?((?!\2)(use_uid\b|group=\H+\b))\h+(?:[^#\n\r]+\h+)?((?!\1)(use_uid\b|group=\H+\b))(\h+.*)?$' /etc/pam.d/su 2>/dev/null; then
    GROUP=$(grep -Pi '^\h*auth\h+(?:required|requisite)\h+pam_wheel\.so\h+(?:[^#\n\r]+\h+)?((?!\2)(use_uid\b|group=\H+\b))\h+(?:[^#\n\r]+\h+)?((?!\1)(use_uid\b|group=\H+\b))(\h+.*)?$' /etc/pam.d/su 2>/dev/null | grep -oP 'group=\K\H+')
    if [ -n "$GROUP" ]; then
        if ! grep "^$GROUP:" /etc/group 2>/dev/null | grep -q ":$GROUP:x:"; then
            sec_audit_report_pass 158 "access to the su command is restricted"
        else
            sec_audit_report_fail 158 "su is not restricted to the wheel group in PAM configuration"
        fi
    else
        sec_audit_report_pass 158 "access to the su command is restricted"
    fi
    else
    sec_audit_report_fail 158 "su is not restricted to the wheel group in PAM configuration"
    fi

}

sec_audit_run_pam_auth() {
    # RULE159
    if sec_audit_pam_password_line_has_module pam_pwquality.so && sec_audit_pam_password_pwquality_before_unix_all_stacks; then
    sec_audit_report_pass 159 "pam_pwquality.so on password stack and ordered before pam_unix.so"
    elif sec_audit_pam_password_line_has_module pam_pwquality.so; then
    sec_audit_report_fail 159 "pam_pwquality.so present but not correctly ordered before pam_unix.so on password stack"
    else
    sec_audit_report_fail 159 "pam_pwquality module is not enabled on the password stack"
    fi

    # RULE160
    if grep -P '^\h*[^#].*pam_unix\.so\b' /etc/pam.d/common-auth /etc/pam.d/common-password /etc/pam.d/common-account 2>/dev/null | grep -q .; then
    sec_audit_report_pass 160 "pam_unix module is enabled"
    else
    sec_audit_report_fail 160 "pam_unix module is not found in common PAM files"
    fi

    # RULE161
    if grep -P '^\h*[^#].*pam_faillock\.so\b' /etc/pam.d/common-auth /etc/pam.d/common-account 2>/dev/null | grep -q .; then
    sec_audit_report_pass 161 "pam_faillock module is enabled"
    else
    sec_audit_report_fail 161 "pam_faillock module is not found in PAM common-auth or common-account"
    fi

    # RULE162
    if grep -P '^\h*[^#].*pam_pwquality\.so\b' /etc/pam.d/common-password 2>/dev/null | grep -q .; then
    sec_audit_report_pass 162 "pam_pwquality module is enabled"
    else
    sec_audit_report_fail 162 "pam_pwquality module is not found in PAM common-password"
    fi

    # RULE163
    if grep -P '^\h*[^#].*pam_pwhistory\.so\b' /etc/pam.d/common-password 2>/dev/null | grep -q .; then
    sec_audit_report_pass 163 "pam_pwhistory module is enabled"
    else
    sec_audit_report_fail 163 "pam_pwhistory module is not found in PAM common-password"
    fi

    # RULE164
    if grep -Psi '^\h*deny\h*=\h*[1-5]\b' /etc/security/faillock.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 164 "password failed attempts lockout is configured"
    else
    sec_audit_report_fail 164 "faillock deny threshold is not configured in /etc/security/faillock.conf"
    fi

    # RULE165
    if grep -Psi '^\h*unlock_time\h*=\h*(0|9[0-9][0-9]|[1-9][0-9]{3,})\b' /etc/security/faillock.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 165 "password unlock time is configured"
    else
    sec_audit_report_fail 165 "faillock unlock_time is not set within the required range"
    fi

    # RULE166
    if grep -Psi '^\h*even_deny_root\b' /etc/security/faillock.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 166 "password failed attempts lockout includes root account"
    else
    sec_audit_report_fail 166 "faillock even_deny_root is not set in /etc/security/faillock.conf"
    fi

    # RULE167
    if grep -Psi '^\h*difok\h*=\h*[2-9]\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 167 "password number of changed characters is configured"
    else
    sec_audit_report_fail 167 "pwquality difok (min changed chars) is not configured"
    fi

    # RULE168
    if grep -Psi '^\h*minlen\h*=\h*(1[4-9]|[2-9][0-9]|[1-9][0-9]{2,})\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 168 "password length is configured"
    else
    sec_audit_report_fail 168 "pwquality minlen is not set to at least 14"
    fi

    # RULE169
    if grep -Psi '^\h*maxrepeat\h*=\h*[1-3]\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 169 "password same consecutive characters is configured"
    else
    sec_audit_report_fail 169 "pwquality maxrepeat (max consecutive chars) is not configured"
    fi

    # RULE170
    if grep -Psi '^\h*maxsequence\h*=\h*[1-4]\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 170 "password maximum sequential characters is configured"
    else
    sec_audit_report_fail 170 "pwquality maxsequence is not configured"
    fi

    # RULE171
    if ! grep -Psi '^\h*dictcheck\h*=\h*0\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 171 "password dictionary check is enabled"
    else
    sec_audit_report_fail 171 "pwquality dictcheck is disabled (dictcheck=0 found)"
    fi

    # RULE172
    if grep -Psi '^\h*enforce_for_root\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 172 "password quality is enforced for the root user"
    else
    sec_audit_report_fail 172 "pwquality enforce_for_root is not set"
    fi

    # RULE173
    if grep -Psi '^\h*enforce_for_root\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 173 "password quality is enforced for the root user"
    else
    sec_audit_report_fail 173 "pwquality enforce_for_root is not set"
    fi

}

sec_audit_run_accounts() {
    # RULE174
    if grep -Psi '^\h*remember\h*=\h*(2[4-9]|[3-9][0-9]|[1-9][0-9]{2,})\b' /etc/security/pwhistory.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 174 "password history remember is configured"
    else
    sec_audit_report_fail 174 "pwhistory remember is not set to 24 or more in /etc/security/pwhistory.conf"
    fi

    # RULE175
    if grep -Psi '^\h*enforce_for_root\b' /etc/security/pwhistory.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 175 "password history is enforced for the root user"
    else
    sec_audit_report_fail 175 "pwhistory enforce_for_root is not set"
    fi

    # RULE176
    if grep -P '^\h*password\h+[^\n\r]+pam_pwhistory\.so\b' /etc/pam.d/common-password 2>/dev/null | grep -Pq 'use_authok\b'; then
    sec_audit_report_pass 176 "pam_pwhistory includes use_authok"
    else
    sec_audit_report_fail 176 "pam_pwhistory in common-password does not include use_authok"
    fi

    # RULE177
    if grep -P '^\h*[^#].*pam_unix\.so\b' /etc/pam.d/common-auth /etc/pam.d/common-password 2>/dev/null | grep -q 'nullok'; then
    sec_audit_report_fail 177 "pam_unix includes nullok (allows empty passwords)"
    else
    sec_audit_report_pass 177 "pam_unix does not include nullok"
    fi

    # RULE178
    if grep -P '^\h*password\h+[^\n\r]+pam_unix\.so\b' /etc/pam.d/common-password 2>/dev/null | grep -q 'remember='; then
    sec_audit_report_fail 178 "pam_unix includes remember= (use pam_pwhistory instead)"
    else
    sec_audit_report_pass 178 "pam_unix does not include remember"
    fi

    # RULE179
    if grep -P '^\h*password\h+([^\n\r]+)\h+pam_unix\.so\b' /etc/pam.d/common-password 2>/dev/null | grep -Piq '(sha512|yescrypt|blowfish|gost_yescrypt|scrypt|bcrypt)\b'; then
    sec_audit_report_pass 179 "pam_unix includes a strong password hashing algorithm"
    else
    sec_audit_report_fail 179 "pam_unix password line does not specify a strong hashing algorithm (sha512/yescrypt)"
    fi

    # RULE180
    if grep -P '^\h*password\h+[^\n\r]+pam_unix\.so\b' /etc/pam.d/common-password 2>/dev/null | grep -q 'use_authok\b'; then
    sec_audit_report_pass 180 "pam_unix includes use_authok"
    else
    sec_audit_report_fail 180 "pam_unix in common-password does not include use_authok"
    fi

    # RULE181
    if grep -Pqs '^\h*PASS_MAX_DAYS\h+(36[0-5]|3[0-5][0-9]|[1-2][0-9][0-9]|[1-9][0-9]|[1-9])\b' /etc/login.defs 2>/dev/null; then
    if ! awk -F: '($2~/^\$.+\$/) {if($5 > 365 || $5 < 1)print}' /etc/shadow 2>/dev/null | grep -q '.'; then
        sec_audit_report_pass 181 "password expiration is configured"
    else
        sec_audit_report_fail 181 "PASS_MAX_DAYS or per-user shadow MAX exceeds policy or is unset"
    fi
    else
    sec_audit_report_fail 181 "PASS_MAX_DAYS or per-user shadow MAX exceeds policy or is unset"
    fi

    # RULE182
    if grep -Pqs '^\h*PASS_WARN_AGE\h+([7-9]|[1-9][0-9]+)\b' /etc/login.defs 2>/dev/null; then
    if ! awk -F: '($2~/^\$.+\$/) {if($6 < 7)print}' /etc/shadow 2>/dev/null | grep -q '.'; then
        sec_audit_report_pass 182 "password expiration warning days is configured"
    else
        sec_audit_report_fail 182 "PASS_WARN_AGE is not set within policy in /etc/login.defs"
    fi
    else
    sec_audit_report_fail 182 "PASS_WARN_AGE is not set within policy in /etc/login.defs"
    fi

    # RULE183
    if grep -Pqs '^\h*ENCRYPT_METHOD\h+(SHA512|YESCRYPT)\b' /etc/login.defs 2>/dev/null; then
    sec_audit_report_pass 183 "strong password hashing algorithm is configured"
    else
    sec_audit_report_fail 183 "ENCRYPT_METHOD in /etc/login.defs does not use a strong hashing algorithm"
    fi

    # RULE184
    if useradd -D 2>/dev/null | grep INACTIVE | cut -d= -f2 | grep -qE '^([1-9]|[1-4][0-9]|45)$'; then
    if ! awk -F: '($2~/^\$.+\$/) {if($7 > 45 || $7 < 0)print}' /etc/shadow 2>/dev/null | grep -q '.'; then
        sec_audit_report_pass 184 "inactive password lock is configured"
    else
        sec_audit_report_fail 184 "useradd INACTIVE or inactive lock policy is not configured"
    fi
    else
    sec_audit_report_fail 184 "useradd INACTIVE or inactive lock policy is not configured"
    fi

    # RULE185
    FAIL185=0
    while IFS=: read -r user pass last_change rest; do
    if [ -n "$last_change" ] && [ "$last_change" -gt 0 ] 2>/dev/null; then
        current_date=$(date +%s)
        last_change_seconds=$((last_change * 86400))
        if [ "$last_change_seconds" -gt "$current_date" ]; then
            sec_audit_report_fail 185 "User $user has password change date in the future"
            FAIL185=1
        fi
    fi
    done < /etc/shadow 2>/dev/null
    if [ $FAIL185 -eq 0 ]; then
    sec_audit_report_pass 185 "All users last password change date is in the past"
    fi

    # RULE186
    if awk -F: '($3 == 0) { print $1 }' /etc/passwd 2>/dev/null | grep -qx "root"; then
    if [ $(awk -F: '($3 == 0) { print $1 }' /etc/passwd 2>/dev/null | wc -l) -eq 1 ]; then
        sec_audit_report_pass 186 "root is the only UID 0 account"
    else
        sec_audit_report_fail 186 "Multiple accounts with UID 0 exist in /etc/passwd"
    fi
    else
    sec_audit_report_fail 186 "Multiple accounts with UID 0 exist in /etc/passwd"
    fi

    # RULE187
    if awk -F: '($1 !~ /^(sync|shutdown|halt|operator)/ && $4=="0") {print $1":"$4}' /etc/passwd 2>/dev/null | grep -q "root:0"; then
    if [ $(awk -F: '($1 !~ /^(sync|shutdown|halt|operator)/ && $4=="0") {print}' /etc/passwd 2>/dev/null | wc -l) -eq 1 ]; then
        sec_audit_report_pass 187 "root is the only GID 0 account"
    else
        sec_audit_report_fail 187 "Multiple users use GID 0 outside policy"
    fi
    else
    sec_audit_report_fail 187 "Multiple users use GID 0 outside policy"
    fi

    # RULE188
    if awk -F: '$3=="0"{print $1":"$3}' /etc/group 2>/dev/null | grep -q "root:0"; then
    if [ $(awk -F: '$3=="0"{print}' /etc/group 2>/dev/null | wc -l) -eq 1 ]; then
        sec_audit_report_pass 188 "group root is the only GID 0 group"
    else
        sec_audit_report_fail 188 "Multiple groups share GID 0"
    fi
    else
    sec_audit_report_fail 188 "Multiple groups share GID 0"
    fi

    # RULE189
    FAIL189=0
    ROOT_PATH=$(sudo -i echo "\$PATH" 2>/dev/null || echo "$PATH")
    if echo "$ROOT_PATH" | grep -q "::"; then
    sec_audit_report_fail 189 "Root PATH contains empty directory (::)"
    FAIL189=1
    fi
    if echo "$ROOT_PATH" | grep -q "\.:"; then
    sec_audit_report_fail 189 "Root PATH contains current directory (.)"
    FAIL189=1
    fi
    if [ $FAIL189 -eq 0 ]; then
    sec_audit_report_pass 189 "Root path integrity is maintained"
    fi

    # RULE190
    if ! grep -Psi '^\h*umask\h+((\d{1,2}(\d[^7]|[^2-7]\d)\b)|(u=[rwx]{1,3},)?(((g=[rx]?[rx]?w[rx]?[rx]?\b)(,o=[rwx]{1,3})?)|((g=[wrx]{1,3},)?o=[wrx]{1,3}\b)))' /root/.bash_profile /root/.bashrc 2>/dev/null; then
    sec_audit_report_pass 190 "root user umask is configured"
    else
    sec_audit_report_fail 190 "root umask is not 027 (or stricter) in profile scripts"
    fi

    # RULE191
    VALID_SHELLS=$(awk -F\/ '$NF != "nologin" && $NF != "false" {print}' /etc/shells 2>/dev/null | sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' -)
    UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs 2>/dev/null)
    if awk -v pat="^($VALID_SHELLS)$" -v uidmin="$UID_MIN" -F: '($1!~/^(root|halt|sync|shutdown|nfsnobody)$/ && ($3<uidmin || $3==65534) && $NF ~ pat) {print}' /etc/passwd 2>/dev/null | grep -q '.'; then
    sec_audit_report_fail 191 "System accounts still have an interactive login shell"
    else
    sec_audit_report_pass 191 "system accounts do not have a valid login shell"
    fi

    # RULE192
    VALID_SHELLS=$(awk -F\/ '$NF != "nologin" && $NF != "false" {print}' /etc/shells 2>/dev/null | sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' -)
    FAIL192=0
    while IFS= read -r l_user; do
    if passwd -S "$l_user" 2>/dev/null | awk '$2 !~ /^L/ {print "found"}' | grep -q "found"; then
        sec_audit_report_fail 192 "Accounts without a valid shell are not locked in /etc/shadow"
        FAIL192=1
        break
    fi
    done <<< "$(awk -v pat="^($VALID_SHELLS)$" -F: '($1 != "root" && $NF !~ pat) {print $1}' /etc/passwd 2>/dev/null)"
    if [ $FAIL192 -eq 0 ]; then
    sec_audit_report_pass 192 "accounts without a valid login shell are locked"
    fi

    # RULE193
    if grep -Ps '^\h*([^#\n\r]+)?\/nologin\b' /etc/shells 2>/dev/null; then
    sec_audit_report_fail 193 "nologin appears in /etc/shells"
    else
    sec_audit_report_pass 193 "nologin is not listed in /etc/shells"
    fi

    # RULE194
    if grep -Pqs '^([^#\n\r]+)?\bTMOUT=(9[0-9]{1,2}|[1-9][0-9]|[1-9])\b' /etc/*bashrc /etc/profile /etc/profile.d/*.sh 2>/dev/null; then
    sec_audit_report_pass 194 "default user shell timeout is configured"
    else
    sec_audit_report_fail 194 "TMOUT is not set for interactive shells in /etc/profile or profile.d"
    fi

    # RULE195
    if grep -Pqs '^\h*umask\h+0?(?:[0-7][2-7]7)\b' /etc/login.defs 2>/dev/null; then
    if grep -Pqs '^\h*umask\h+0?027\b' /etc/profile.d/*.sh 2>/dev/null; then
        sec_audit_report_pass 195 "default user umask is configured"
    else
        sec_audit_report_fail 195 "Default user umask 027 is not set in /etc/profile or profile.d"
    fi
    else
    sec_audit_report_fail 195 "Default user umask 027 is not set in /etc/profile or profile.d"
    fi

}

sec_audit_run_logging() {
    # RULE196
    if systemctl is-active systemd-journald.service 2>/dev/null | grep -q '^active'; then
    sec_audit_report_pass 196 "journald service is active"
    else
    sec_audit_report_fail 196 "systemd-journald service is not active"
    fi

    # RULE197
    if systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -Pqs '^\h*ForwardToSyslog\h*=\h*no\b'; then
    sec_audit_report_pass 197 "journald ForwardToSyslog is disabled"
    else
    sec_audit_report_fail 197 "journald ForwardToSyslog is not set to no"
    fi

    # RULE198
    if systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -Psi '^\h*Storage\h*=\h*(persistent|auto)\b'; then
    sec_audit_report_pass 198 "journald Storage is configured"
    else
    sec_audit_report_fail 198 "journald Storage is not set to persistent or auto"
    fi

    # RULE199
    if systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -Psi '^\h*Compress\h*=\h*yes\b'; then
    sec_audit_report_pass 199 "journald Compress is configured"
    else
    sec_audit_report_fail 199 "journald Compress is not set to yes"
    fi

    # RULE200
    if sec_audit_pkg_is_installed systemd-journal-remote; then
    sec_audit_report_pass 200 "systemd-journal-remote is installed"
    else
    sec_audit_report_fail 200 "systemd-journal-remote package is not installed"
    fi

    # RULE201
    if systemctl is-enabled systemd-journal-upload.service 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active systemd-journal-upload.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_pass 201 "systemd-journal-upload is enabled and active"
    else
        sec_audit_report_fail 201 "systemd-journal-upload is enabled but not active"
    fi
    else
    sec_audit_report_fail 201 "systemd-journal-upload is not enabled"
    fi

    # RULE202
    if systemctl is-active systemd-journal-remote.service 2>/dev/null | grep -q '^active'; then
    sec_audit_report_fail 202 "systemd-journal-remote service is active (should not be in use as log receiver)"
    elif systemctl is-enabled systemd-journal-remote.socket 2>/dev/null | grep -qv 'disabled'; then
    sec_audit_report_fail 202 "systemd-journal-remote.socket is enabled (should be disabled)"
    else
    sec_audit_report_pass 202 "systemd-journal-remote service is not in use"
    fi

    # RULE203
    if sec_audit_pkg_is_installed rsyslog; then
    sec_audit_report_pass 203 "rsyslog is installed"
    else
    sec_audit_report_fail 203 "rsyslog package is not installed"
    fi

    # RULE204
    if systemctl is-enabled rsyslog.service 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active rsyslog.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_pass 204 "rsyslog service is enabled and active"
    else
        sec_audit_report_fail 204 "rsyslog service is enabled but not active"
    fi
    else
    sec_audit_report_fail 204 "rsyslog service is not enabled"
    fi

    # RULE205
    if systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -Pqs '^\h*ForwardToSyslog\h*=\h*yes\b'; then
    sec_audit_report_pass 205 "journald is configured to send logs to rsyslog"
    else
    sec_audit_report_fail 205 "journald ForwardToSyslog=yes is not set"
    fi

    # RULE206
    if grep -Pqs '^\h*\$FileCreateMode\h+0[0-6][04][04]\b' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null; then
    sec_audit_report_pass 206 "rsyslog log file creation mode is configured"
    else
    sec_audit_report_fail 206 "rsyslog \$FileCreateMode is not configured"
    fi

    # RULE207
    if grep -Ps '^\h*(module|input)\h*\(load="imtcp"' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -q .; then
    sec_audit_report_fail 207 "rsyslog is configured to receive logs from remote client (imtcp module loaded)"
    elif grep -Ps '^\h*\$ModLoad\h+imtcp\b' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -q .; then
    sec_audit_report_fail 207 "rsyslog is configured to receive logs from remote client (imtcp loaded)"
    else
    sec_audit_report_pass 207 "rsyslog is not configured to receive logs from a remote client"
    fi

    # RULE208
    if sec_audit_pkg_is_installed rsyslog-gnutls; then
    sec_audit_report_pass 208 "rsyslog-gnutls is installed"
    else
    sec_audit_report_fail 208 "rsyslog-gnutls package is not installed"
    fi

    # RULE209
    if grep -Psi '^\h*\$DefaultNetstreamDriverCaFile\b' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 209 "rsyslog forwarding uses gTLS"
    else
    sec_audit_report_fail 209 "rsyslog gTLS forwarding is not configured (\$DefaultNetstreamDriverCaFile missing)"
    fi

    # RULE210
    LOGFILE_FAIL=0
    while IFS= read -r f; do
    perm=$(stat -Lc '%a' "$f" 2>/dev/null)
    if echo "$perm" | grep -qE '^[0-7][0-7][1-7]$'; then
        LOGFILE_FAIL=1; break
    fi
    done < <(find /var/log -type f 2>/dev/null)
    if [ $LOGFILE_FAIL -eq 0 ]; then
    sec_audit_report_pass 210 "access to all logfiles has been configured"
    else
    sec_audit_report_fail 210 "one or more logfiles in /var/log have world-readable or group-write permissions"
    fi

}

sec_audit_run_auditd() {
    # RULE211
    if systemctl is-enabled systemd-journald.service 2>/dev/null | grep -q 'static'; then
    if systemctl is-active systemd-journald.service 2>/dev/null | grep -q 'active'; then
        sec_audit_report_pass 211 "journald service is active"
    else
        sec_audit_report_fail 211 "systemd-journald is not active or not in expected state"
    fi
    else
    sec_audit_report_fail 211 "systemd-journald is not active or not in expected state"
    fi

    # RULE212
    if [ -d /var/log/journal ]; then
    DIR_PERM=$(stat -c '%a' /var/log/journal 2>/dev/null)
    if [ "$DIR_PERM" = "755" ] || [ "$DIR_PERM" = "750" ]; then
        sec_audit_report_pass 212 "journald log file access is configured (directory mode: $DIR_PERM)"
    else
        sec_audit_report_fail 212 "journald log directory has insecure permissions: $DIR_PERM"
    fi
    else
    sec_audit_report_pass 212 "journald log file access is configured (directory not found)"
    fi

    # RULE213
    if grep -q "^SystemMaxUse\|^SystemMaxFileSize\|^MaxFileSec" /etc/systemd/journald.conf 2>/dev/null; then
    sec_audit_report_pass 213 "journald log file rotation is configured"
    else
    sec_audit_report_fail 213 "journald log file rotation not explicitly configured"
    fi

    # RULE214
    if systemctl is-active --quiet rsyslog 2>/dev/null; then
    if systemctl is-active --quiet systemd-journald 2>/dev/null; then
        sec_audit_report_fail 214 "more than one logging system is in use (both rsyslog and journald are active)"
    else
        sec_audit_report_pass 214 "only one logging system is in use (rsyslog)"
    fi
    elif systemctl is-active --quiet systemd-journald 2>/dev/null; then
    sec_audit_report_pass 214 "only one logging system is in use (journald)"
    else
    sec_audit_report_fail 214 "no logging system is active (neither rsyslog nor journald)"
    fi

    # RULE215
    if grep -Ps '^\h*max_log_file\h*=\h*[1-9][0-9]*\b' /etc/audit/auditd.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 215 "audit log storage size is configured"
    else
    sec_audit_report_fail 215 "auditd max_log_file is not configured in /etc/audit/auditd.conf"
    fi

    # RULE216
    if systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -E '^ForwardToSyslog=no' | head -1 | grep -q "ForwardToSyslog=no"; then
    sec_audit_report_pass 216 "journald ForwardToSyslog is disabled"
    elif systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -E '^ForwardToSyslog=yes' | head -1 | grep -q "ForwardToSyslog=yes"; then
    sec_audit_report_fail 216 "journald ForwardToSyslog is disabled (should be no)"
    else
    sec_audit_report_pass 216 "journald ForwardToSyslog is disabled (default)"
    fi

    # RULE217
    if systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -E '^Compress=yes' | head -1 | grep -q "Compress=yes"; then
    sec_audit_report_pass 217 "journald Compress is configured"
    else
    sec_audit_report_pass 217 "journald Compress is configured (default)"
    fi

    # RULE218
    if systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -E '^Storage=persistent' | head -1 | grep -q "Storage=persistent"; then
    sec_audit_report_pass 218 "journald Storage is configured"
    else
    sec_audit_report_fail 218 "journald Storage=persistent (or required value) is not set in merged config"
    fi

    # RULE219
    if sec_audit_pkg_is_installed rsyslog; then
    sec_audit_report_pass 219 "rsyslog is installed"
    else
    sec_audit_report_fail 219 "rsyslog package is not installed"
    fi

    # RULE220
    if systemctl is-enabled rsyslog 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active rsyslog.service 2>/dev/null | grep -q 'active'; then
        sec_audit_report_pass 220 "rsyslog service is enabled and active"
    else
        sec_audit_report_fail 220 "rsyslog is not enabled or not active"
    fi
    else
    sec_audit_report_fail 220 "rsyslog is not enabled or not active"
    fi

    # RULE221
    if systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -E '^ForwardToSyslog=yes' | head -1 | grep -q "ForwardToSyslog=yes"; then
    sec_audit_report_pass 221 "journald is configured to send logs to rsyslog"
    else
    sec_audit_report_fail 221 "journald ForwardToSyslog or forwarding to rsyslog is not configured"
    fi

    # RULE222
    if grep -Pqs '^\h*\$FileCreateMode\h+0[0,2,4,6][0,2,4]0\b' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null; then
    sec_audit_report_pass 222 "rsyslog log file creation mode is configured"
    else
    sec_audit_report_fail 222 "rsyslog $FileCreateMode (or equivalent) does not meet policy"
    fi

    # RULE223
    if command -v rsyslogd &>/dev/null; then
    if [ -f /etc/rsyslog.conf ] && grep -v "^#" /etc/rsyslog.conf 2>/dev/null | grep -q "^\*\.\*\|^auth\|^mail\|^cron"; then
        sec_audit_report_pass 223 "rsyslog logging is configured"
    else
        sec_audit_report_fail 223 "rsyslog logging is not properly configured"
    fi
    else
    sec_audit_report_pass 223 "rsyslog is not installed"
    fi

    # RULE224
    if auditctl -l 2>/dev/null | grep -q '/etc/issue' || grep -r '/etc/issue' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q '\-w'; then
    sec_audit_report_pass 224 "events that modify /etc/issue and /etc/issue.net are collected"
    else
    sec_audit_report_fail 224 "auditd watch rules for /etc/issue and /etc/issue.net are not configured"
    fi

    # RULE225
    if auditctl -l 2>/dev/null | grep -q '/etc/hosts' || grep -r '/etc/hosts' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q '\-w'; then
    sec_audit_report_pass 225 "events that modify /etc/hosts and /etc/hostname are collected"
    else
    sec_audit_report_fail 225 "auditd watch rules for /etc/hosts are not configured"
    fi

    # RULE226
    if command -v logrotate &>/dev/null; then
    if [ -f /etc/logrotate.conf ] && grep -q "^rotate\|^daily\|^weekly\|^monthly" /etc/logrotate.conf 2>/dev/null; then
        sec_audit_report_pass 226 "rsyslog logrotate is configured"
    else
        sec_audit_report_fail 226 "rsyslog logrotate is not properly configured"
    fi
    else
    sec_audit_report_fail 226 "logrotate is not installed"
    fi

    # RULE227
    if auditctl -l 2>/dev/null | grep -q '/etc/NetworkManager' || grep -r '/etc/NetworkManager' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q '\-w'; then
    sec_audit_report_pass 227 "events that modify /etc/NetworkManager directory are collected"
    else
    sec_audit_report_fail 227 "auditd watch rules for /etc/NetworkManager are not configured"
    fi

    # RULE228
    PRIV_CMD_FAIL=0
    for cmd in $(find /usr/bin /usr/sbin /bin /sbin -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null); do
    if ! auditctl -l 2>/dev/null | grep -q "$cmd" && ! grep -r "$cmd" /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q '\-a'; then
        PRIV_CMD_FAIL=1; break
    fi
    done
    if [ $PRIV_CMD_FAIL -eq 0 ]; then
    sec_audit_report_pass 228 "use of privileged commands are collected"
    else
    sec_audit_report_fail 228 "not all setuid/setgid commands are monitored by auditd"
    fi

    # RULE229
    if auditctl -l 2>/dev/null | grep -qP '\-EACCES|\-EPERM' || grep -r '\-EACCES\|\-EPERM\|EACCES\|EPERM' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q '\-a'; then
    sec_audit_report_pass 229 "unsuccessful file access attempts are collected"
    else
    sec_audit_report_fail 229 "auditd rules for EACCES/EPERM are not configured"
    fi

    # RULE230
    if auditctl -l 2>/dev/null | grep -q '/etc/group' || grep -r '/etc/group' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q '\-w'; then
    sec_audit_report_pass 230 "events that modify /etc/group information are collected"
    else
    sec_audit_report_fail 230 "auditd watch rules for /etc/group are not configured"
    fi

    # RULE231
    if auditctl -l 2>/dev/null | grep -q '/etc/passwd' || grep -r '/etc/passwd' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q '\-w'; then
    sec_audit_report_pass 231 "events that modify /etc/passwd information are collected"
    else
    sec_audit_report_fail 231 "auditd watch rules for /etc/passwd are not configured"
    fi

    # RULE232
    if auditctl -l 2>/dev/null | grep -q '/etc/shadow' || grep -r '/etc/shadow' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q '\-w'; then
    sec_audit_report_pass 232 "events that modify /etc/shadow and /etc/gshadow are collected"
    else
    sec_audit_report_fail 232 "auditd watch rules for /etc/shadow and /etc/gshadow are not configured"
    fi

    # RULE233
    if auditctl -l 2>/dev/null | grep -q '/etc/security/opasswd' || grep -r 'opasswd' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q '\-w'; then
    sec_audit_report_pass 233 "events that modify /etc/security/opasswd are collected"
    else
    sec_audit_report_fail 233 "auditd watch rules for /etc/security/opasswd are not configured"
    fi

    # RULE234
    if auditctl -l 2>/dev/null | grep -q '/etc/nsswitch.conf' || grep -r 'nsswitch' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q '\-w'; then
    sec_audit_report_pass 234 "events that modify /etc/nsswitch.conf are collected"
    else
    sec_audit_report_fail 234 "auditd watch rules for /etc/nsswitch.conf are not configured"
    fi

    # RULE235
    if auditctl -l 2>/dev/null | grep -q '/etc/pam' || grep -r '/etc/pam' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q '\-w'; then
    sec_audit_report_pass 235 "events that modify /etc/pam.conf and /etc/pam.d/ are collected"
    else
    sec_audit_report_fail 235 "auditd watch rules for /etc/pam files are not configured"
    fi

    # RULE236
    if auditctl -l 2>/dev/null | grep -Pq 'chmod|fchmodat' || grep -r 'chmod' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -qP '\-a.*always\b|\-a.*exit\b'; then
    sec_audit_report_pass 236 "DAC permission modification events (chmod) are collected"
    else
    sec_audit_report_fail 236 "auditd rules for chmod/fchmodat events are not configured"
    fi

    # RULE237
    if auditctl -l 2>/dev/null | grep -Pq 'chown|fchownat' || grep -r 'chown' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -qP '\-a.*always\b|\-a.*exit\b'; then
    sec_audit_report_pass 237 "DAC permission modification events (chown) are collected"
    else
    sec_audit_report_fail 237 "auditd rules for chown/fchownat events are not configured"
    fi

    # RULE238
    if auditctl -l 2>/dev/null | grep -Pq 'setxattr|removexattr' || grep -r 'setxattr\|removexattr' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -qP '\-a.*always\b|\-a.*exit\b'; then
    sec_audit_report_pass 238 "DAC permission modification events (xattr) are collected"
    else
    sec_audit_report_fail 238 "auditd rules for setxattr/removexattr events are not configured"
    fi

    # RULE239
    if auditctl -l 2>/dev/null | grep -q 'mount' || grep -r 'mount' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -qP '\-a.*always\b|\-a.*exit\b'; then
    sec_audit_report_pass 239 "successful file system mounts are collected"
    else
    sec_audit_report_fail 239 "auditd rules for mount events are not configured"
    fi

    # RULE240
    if auditctl -l 2>/dev/null | grep -q 'session\|logins' || grep -r 'session\|logins' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q '\-w'; then
    sec_audit_report_pass 240 "session initiation information is collected"
    else
    sec_audit_report_fail 240 "auditd rules for session initiation are not configured"
    fi

    # RULE241
    if auditctl -l 2>/dev/null | grep -q '/var/log/faillog\|/var/log/lastlog\|/var/log/tallylog' || grep -r 'faillog\|lastlog\|tallylog' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q '\-w'; then
    sec_audit_report_pass 241 "login and logout events are collected"
    else
    sec_audit_report_fail 241 "auditd watch rules for login/logout files are not configured"
    fi

    # RULE242
    if auditctl -l 2>/dev/null | grep -q 'delete\|unlink' || grep -r 'delete\|unlink' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -qP '\-a.*always\b|\-a.*exit\b'; then
    sec_audit_report_pass 242 "unlink file deletion events are collected"
    else
    sec_audit_report_fail 242 "auditd rules for unlink/delete events are not configured"
    fi

    # RULE243
    if auditctl -l 2>/dev/null | grep -q 'rename' || grep -r 'rename' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -qP '\-a.*always\b|\-a.*exit\b'; then
    sec_audit_report_pass 243 "rename file deletion events are collected"
    else
    sec_audit_report_fail 243 "auditd rules for rename events are not configured"
    fi

    # RULE244
    if auditctl -l 2>/dev/null | grep -q 'MAC-policy\|apparmor' || grep -r 'MAC-policy\|apparmor' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q '\-w'; then
    sec_audit_report_pass 244 "events that modify Mandatory Access Controls are collected"
    else
    sec_audit_report_fail 244 "auditd watch rules for MAC (AppArmor) modifications are not configured"
    fi

    # RULE245
    if auditctl -l 2>/dev/null | grep -q 'chcon' || grep -r 'chcon' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -qP '\-a.*always\b|\-a.*exit\b'; then
    sec_audit_report_pass 245 "chcon command use is collected"
    else
    CHCON_PATH=$(command -v chcon 2>/dev/null)
    if [ -z "$CHCON_PATH" ]; then
        sec_audit_report_pass 245 "chcon is not installed (not applicable)"
    else
        sec_audit_report_fail 245 "auditd rules for chcon command are not configured"
    fi
    fi

    # RULE246
    if auditctl -l 2>/dev/null | grep -q 'setfacl\|perm_mod' || grep -r 'setfacl' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -qP '\-a.*always\b|\-a.*exit\b'; then
    sec_audit_report_pass 246 "setfacl command use is collected"
    else
    sec_audit_report_fail 246 "auditd rules for setfacl are not configured"
    fi

    # RULE247
    if auditctl -l 2>/dev/null | grep -q 'chacl' || grep -r 'chacl' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -qP '\-a.*always\b|\-a.*exit\b'; then
    sec_audit_report_pass 247 "chacl command use is collected"
    else
    CHACL_PATH=$(command -v chacl 2>/dev/null)
    if [ -z "$CHACL_PATH" ]; then
        sec_audit_report_pass 247 "chacl is not installed (not applicable)"
    else
        sec_audit_report_fail 247 "auditd rules for chacl are not configured"
    fi
    fi

    # RULE248
    if auditctl -l 2>/dev/null | grep -q 'usermod' || grep -r 'usermod' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -qP '\-a.*always\b|\-a.*exit\b'; then
    sec_audit_report_pass 248 "usermod command use is collected"
    else
    sec_audit_report_fail 248 "auditd rules for usermod are not configured"
    fi

    # RULE249
    if auditctl -l 2>/dev/null | grep -q 'modules\|insmod\|rmmod\|modprobe' || grep -r 'modules\|insmod\|rmmod\|modprobe' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -q '\-a\|\-w'; then
    sec_audit_report_pass 249 "kernel module loading/unloading is collected"
    else
    sec_audit_report_fail 249 "auditd rules for kernel module operations are not configured"
    fi

    # RULE250
    if auditctl -l 2>/dev/null | grep -Pq 'init_module|finit_module' || grep -r 'init_module\|finit_module' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -qP '\-a.*always\b|\-a.*exit\b'; then
    sec_audit_report_pass 250 "kernel init_module and finit_module are collected"
    else
    sec_audit_report_fail 250 "auditd rules for init_module/finit_module syscalls are not configured"
    fi

    # RULE251
    if auditctl -l 2>/dev/null | grep -Pq 'delete_module' || grep -r 'delete_module' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null | grep -qP '\-a.*always\b|\-a.*exit\b'; then
    sec_audit_report_pass 251 "kernel delete_module is collected"
    else
    sec_audit_report_fail 251 "auditd rules for delete_module syscall are not configured"
    fi

    # RULE252
    if grep -Psi '^\h*-i\b' /etc/audit/rules.d/*.rules /etc/audit/audit.rules 2>/dev/null | grep -q .; then
    sec_audit_report_pass 252 "the audit configuration is loaded regardless of errors (-i flag)"
    else
    sec_audit_report_fail 252 "auditd -i (ignore-errors) flag is not set in audit rules"
    fi

    # RULE253
    if sec_audit_audit_rule_loaded_and_on_disk -- '-e 2'; then
    sec_audit_report_pass 253 "the audit configuration is immutable (-e 2 loaded and on disk)"
    elif sec_audit_audit_rules_files_grep -q -- '-e 2'; then
    sec_audit_report_fail 253 "Immutable rule (-e 2) is on disk but not loaded (auditctl -l)"
    elif sec_audit_auditctl_rules_grep -q -- '-e 2'; then
    sec_audit_report_fail 253 "Immutable rule (-e 2) is loaded but missing from on-disk audit rules"
    else
    sec_audit_report_fail 253 "Immutable rule (-e 2) is missing from loaded and on-disk audit rules"
    fi

    # RULE254
    FAIL254=0
    for logfile in /var/log/messages /var/log/secure /var/log/maillog /var/log/cron /var/log/boot.log; do
    if [ -f "$logfile" ]; then
        PERM=$(stat -c '%a' "$logfile" 2>/dev/null)
        OWNER=$(stat -c '%U' "$logfile" 2>/dev/null)
        if [ "$PERM" -gt 640 ] 2>/dev/null || [ "$OWNER" != "root" ]; then
            sec_audit_report_fail 254 "$logfile has insecure permissions ($PERM) or owner ($OWNER)"
            FAIL254=1
        fi
    fi
    done
    [ $FAIL254 -eq 0 ] && sec_audit_report_pass 254 "Access to all logfiles has been configured"

    # RULE255
    AUDIT_LOG=$(grep -Ps '^\h*log_file\h*=' /etc/audit/auditd.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
    AUDIT_LOG="${AUDIT_LOG:-/var/log/audit/audit.log}"
    AUDIT_DIR=$(dirname "$AUDIT_LOG")
    if find "$AUDIT_DIR" -maxdepth 1 -type f \( ! -user root \) 2>/dev/null | grep -q .; then
    sec_audit_report_fail 255 "audit log files are not owned by root"
    else
    sec_audit_report_pass 255 "audit log files owner is configured"
    fi

    # RULE256
    if find "$AUDIT_DIR" -maxdepth 1 -type f \( ! -group adm ! -group root \) 2>/dev/null | grep -q .; then
    sec_audit_report_fail 256 "audit log files are not group owned by root or adm"
    else
    sec_audit_report_pass 256 "audit log files group owner is configured"
    fi

    # RULE257
    DIR_PERM=$(stat -Lc '%a' "$AUDIT_DIR" 2>/dev/null)
    if echo "$DIR_PERM" | grep -qE '^7[0-5][05]$|^750$|^700$'; then
    sec_audit_report_pass 257 "audit log file directory mode is configured ($DIR_PERM)"
    else
    sec_audit_report_fail 257 "audit log directory $AUDIT_DIR has insecure permissions: $DIR_PERM"
    fi

    # RULE258
    if find /etc/audit/ -maxdepth 2 -type f \( -name "*.conf" -o -name "*.rules" \) 2>/dev/null | while read f; do
    perm=$(stat -Lc '%a' "$f" 2>/dev/null)
    echo "$perm" | grep -qE '^[0-6][04][04]$' || echo FAIL
    done | grep -q FAIL; then
    sec_audit_report_fail 258 "audit configuration files have overly permissive mode"
    else
    sec_audit_report_pass 258 "audit configuration files mode is configured"
    fi

    # RULE259
    if find /etc/audit/ -maxdepth 2 -type f \( ! -user root \) 2>/dev/null | grep -q .; then
    sec_audit_report_fail 259 "audit configuration files are not owned by root"
    else
    sec_audit_report_pass 259 "audit configuration files owner is configured"
    fi

    # RULE260
    if find /etc/audit/ -maxdepth 2 -type f \( ! -group root \) 2>/dev/null | grep -q .; then
    sec_audit_report_fail 260 "audit configuration files are not group owned by root"
    else
    sec_audit_report_pass 260 "audit configuration files group owner is configured"
    fi

    # RULE261
    AUDIT_TOOLS="/sbin/auditctl /sbin/auditd /sbin/ausearch /sbin/aureport /sbin/autrace /sbin/augenrules"
    FAIL261=0
    for t in $AUDIT_TOOLS; do
    [ -f "$t" ] || continue
    perm=$(stat -Lc '%a' "$t" 2>/dev/null)
    if ! echo "$perm" | grep -qE '^[0-7][05][05]$'; then FAIL261=1; break; fi
    done
    if [ $FAIL261 -eq 0 ]; then
    sec_audit_report_pass 261 "audit tools mode is configured"
    else
    sec_audit_report_fail 261 "one or more audit tools have overly permissive mode"
    fi

    # RULE262
    FAIL262=0
    for t in $AUDIT_TOOLS; do
    [ -f "$t" ] || continue
    owner=$(stat -Lc '%U' "$t" 2>/dev/null)
    if [ "$owner" != "root" ]; then FAIL262=1; break; fi
    done
    if [ $FAIL262 -eq 0 ]; then
    sec_audit_report_pass 262 "audit tools owner is configured"
    else
    sec_audit_report_fail 262 "one or more audit tools are not owned by root"
    fi

    # RULE263
    FAIL263=0
    for t in $AUDIT_TOOLS; do
    [ -f "$t" ] || continue
    grp=$(stat -Lc '%G' "$t" 2>/dev/null)
    if [ "$grp" != "root" ]; then FAIL263=1; break; fi
    done
    if [ $FAIL263 -eq 0 ]; then
    sec_audit_report_pass 263 "audit tools group owner is configured"
    else
    sec_audit_report_fail 263 "one or more audit tools are not group owned by root"
    fi

}

sec_audit_run_aide() {
    # RULE264
    if sec_audit_pkg_is_installed aide || sec_audit_pkg_is_installed aide-common || command -v aide &>/dev/null; then
    sec_audit_report_pass 264 "AIDE is installed"
    else
    sec_audit_report_fail 264 "AIDE package is not installed"
    fi

    # RULE265
    if crontab -l 2>/dev/null | grep -qi 'aide\|--check'; then
    sec_audit_report_pass 265 "filesystem integrity check (AIDE) is regularly scheduled"
    elif grep -r 'aide\|--check' /etc/cron* /etc/anacrontab 2>/dev/null | grep -qi 'aide'; then
    sec_audit_report_pass 265 "filesystem integrity check (AIDE) is regularly scheduled"
    elif systemctl is-enabled aidecheck.timer 2>/dev/null | grep -q 'enabled'; then
    sec_audit_report_pass 265 "filesystem integrity check (AIDE) is regularly scheduled via systemd timer"
    else
    sec_audit_report_fail 265 "AIDE filesystem integrity check is not scheduled in cron or systemd"
    fi

}

sec_audit_run_identity_files() {
    # RULE266
    if stat -Lc '%a' /etc/passwd 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' /etc/passwd 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 266 "access to /etc/passwd is configured"
    else
        sec_audit_report_fail 266 "File /etc/passwd permissions or ownership not correct"
    fi
    else
    sec_audit_report_fail 266 "File /etc/passwd permissions or ownership not correct"
    fi

    # RULE267
    if [ -e /etc/passwd- ]; then
    if stat -Lc '%a' /etc/passwd- 2>/dev/null | grep -qE '^[0-6]44$'; then
        if stat -Lc '%U:%G' /etc/passwd- 2>/dev/null | grep -q '^root:root$'; then
            sec_audit_report_pass 267 "access to /etc/passwd- is configured"
        else
            sec_audit_report_fail 267 "File /etc/passwd- permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 267 "File /etc/passwd- permissions or ownership not correct"
    fi
    else
    sec_audit_report_pass 267 "/etc/passwd- is absent (optional file; permission check skipped)"
    fi

    # RULE268
    if stat -Lc '%a' /etc/group 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' /etc/group 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 268 "access to /etc/group is configured"
    else
        sec_audit_report_fail 268 "File /etc/group permissions or ownership not correct"
    fi
    else
    sec_audit_report_fail 268 "File /etc/group permissions or ownership not correct"
    fi

    # RULE269
    if [ -e /etc/group- ]; then
    if stat -Lc '%a' /etc/group- 2>/dev/null | grep -qE '^[0-6]44$'; then
        if stat -Lc '%U:%G' /etc/group- 2>/dev/null | grep -q '^root:root$'; then
            sec_audit_report_pass 269 "access to /etc/group- is configured"
        else
            sec_audit_report_fail 269 "File /etc/group- permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 269 "File /etc/group- permissions or ownership not correct"
    fi
    else
    sec_audit_report_pass 269 "/etc/group- is absent (optional file; permission check skipped)"
    fi

    # RULE270
    if stat -Lc '%a' /etc/shadow 2>/dev/null | grep -qE '^[0-6]40$'; then
    if stat -Lc '%U' /etc/shadow 2>/dev/null | grep -q 'root'; then
        if stat -Lc '%G' /etc/shadow 2>/dev/null | grep -qE 'root|shadow'; then
            sec_audit_report_pass 270 "access to /etc/shadow is configured"
        else
            sec_audit_report_fail 270 "File /etc/shadow permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 270 "File /etc/shadow permissions or ownership not correct"
    fi
    else
    sec_audit_report_fail 270 "File /etc/shadow permissions or ownership not correct"
    fi

    # RULE271
    if [ -e /etc/shadow- ]; then
    if stat -Lc '%a' /etc/shadow- 2>/dev/null | grep -qE '^[0-6]40$'; then
        if stat -Lc '%U' /etc/shadow- 2>/dev/null | grep -q 'root'; then
            if stat -Lc '%G' /etc/shadow- 2>/dev/null | grep -qE 'root|shadow'; then
                sec_audit_report_pass 271 "access to /etc/shadow- is configured"
            else
                sec_audit_report_fail 271 "File /etc/shadow- permissions or ownership not correct"
            fi
        else
            sec_audit_report_fail 271 "File /etc/shadow- permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 271 "File /etc/shadow- permissions or ownership not correct"
    fi
    else
    sec_audit_report_pass 271 "/etc/shadow- is absent (optional file; permission check skipped)"
    fi

    # RULE272
    if [ -e /etc/gshadow ]; then
    if stat -Lc '%a' /etc/gshadow 2>/dev/null | grep -qE '^[0-6]40$'; then
        if stat -Lc '%U' /etc/gshadow 2>/dev/null | grep -q 'root'; then
            if stat -Lc '%G' /etc/gshadow 2>/dev/null | grep -qE 'root|shadow'; then
                sec_audit_report_pass 272 "access to /etc/gshadow is configured"
            else
                sec_audit_report_fail 272 "File /etc/gshadow permissions or ownership not correct"
            fi
        else
            sec_audit_report_fail 272 "File /etc/gshadow permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 272 "File /etc/gshadow permissions or ownership not correct"
    fi
    else
    sec_audit_report_pass 272 "/etc/gshadow is absent (optional file; permission check skipped)"
    fi

    # RULE273
    if [ -e /etc/gshadow- ]; then
    if stat -Lc '%a' /etc/gshadow- 2>/dev/null | grep -qE '^[0-6]40$'; then
        if stat -Lc '%U' /etc/gshadow- 2>/dev/null | grep -q 'root'; then
            if stat -Lc '%G' /etc/gshadow- 2>/dev/null | grep -qE 'root|shadow'; then
                sec_audit_report_pass 273 "access to /etc/gshadow- is configured"
            else
                sec_audit_report_fail 273 "File /etc/gshadow- permissions or ownership not correct"
            fi
        else
            sec_audit_report_fail 273 "File /etc/gshadow- permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 273 "File /etc/gshadow- permissions or ownership not correct"
    fi
    else
    sec_audit_report_pass 273 "/etc/gshadow- is absent (optional file; permission check skipped)"
    fi

    # RULE274
    if stat -Lc '%a' /etc/shells 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' /etc/shells 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 274 "access to /etc/shells is configured"
    else
        sec_audit_report_fail 274 "File /etc/shells permissions or ownership not correct"
    fi
    else
    sec_audit_report_fail 274 "File /etc/shells permissions or ownership not correct"
    fi

    # RULE275
    if [ -e /etc/security/opasswd ]; then
    if stat -Lc '%a' /etc/security/opasswd 2>/dev/null | grep -q '^600$'; then
        if stat -Lc '%U:%G' /etc/security/opasswd 2>/dev/null | grep -q '^root:root$'; then
            sec_audit_report_pass 275 "access to /etc/security/opasswd is configured"
        else
            sec_audit_report_fail 275 "File /etc/security/opasswd permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 275 "File /etc/security/opasswd permissions or ownership not correct"
    fi
    else
    sec_audit_report_pass 275 "/etc/security/opasswd is absent (optional file; permission check skipped)"
    fi

}

sec_audit_run_filesystem_integrity() {
    # RULE276
    if awk -F: '($2 != "x" ) { print }' /etc/passwd 2>/dev/null | grep -q '.'; then
    sec_audit_report_fail 276 "Non-shadow password field found in /etc/passwd (second field not "x")"
    else
    sec_audit_report_pass 276 "accounts in /etc/passwd use shadowed passwords"
    fi

    # RULE277
    if awk -F: '($2 == "" ) { print }' /etc/shadow 2>/dev/null | grep -q '.'; then
    sec_audit_report_fail 277 "Empty password hash found in /etc/shadow"
    else
    sec_audit_report_pass 277 "/etc/shadow password fields are not empty"
    fi

    # RULE278
    if cut -f3 -d":" /etc/passwd 2>/dev/null | sort -n | uniq -c | while read -r count uid; do [ "$count" -gt 1 ] && echo "found"; done | grep -q "found"; then
    sec_audit_report_fail 278 "Duplicate UID entries exist in /etc/passwd"
    else
    sec_audit_report_pass 278 "no duplicate UIDs exist"
    fi

    # RULE279
    if cut -f3 -d":" /etc/group 2>/dev/null | sort -n | uniq -c | while read -r count gid; do [ "$count" -gt 1 ] && echo "found"; done | grep -q "found"; then
    sec_audit_report_fail 279 "Duplicate GID entries exist in /etc/group"
    else
    sec_audit_report_pass 279 "no duplicate GIDs exist"
    fi

    # RULE280
    if cut -f1 -d":" /etc/passwd 2>/dev/null | sort -n | uniq -c | while read -r count user; do [ "$count" -gt 1 ] && echo "found"; done | grep -q "found"; then
    sec_audit_report_fail 280 "Duplicate user names exist in /etc/passwd"
    else
    sec_audit_report_pass 280 "no duplicate user names exist"
    fi

    # RULE281
    if cut -f1 -d":" /etc/group 2>/dev/null | sort -n | uniq -c | while read -r count group; do [ "$count" -gt 1 ] && echo "found"; done | grep -q "found"; then
    sec_audit_report_fail 281 "Duplicate group names exist in /etc/group"
    else
    sec_audit_report_pass 281 "no duplicate group names exist"
    fi

    # RULE282
    if awk -F: '($1=="shadow") {print $4}' /etc/group 2>/dev/null | grep -q '.'; then
    sec_audit_report_fail 282 "shadow group is not empty"
    else
    sec_audit_report_pass 282 "shadow group is empty"
    fi

    # RULE283
    FAIL283=0
    while IFS=: read -r user pass uid gid rest; do
    if [ "$uid" -ge 1000 ] 2>/dev/null && [ "$uid" -lt 65534 ]; then
        home=$(echo "$rest" | cut -d: -f1)
        for dotfile in "$home/.bashrc" "$home/.bash_profile" "$home/.profile" "$home/.bash_logout"; do
            if [ -f "$dotfile" ]; then
                perm=$(stat -c '%a' "$dotfile" 2>/dev/null)
                if [ "${perm:2:1}" -gt 0 ] 2>/dev/null || [ "${perm:1:1}" -gt 0 ] 2>/dev/null; then
                    sec_audit_report_fail 283 "User $user dot file $dotfile has world/group write permissions ($perm)"
                    FAIL283=1
                fi
            fi
        done
    fi
    done < /etc/passwd 2>/dev/null
    [ $FAIL283 -eq 0 ] && sec_audit_report_pass 283 "Local interactive user dot files access is configured"

    # RULE284
    if awk -F: '($2 != "" && $2 != "x") {print}' /etc/group 2>/dev/null | grep -q .; then
    sec_audit_report_fail 284 "/etc/group contains non-empty password field(s)"
    else
    sec_audit_report_pass 284 "no passwords are stored in /etc/group"
    fi

    exit 0

}

sec_audit_main() {
    sec_audit_run_kernel_modules
    sec_audit_run_filesystem_partitions
    sec_audit_run_package_security
    sec_audit_run_apparmor
    sec_audit_run_bootloader
    sec_audit_run_process_hardening
    sec_audit_run_banners
    sec_audit_run_gdm
    sec_audit_run_unused_services
    sec_audit_run_client_tools
    sec_audit_run_time_sync
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
