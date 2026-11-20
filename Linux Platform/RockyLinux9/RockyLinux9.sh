#!/bin/bash

# SecAudit rule allowlist — source or paste into audit/remediation shell scripts.
# Unset/empty SECAUDIT_RULES and SECAUDIT_REMEDIATE_RULES => all rules enabled.
secaudit_rule_enabled() {
    local raw="${SECAUDIT_RULES:-${SECAUDIT_REMEDIATE_RULES:-}}" id="$1" token n want
    [ -z "$raw" ] && return 0
    n="${id#RULE}"; n="${n#rule}"; n="${n#Rule}"
    case "$n" in (*[!0-9]*|"") want=$(printf '%s' "$id" | tr '[:lower:]' '[:upper:]') ;;
        *) want="RULE$((10#$n))" ;;
    esac
    local IFS=','
    for token in $raw; do
        token=$(printf '%s' "$token" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')
        [ -z "$token" ] && continue
        local tn="${token#RULE}"
        case "$tn" in (*[!0-9]*|"") ;;
            *) token="RULE$((10#$tn))" ;;
        esac
        [ "$token" = "$want" ] && return 0
    done
    return 1
}

# --- bootstrap / reporting ---
sec_audit_report_pass() { secaudit_rule_enabled "$1" || return 0; printf 'RULE%s= PASS: %s\n' "$1" "$2"; }
sec_audit_report_fail() { secaudit_rule_enabled "$1" || return 0; printf 'RULE%s= FAIL: %s\n' "$1" "${3:-$2}"; }
sec_audit_report_skip() { secaudit_rule_enabled "$1" || return 0; printf 'RULE%s= SKIP: %s\n' "$1" "$2"; }
sec_audit_report_error() { secaudit_rule_enabled "$1" || return 0; printf 'RULE%s= ERROR: %s\n' "$1" "$2"; }
sec_audit_report_review() { secaudit_rule_enabled "$1" || return 0; printf 'RULE%s= REVIEW: %s\n' "$1" "$2"; }
sec_audit_report_warn() { secaudit_rule_enabled "$1" || return 0; printf 'RULE%s= WARN: %s\n' "$1" "$2"; }

export LC_ALL=C

sec_audit_have_bin() {
    command -v "$1" >/dev/null 2>&1
}

sec_audit_low_impact_find() {
    local timeout_seconds=""
    local cmd=()

    if [[ "${1:-}" == --timeout=* ]]; then
        timeout_seconds="${1#--timeout=}"
        shift
    fi

    if [ -n "$timeout_seconds" ] && sec_audit_have_bin timeout; then
        cmd+=(timeout "$timeout_seconds")
    fi
    if sec_audit_have_bin nice; then
        cmd+=(nice -n 19)
    fi
    if sec_audit_have_bin ionice; then
        cmd+=(ionice -c3)
    fi

    cmd+=(find "$@")
    "${cmd[@]}"
}

sec_audit_safe_find_roots() {
    if ! sec_audit_have_bin findmnt; then
        builtin printf '%s\n' /
        return 0
    fi

    findmnt -rn -o TARGET,FSTYPE,OPTIONS 2>/dev/null | awk '
        BEGIN {
            skip_fs["proc"]; skip_fs["sysfs"]; skip_fs["devtmpfs"]; skip_fs["devpts"];
            skip_fs["tmpfs"]; skip_fs["cgroup"]; skip_fs["cgroup2"]; skip_fs["pstore"];
            skip_fs["securityfs"]; skip_fs["debugfs"]; skip_fs["tracefs"]; skip_fs["configfs"];
            skip_fs["fusectl"]; skip_fs["mqueue"]; skip_fs["hugetlbfs"]; skip_fs["rpc_pipefs"];
            skip_fs["autofs"]; skip_fs["overlay"]; skip_fs["squashfs"]; skip_fs["iso9660"];
            skip_fs["nfs"]; skip_fs["nfs4"]; skip_fs["cifs"]; skip_fs["smbfs"]; skip_fs["sshfs"];
            skip_fs["fuse.sshfs"]; skip_fs["afs"]; skip_fs["ceph"]; skip_fs["glusterfs"];
            skip_fs["gpfs"]; skip_fs["lustre"];
        }
        {
            target=$1; fstype=$2; options=$3;
            if (target == "" || fstype == "" || target ~ "^/(proc|sys|dev|run)(/|$)") next;
            if (fstype in skip_fs) next;
            if (options ~ /(^|,)bind(,|$)/) next;
            print target;
        }
    ' | sort -u
}

sec_audit_findmnt_have() {
    sec_audit_have_bin findmnt
}

sec_audit_findmnt_path_resolvable() {
    local mp="${1%/}"
    sec_audit_findmnt_have || return 1
    findmnt -kn -T "$mp" &>/dev/null
}

sec_audit_findmnt_is_explicit_mountpoint() {
    local mp="${1%/}" tgt
    sec_audit_findmnt_have || return 1
    tgt=$(findmnt -kn -T "$mp" -o TARGET --noheadings 2>/dev/null | head -n1)
    tgt="${tgt#"${tgt%%[![:space:]]*}"}"
    tgt="${tgt%"${tgt##*[![:space:]]}"}"
    tgt="${tgt%/}"
    [ -n "$tgt" ] && [ "$tgt" = "$mp" ]
}

sec_audit_findmnt_source_for() {
    local mp="${1%/}" s
    sec_audit_findmnt_have || return 1
    s=$(findmnt -kn -T "$mp" -o SOURCE --noheadings 2>/dev/null | head -n1)
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    builtin printf '%s' "$s"
}

sec_audit_findmnt_fstype_for() {
    local mp="${1%/}" f
    sec_audit_findmnt_have || return 1
    f=$(findmnt -kn -T "$mp" -o FSTYPE --noheadings 2>/dev/null | head -n1)
    f="${f#"${f%%[![:space:]]*}"}"
    f="${f%"${f##*[![:space:]]}"}"
    builtin printf '%s' "$f"
}

sec_audit_findmnt_options_raw() {
    local mp="${1%/}" o
    sec_audit_findmnt_have || return 1
    o=$(findmnt -kn -T "$mp" -o OPTIONS --noheadings 2>/dev/null | head -n1)
    o="${o#"${o%%[![:space:]]*}"}"
    o="${o%"${o##*[![:space:]]}"}"
    builtin printf '%s' "$o"
}

sec_audit_findmnt_has_mnt_option() {
    local mp="$1" want="$2" opts token
    sec_audit_findmnt_have || return 1
    opts=$(sec_audit_findmnt_options_raw "$mp")
    [ -z "$opts" ] && return 1
    local IFS=,
    for token in $opts; do
        token="${token#"${token%%[![:space:]]*}"}"
        token="${token%"${token##*[![:space:]]}"}"
        [ "$token" = "$want" ] && return 0
    done
    return 1
}

sec_audit_findmnt_tmp_cis_ok() {
    local fst src root_src
    sec_audit_findmnt_have || return 1
    sec_audit_findmnt_is_explicit_mountpoint /tmp || return 1
    fst=$(sec_audit_findmnt_fstype_for /tmp)
    src=$(sec_audit_findmnt_source_for /tmp)
    root_src=$(sec_audit_findmnt_source_for /)
    [ "$fst" = "tmpfs" ] && return 0
    [ -n "$src" ] && [ -n "$root_src" ] && [ "$src" != "$root_src" ] && return 0
    return 1
}

sec_audit_findmnt_shm_cis_ok() {
    local fst src root_src
    sec_audit_findmnt_have || return 1
    sec_audit_findmnt_is_explicit_mountpoint /dev/shm || return 1
    fst=$(sec_audit_findmnt_fstype_for /dev/shm)
    src=$(sec_audit_findmnt_source_for /dev/shm)
    root_src=$(sec_audit_findmnt_source_for /)
    [ "$fst" = "tmpfs" ] && return 0
    [ -n "$src" ] && [ -n "$root_src" ] && [ "$src" != "$root_src" ] && return 0
    return 1
}

sec_audit_findmnt_separate_partition_ok() {
    local mp="${1%/}" src root_src
    sec_audit_findmnt_have || return 1
    sec_audit_findmnt_is_explicit_mountpoint "$mp" || return 1
    src=$(sec_audit_findmnt_source_for "$mp")
    root_src=$(sec_audit_findmnt_source_for /)
    [ -n "$src" ] && [ -n "$root_src" ] && [ "$src" != "$root_src" ]
}

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
                flush
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
                flush
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
        ' "$f" && { shopt -u nullglob; return 0; }
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

_AUDITCTL_L_READY=0
_auditctl_l_cache=""

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

sec_audit__req_sysctl_check() {
    local num="$1" key="$2" want="$3" r
    r=$(sec_audit_sysctl_key_runtime "$key")
    if sec_audit_sysctl_runtime_equals "$key" "$want"; then
        sec_audit_report_pass ${num} "${key}=${want} in kernel$(sec_audit_sysctl_runtime_disk_hint "$key" "$want")"
    else
        sec_audit_report_fail ${num} "kernel ${key} is '${r:-<unreadable>}', expected ${want}$(sec_audit_sysctl_runtime_disk_hint "$key" "$want")"
    fi
}

sec_audit_kernel_mod_in_modules_load() {
    local pat="" a
    for a in "$@"; do
        pat+="${pat:+|}${a}"
    done
    grep -rqE "^[[:space:]]*(${pat})([[:space:]]|$)" /etc/modules-load.d /usr/lib/modules-load.d /run/modules-load.d 2>/dev/null
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

DNF_TIMEOUT="${DNF_TIMEOUT:-30}"
CMD_TIMEOUT="${CMD_TIMEOUT:-10}"

sec_audit_timed_run() {
    local t="$1"
    shift
    if sec_audit_have_bin timeout; then
        timeout "$t" "$@"
    else
        "$@"
    fi
}

_DNF_CHECK_UPDATE_READY=0
_DNF_CHECK_UPDATE_OUT=""
_DNF_CHECK_UPDATE_RC=0

sec_audit_dnf_check_update_security_ensure() {
    if [ "$_DNF_CHECK_UPDATE_READY" -eq 1 ]; then
        return 0
    fi
    _DNF_CHECK_UPDATE_READY=1
    _DNF_CHECK_UPDATE_OUT=""
    _DNF_CHECK_UPDATE_RC=0
    if ! sec_audit_have_bin dnf; then
        _DNF_CHECK_UPDATE_RC=2
        return 0
    fi
    _DNF_CHECK_UPDATE_OUT=$(sec_audit_timed_run "$DNF_TIMEOUT" dnf -q check-update --security 2>/dev/null)
    _DNF_CHECK_UPDATE_RC=$?
}

sec_audit_audit_rule_disk_or_loaded() {
    local pat="$1"
    sec_audit_audit_rules_files_grep -q "$pat" && return 0
    sec_audit_auditctl_rules_grep -q "$pat" && return 0
    return 1
}

sec_audit_gdm_package_installed() {
    rpm -q gdm &>/dev/null
}

# =============================================================================
# Section runners
# =============================================================================

sec_audit_run_initial_setup() {
if secaudit_rule_enabled 1; then
if sec_audit_kernel_mod_in_modules_load cramfs; then
    sec_audit_report_fail 1 "cramfs kernel module is listed in modules-load.d (auto-load at boot)"
elif ! sec_audit_low_impact_find --timeout=20 /usr/lib/modules/ /lib/modules/ -xdev -ignore_readdir_race -type f -name "cramfs.ko*" 2>/dev/null | grep -q .; then
    sec_audit_report_pass 1 "cramfs kernel module is not available"
else
    if ! lsmod | grep -q cramfs && modprobe --showconfig | grep -Pq '^\h*(blacklist|install)\h+cramfs\b'; then
        sec_audit_report_pass 1 "cramfs kernel module is not available"
    else
        sec_audit_report_fail 1 "cramfs kernel module is available, loaded, or not effectively blocked (modprobe blacklist/install)"
    fi
fi

fi
if secaudit_rule_enabled 2; then
if sec_audit_kernel_mod_in_modules_load freevxfs; then
    sec_audit_report_fail 2 "freevxfs kernel module is listed in modules-load.d (auto-load at boot)"
elif ! sec_audit_low_impact_find --timeout=20 /usr/lib/modules/ /lib/modules/ -xdev -ignore_readdir_race -type f -name "freevxfs.ko*" 2>/dev/null | grep -q .; then
    sec_audit_report_pass 2 "freevxfs kernel module is not available"
else
    if ! lsmod | grep -q freevxfs && modprobe --showconfig | grep -Pq '^\h*(blacklist|install)\h+freevxfs\b'; then
        sec_audit_report_pass 2 "freevxfs kernel module is not available"
    else
        sec_audit_report_fail 2 "freevxfs kernel module is available, loaded, or not effectively blocked (modprobe blacklist/install)"
    fi
fi

fi
if secaudit_rule_enabled 3; then
if sec_audit_kernel_mod_in_modules_load hfs; then
    sec_audit_report_fail 3 "hfs kernel module is listed in modules-load.d (auto-load at boot)"
elif ! sec_audit_low_impact_find --timeout=20 /usr/lib/modules/ /lib/modules/ -xdev -ignore_readdir_race -type f -name "hfs.ko*" 2>/dev/null | grep -q .; then
    sec_audit_report_pass 3 "hfs kernel module is not available"
else
    if ! lsmod | grep -q hfs && modprobe --showconfig | grep -Pq '^\h*(blacklist|install)\h+hfs\b'; then
        sec_audit_report_pass 3 "hfs kernel module is not available"
    else
        sec_audit_report_fail 3 "hfs kernel module is available, loaded, or not effectively blocked (modprobe blacklist/install)"
    fi
fi

fi
if secaudit_rule_enabled 4; then
if sec_audit_kernel_mod_in_modules_load hfsplus; then
    sec_audit_report_fail 4 "hfsplus kernel module is listed in modules-load.d (auto-load at boot)"
elif ! sec_audit_low_impact_find --timeout=20 /usr/lib/modules/ /lib/modules/ -xdev -ignore_readdir_race -type f -name "hfsplus.ko*" 2>/dev/null | grep -q .; then
    sec_audit_report_pass 4 "hfsplus kernel module is not available"
else
    if ! lsmod | grep -q hfsplus && modprobe --showconfig | grep -Pq '^\h*(blacklist|install)\h+hfsplus\b'; then
        sec_audit_report_pass 4 "hfsplus kernel module is not available"
    else
        sec_audit_report_fail 4 "hfsplus kernel module is available, loaded, or not effectively blocked (modprobe blacklist/install)"
    fi
fi

fi
if secaudit_rule_enabled 5; then
if sec_audit_kernel_mod_in_modules_load jffs2; then
    sec_audit_report_fail 5 "jffs2 kernel module is listed in modules-load.d (auto-load at boot)"
elif ! sec_audit_low_impact_find --timeout=20 /usr/lib/modules/ /lib/modules/ -xdev -ignore_readdir_race -type f -name "jffs2.ko*" 2>/dev/null | grep -q .; then
    sec_audit_report_pass 5 "jffs2 kernel module is not available"
else
    if ! lsmod | grep -q jffs2 && modprobe --showconfig | grep -Pq '^\h*(blacklist|install)\h+jffs2\b'; then
        sec_audit_report_pass 5 "jffs2 kernel module is not available"
    else
        sec_audit_report_fail 5 "jffs2 kernel module is available, loaded, or not effectively blocked (modprobe blacklist/install)"
    fi
fi

fi
if secaudit_rule_enabled 6; then
if sec_audit_kernel_mod_in_modules_load overlay; then
    sec_audit_report_fail 6 "overlay kernel module is listed in modules-load.d (auto-load at boot)"
elif ! sec_audit_low_impact_find --timeout=20 /usr/lib/modules/ /lib/modules/ -xdev -ignore_readdir_race -type f -name "overlay.ko*" 2>/dev/null | grep -q .; then
    sec_audit_report_pass 6 "overlay kernel module is not available"
else
    if ! lsmod | grep -q overlay && modprobe --showconfig | grep -Pq '^\h*(blacklist|install)\h+overlay\b'; then
        sec_audit_report_pass 6 "overlay kernel module is not available"
    else
        sec_audit_report_fail 6 "overlay kernel module is available, loaded, or not effectively blocked (modprobe blacklist/install)"
    fi
fi

fi
if secaudit_rule_enabled 7; then
if sec_audit_kernel_mod_in_modules_load squashfs; then
    sec_audit_report_fail 7 "squashfs kernel module is listed in modules-load.d (auto-load at boot)"
elif ! sec_audit_low_impact_find --timeout=20 /usr/lib/modules/ /lib/modules/ -xdev -ignore_readdir_race -type f -name "squashfs.ko*" 2>/dev/null | grep -q .; then
    sec_audit_report_pass 7 "squashfs kernel module is not available"
else
    if ! lsmod | grep -q squashfs && modprobe --showconfig | grep -Pq '^\h*(blacklist|install)\h+squashfs\b'; then
        sec_audit_report_pass 7 "squashfs kernel module is not available"
    else
        sec_audit_report_fail 7 "squashfs kernel module is available, loaded, or not effectively blocked (modprobe blacklist/install)"
    fi
fi

fi
if secaudit_rule_enabled 8; then
if sec_audit_kernel_mod_in_modules_load udf; then
    sec_audit_report_fail 8 "udf kernel module is listed in modules-load.d (auto-load at boot)"
elif ! sec_audit_low_impact_find --timeout=20 /usr/lib/modules/ /lib/modules/ -xdev -ignore_readdir_race -type f -name "udf.ko*" 2>/dev/null | grep -q .; then
    sec_audit_report_pass 8 "udf kernel module is not available"
else
    if ! lsmod | grep -q udf && modprobe --showconfig | grep -Pq '^\h*(blacklist|install)\h+udf\b'; then
        sec_audit_report_pass 8 "udf kernel module is not available"
    else
        sec_audit_report_fail 8 "udf kernel module is available, loaded, or not effectively blocked (modprobe blacklist/install)"
    fi
fi

fi
if secaudit_rule_enabled 9; then
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

fi
if secaudit_rule_enabled 10; then
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

fi
if secaudit_rule_enabled 11; then
sec_audit_report_review 11 "verify unused filesystem kernel modules are disabled per site policy ( manual check)"

fi
if secaudit_rule_enabled 12; then
if sec_audit_findmnt_tmp_cis_ok; then
    sec_audit_report_pass 12 "/tmp is tmpfs or a separate partition"
else
    sec_audit_report_fail 12 "/tmp does not meet tmpfs or separate-partition requirement"
fi

fi
if secaudit_rule_enabled 13; then
if sec_audit_findmnt_path_resolvable /tmp && sec_audit_findmnt_has_mnt_option /tmp nodev; then
    sec_audit_report_pass 13 "nodev option set on /tmp partition"
elif ! sec_audit_findmnt_path_resolvable /tmp; then
    sec_audit_report_fail 13 "nodev is not set on /tmp (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 13 "nodev is not set on /tmp (or path not resolvable / not an explicit mount per policy)"
fi

fi
if secaudit_rule_enabled 14; then
if sec_audit_findmnt_path_resolvable /tmp && sec_audit_findmnt_has_mnt_option /tmp nosuid; then
    sec_audit_report_pass 14 "nosuid option set on /tmp partition"
elif ! sec_audit_findmnt_path_resolvable /tmp; then
    sec_audit_report_fail 14 "nosuid is not set on /tmp (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 14 "nosuid is not set on /tmp (or path not resolvable / not an explicit mount per policy)"
fi

fi
if secaudit_rule_enabled 15; then
if sec_audit_findmnt_path_resolvable /tmp && sec_audit_findmnt_has_mnt_option /tmp noexec; then
    sec_audit_report_pass 15 "noexec option set on /tmp partition"
elif ! sec_audit_findmnt_path_resolvable /tmp; then
    sec_audit_report_fail 15 "noexec is not set on /tmp (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 15 "noexec is not set on /tmp (or path not resolvable / not an explicit mount per policy)"
fi

fi
if secaudit_rule_enabled 16; then
if sec_audit_findmnt_shm_cis_ok; then
    sec_audit_report_pass 16 "/dev/shm is tmpfs or a separate partition"
else
    sec_audit_report_fail 16 "/dev/shm does not meet tmpfs or separate-partition requirement"
fi

fi
if secaudit_rule_enabled 17; then
if sec_audit_findmnt_path_resolvable /dev/shm && sec_audit_findmnt_has_mnt_option /dev/shm nodev; then
    sec_audit_report_pass 17 "nodev option set on /dev/shm partition"
elif ! sec_audit_findmnt_path_resolvable /dev/shm; then
    sec_audit_report_fail 17 "nodev is not set on /dev/shm (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 17 "nodev is not set on /dev/shm (or path not resolvable / not an explicit mount per policy)"
fi

fi
if secaudit_rule_enabled 18; then
if sec_audit_findmnt_path_resolvable /dev/shm && sec_audit_findmnt_has_mnt_option /dev/shm nosuid; then
    sec_audit_report_pass 18 "nosuid option set on /dev/shm partition"
elif ! sec_audit_findmnt_path_resolvable /dev/shm; then
    sec_audit_report_fail 18 "nosuid is not set on /dev/shm (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 18 "nosuid is not set on /dev/shm (or path not resolvable / not an explicit mount per policy)"
fi

fi
if secaudit_rule_enabled 19; then
if sec_audit_findmnt_path_resolvable /dev/shm && sec_audit_findmnt_has_mnt_option /dev/shm noexec; then
    sec_audit_report_pass 19 "noexec option set on /dev/shm partition"
elif ! sec_audit_findmnt_path_resolvable /dev/shm; then
    sec_audit_report_fail 19 "noexec is not set on /dev/shm (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 19 "noexec is not set on /dev/shm (or path not resolvable / not an explicit mount per policy)"
fi

fi
if secaudit_rule_enabled 20; then
if sec_audit_findmnt_separate_partition_ok /home; then
    sec_audit_report_pass 20 "separate partition exists for /home"
else
    sec_audit_report_fail 20 "no compliant dedicated mount for /home"
fi

fi
if secaudit_rule_enabled 21; then
if sec_audit_findmnt_path_resolvable /home && sec_audit_findmnt_has_mnt_option /home nodev; then
    sec_audit_report_pass 21 "nodev option set on /home partition"
elif ! sec_audit_findmnt_path_resolvable /home; then
    sec_audit_report_fail 21 "nodev is not set on /home (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 21 "nodev is not set on /home (or path not resolvable / not an explicit mount per policy)"
fi

fi
if secaudit_rule_enabled 22; then
if sec_audit_findmnt_path_resolvable /home && sec_audit_findmnt_has_mnt_option /home nosuid; then
    sec_audit_report_pass 22 "nosuid option set on /home partition"
elif ! sec_audit_findmnt_path_resolvable /home; then
    sec_audit_report_fail 22 "nosuid is not set on /home (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 22 "nosuid is not set on /home (or path not resolvable / not an explicit mount per policy)"
fi

fi
if secaudit_rule_enabled 23; then
if sec_audit_findmnt_separate_partition_ok /var; then
    sec_audit_report_pass 23 "separate partition exists for /var"
else
    sec_audit_report_fail 23 "no compliant dedicated mount for /var"
fi

fi
if secaudit_rule_enabled 24; then
if sec_audit_findmnt_path_resolvable /var && sec_audit_findmnt_has_mnt_option /var nodev; then
    sec_audit_report_pass 24 "nodev option set on /var partition"
elif ! sec_audit_findmnt_path_resolvable /var; then
    sec_audit_report_fail 24 "nodev is not set on /var (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 24 "nodev is not set on /var (or path not resolvable / not an explicit mount per policy)"
fi

fi
if secaudit_rule_enabled 25; then
if sec_audit_findmnt_path_resolvable /var && sec_audit_findmnt_has_mnt_option /var nosuid; then
    sec_audit_report_pass 25 "nosuid option set on /var partition"
elif ! sec_audit_findmnt_path_resolvable /var; then
    sec_audit_report_fail 25 "nosuid is not set on /var (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 25 "nosuid is not set on /var (or path not resolvable / not an explicit mount per policy)"
fi

fi
if secaudit_rule_enabled 26; then
if sec_audit_findmnt_separate_partition_ok /var/tmp; then
    sec_audit_report_pass 26 "separate partition exists for /var/tmp"
else
    sec_audit_report_fail 26 "no compliant dedicated mount for /var/tmp"
fi

fi
if secaudit_rule_enabled 27; then
if sec_audit_findmnt_path_resolvable /var/tmp && sec_audit_findmnt_has_mnt_option /var/tmp nodev; then
    sec_audit_report_pass 27 "nodev option set on /var/tmp partition"
elif ! sec_audit_findmnt_path_resolvable /var/tmp; then
    sec_audit_report_fail 27 "nodev is not set on /var/tmp (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 27 "nodev is not set on /var/tmp (or path not resolvable / not an explicit mount per policy)"
fi

fi
if secaudit_rule_enabled 28; then
if sec_audit_findmnt_path_resolvable /var/tmp && sec_audit_findmnt_has_mnt_option /var/tmp nosuid; then
    sec_audit_report_pass 28 "nosuid option set on /var/tmp partition"
elif ! sec_audit_findmnt_path_resolvable /var/tmp; then
    sec_audit_report_fail 28 "nosuid is not set on /var/tmp (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 28 "nosuid is not set on /var/tmp (or path not resolvable / not an explicit mount per policy)"
fi

fi
if secaudit_rule_enabled 29; then
if sec_audit_findmnt_path_resolvable /var/tmp && sec_audit_findmnt_has_mnt_option /var/tmp noexec; then
    sec_audit_report_pass 29 "noexec option set on /var/tmp partition"
elif ! sec_audit_findmnt_path_resolvable /var/tmp; then
    sec_audit_report_fail 29 "noexec is not set on /var/tmp (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 29 "noexec is not set on /var/tmp (or path not resolvable / not an explicit mount per policy)"
fi

fi
if secaudit_rule_enabled 30; then
if sec_audit_findmnt_separate_partition_ok /var/log; then
    sec_audit_report_pass 30 "separate partition exists for /var/log"
else
    sec_audit_report_fail 30 "no compliant dedicated mount for /var/log"
fi

fi
if secaudit_rule_enabled 31; then
if sec_audit_findmnt_path_resolvable /var/log && sec_audit_findmnt_has_mnt_option /var/log nodev; then
    sec_audit_report_pass 31 "nodev option set on /var/log partition"
elif ! sec_audit_findmnt_path_resolvable /var/log; then
    sec_audit_report_fail 31 "nodev is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 31 "nodev is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
fi

fi
if secaudit_rule_enabled 32; then
if sec_audit_findmnt_path_resolvable /var/log && sec_audit_findmnt_has_mnt_option /var/log nosuid; then
    sec_audit_report_pass 32 "nosuid option set on /var/log partition"
elif ! sec_audit_findmnt_path_resolvable /var/log; then
    sec_audit_report_fail 32 "nosuid is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 32 "nosuid is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
fi

fi
if secaudit_rule_enabled 33; then
if sec_audit_findmnt_path_resolvable /var/log && sec_audit_findmnt_has_mnt_option /var/log noexec; then
    sec_audit_report_pass 33 "noexec option set on /var/log partition"
elif ! sec_audit_findmnt_path_resolvable /var/log; then
    sec_audit_report_fail 33 "noexec is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 33 "noexec is not set on /var/log (or path not resolvable / not an explicit mount per policy)"
fi

fi
if secaudit_rule_enabled 34; then
if sec_audit_findmnt_separate_partition_ok /var/log/audit; then
    sec_audit_report_pass 34 "separate partition exists for /var/log/audit"
else
    sec_audit_report_fail 34 "no compliant dedicated mount for /var/log/audit"
fi

fi
if secaudit_rule_enabled 35; then
if sec_audit_findmnt_path_resolvable /var/log/audit && sec_audit_findmnt_has_mnt_option /var/log/audit nodev; then
    sec_audit_report_pass 35 "nodev option set on /var/log/audit partition"
elif ! sec_audit_findmnt_path_resolvable /var/log/audit; then
    sec_audit_report_fail 35 "nodev is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 35 "nodev is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
fi

fi
if secaudit_rule_enabled 36; then
if sec_audit_findmnt_path_resolvable /var/log/audit && sec_audit_findmnt_has_mnt_option /var/log/audit nosuid; then
    sec_audit_report_pass 36 "nosuid option set on /var/log/audit partition"
elif ! sec_audit_findmnt_path_resolvable /var/log/audit; then
    sec_audit_report_fail 36 "nosuid is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 36 "nosuid is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
fi

fi
if secaudit_rule_enabled 37; then
if sec_audit_findmnt_path_resolvable /var/log/audit && sec_audit_findmnt_has_mnt_option /var/log/audit noexec; then
    sec_audit_report_pass 37 "noexec option set on /var/log/audit partition"
elif ! sec_audit_findmnt_path_resolvable /var/log/audit; then
    sec_audit_report_fail 37 "noexec is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
else
    sec_audit_report_fail 37 "noexec is not set on /var/log/audit (or path not resolvable / not an explicit mount per policy)"
fi

fi
if secaudit_rule_enabled 38; then
_req37_k=$(sec_audit_rpm_gpg_pubkey_pkg_count)
_req37_sample=""
if sec_audit_have_bin rpm && [ "${_req37_k:-0}" -gt 0 ]; then
    _req37_sample=$(
        rpm -qa 'gpg-pubkey*' --qf '%{VERSION}\n' 2>/dev/null | awk 'NF && NR <= 6 { s = (s ? s "," : s) $1 } END { print s }'
    )
fi
if ! sec_audit_have_bin rpm; then
    sec_audit_report_fail 38 "rpm not available; cannot verify gpg-pubkey packages in the RPM database"
elif [ "${_req37_k:-0}" -eq 0 ]; then
    sec_audit_report_fail 38 "no gpg-pubkey packages in the RPM database (import distribution or repository signing keys)"
else
    sec_audit_report_pass 38 "${_req37_k} gpg-pubkey package(s) in RPM DB (sample key VERSION ids: ${_req37_sample:-n/a})"
fi

fi
if secaudit_rule_enabled 39; then
_req38_main=$(sec_audit_dnf_main_last_value gpgcheck)
_req38_repo=$(sec_audit__yum_repo_list_explicit_gpgcheck0 | head -n1)
if sec_audit_dnf_val_is_false "$_req38_main"; then
    sec_audit_report_fail 39 "merged [main] gpgcheck is disabled (effective value: ${_req38_main})"
elif [ -n "$_req38_repo" ]; then
    sec_audit_report_fail 39 "enabled repository section explicitly sets gpgcheck=0 (${_req38_repo//|/ -> })"
else
    sec_audit_report_pass 39 "[main] gpgcheck is not false and no enabled .repo section forces gpgcheck=0"
fi

fi
if secaudit_rule_enabled 40; then
_req39_main=$(sec_audit_dnf_main_last_value repo_gpgcheck)
_req39_repo=$(sec_audit__yum_repo_list_explicit_repo_gpgcheck0 | head -n1)
if sec_audit_dnf_val_is_false "$_req39_main"; then
    sec_audit_report_fail 40 "merged [main] repo_gpgcheck is disabled (effective value: ${_req39_main})"
elif [ -z "$_req39_main" ]; then
    sec_audit_report_fail 40 "repo_gpgcheck not explicitly enabled in merged [main] (dnf defaults to false when unset)"
elif ! sec_audit_dnf_val_is_true "$_req39_main"; then
    sec_audit_report_fail 40 "repo_gpgcheck in [main] is not a true value (expected 1/true/yes/on; got: ${_req39_main})"
elif [ -n "$_req39_repo" ]; then
    sec_audit_report_fail 40 "enabled repository section explicitly sets repo_gpgcheck=0 (${_req39_repo//|/ -> })"
else
    sec_audit_report_pass 40 "repo_gpgcheck enabled in [main] and no enabled .repo section forces repo_gpgcheck=0"
fi

fi
if secaudit_rule_enabled 41; then
_req40_dnf_n=$(sec_audit_dnf_repolist_enabled_count)
if [ ! -d /etc/yum.repos.d ]; then
    sec_audit_report_fail 41 "/etc/yum.repos.d is missing"
else
    _req40_nrepo=0
    shopt -s nullglob
    for _rf in /etc/yum.repos.d/*.repo; do
        [ -f "$_rf" ] && _req40_nrepo=$((_req40_nrepo + 1))
    done
    shopt -u nullglob
    if [ "${_req40_nrepo:-0}" -eq 0 ]; then
        sec_audit_report_fail 41 "no .repo files under /etc/yum.repos.d"
    elif ! sec_audit__yum_repo_any_enabled_has_uris; then
        sec_audit_report_fail 41 "no enabled repository section defines a non-empty baseurl, mirrorlist, or metalink"
    elif sec_audit_have_bin dnf && [ "${_req40_dnf_n:-0}" -eq 0 ]; then
        sec_audit_report_fail 41 ".repo files define URIs but dnf repolist enabled reports 0 repos (metadata, plugin, or config error)"
    else
        if sec_audit_have_bin dnf && [ "${_req40_dnf_n:-0}" -gt 0 ]; then
            sec_audit_report_pass 41 "${_req40_nrepo} .repo file(s); dnf reports ${_req40_dnf_n} enabled repo(s); enabled sections include package URIs"
        else
            sec_audit_report_pass 41 "${_req40_nrepo} .repo file(s); enabled sections include baseurl/mirrorlist/metalink (dnf not used for count)"
        fi
    fi
fi

fi
if secaudit_rule_enabled 42; then
_req41_iwd=$(sec_audit_dnf_main_last_value install_weak_deps)
if sec_audit_dnf_val_is_false "$_req41_iwd"; then
    sec_audit_report_pass 42 "install_weak_deps is false in merged [main] (weak dependencies not installed by default)"
elif [ -z "$_req41_iwd" ]; then
    sec_audit_report_fail 42 "install_weak_deps not set to 0/false/no/off in [main] (dnf default enables weak dependencies)"
else
    sec_audit_report_fail 42 "install_weak_deps is not false in merged [main] (effective: ${_req41_iwd})"
fi

fi
if secaudit_rule_enabled 43; then
if ! sec_audit_have_bin dnf; then
	sec_audit_report_fail 43 "dnf unavailable; cannot verify package updates"
else
	sec_audit_dnf_check_update_security_ensure
	if [ "${_DNF_CHECK_UPDATE_RC}" -eq 124 ]; then
		sec_audit_report_pass 43 "dnf check-update --security timed out after ${DNF_TIMEOUT}s (repos unreachable); update status not verified"
	elif [ "${_DNF_CHECK_UPDATE_RC}" -eq 100 ] || printf '%s\n' "$_DNF_CHECK_UPDATE_OUT" | tail -n +2 | grep -qE '^[[:alnum:]_]'; then
		_sec=$(printf '%s\n' "$_DNF_CHECK_UPDATE_OUT" | tail -n +2 | grep -cE '^[[:alnum:]_]' || true)
		sec_audit_report_fail 43 "security updates pending (${_sec} package(s))"
	elif [ "${_DNF_CHECK_UPDATE_RC}" -eq 0 ]; then
		sec_audit_report_pass 43 "no pending security updates reported by dnf check-update --security"
	else
		sec_audit_report_pass 43 "dnf check-update --security failed (exit ${_DNF_CHECK_UPDATE_RC}); cannot confirm pending security updates"
	fi
fi

fi
if secaudit_rule_enabled 44; then
if rpm -q libselinux &>/dev/null; then
    sec_audit_report_pass 44 "SELinux is installed"
else
    sec_audit_report_fail 44 "SELinux stack (libselinux) is not installed"
fi

fi
if secaudit_rule_enabled 45; then
if grep -P '(selinux|enforcing)=0\b' /proc/cmdline 2>/dev/null; then
    sec_audit_report_fail 45 "SELinux is disabled via kernel command line or bootloader configuration"
elif grep -Prs '^\h*([^#\n\r]+\h+)?kernelopts=([^#\n\r]+\h+)?(selinux|enforcing)=0\b' /boot/grub2 /boot/efi 2>/dev/null; then
    sec_audit_report_fail 45 "SELinux is disabled via kernel command line or bootloader configuration"
else
    sec_audit_report_pass 45 "SELinux is not disabled in bootloader configuration"
fi

fi
if secaudit_rule_enabled 46; then
if grep -Psi '^\h*SELINUXTYPE\h*=\h*(targeted|mls)\b' /etc/selinux/config 2>/dev/null; then
    sec_audit_report_pass 46 "SELinux policy is configured"
else
    sec_audit_report_fail 46 "SELinux policy type is not set to targeted or mls in /etc/selinux/config"
fi

fi
if secaudit_rule_enabled 47; then
if grep -Pi '^\h*SELINUX=(enforcing|permissive)\b' /etc/selinux/config 2>/dev/null; then
    if getenforce | grep -qE 'Enforcing|Permissive'; then
        sec_audit_report_pass 47 "the SELinux mode is not disabled"
    else
        sec_audit_report_fail 47 "SELinux is disabled in /etc/selinux/config or getenforce reports Disabled"
    fi
else
    sec_audit_report_fail 47 "SELinux is disabled in /etc/selinux/config or getenforce reports Disabled"
fi

fi
if secaudit_rule_enabled 48; then
if grep -Pi '^\h*SELINUX=enforcing\b' /etc/selinux/config 2>/dev/null; then
    if getenforce | grep -q Enforcing; then
        sec_audit_report_pass 48 "the SELinux mode is enforcing"
    else
        sec_audit_report_fail 48 "SELinux is not enforcing in /etc/selinux/config or getenforce is not Enforcing"
    fi
else
    sec_audit_report_fail 48 "SELinux is not enforcing in /etc/selinux/config or getenforce is not Enforcing"
fi

fi
if secaudit_rule_enabled 49; then
if ps -eZ 2>/dev/null | grep -q unconfined_service_t; then
    sec_audit_report_fail 49 "Processes running with unconfined_service_t were detected"
else
    sec_audit_report_pass 49 "no unconfined services exist"
fi

fi
if secaudit_rule_enabled 50; then
if rpm -q mcstrans &>/dev/null; then
    sec_audit_report_fail 50 "package mcstrans is installed"
else
    sec_audit_report_pass 50 "package mcstrans is not installed"
fi

fi
if secaudit_rule_enabled 51; then
if rpm -q setroubleshoot &>/dev/null; then
    sec_audit_report_fail 51 "SETroubleshoot package is installed"
else
    sec_audit_report_pass 51 "SETroubleshoot is not installed"
fi

fi
if secaudit_rule_enabled 52; then
if grep "^\s*set superusers" /boot/grub2/grub.cfg 2>/dev/null | grep -q "set superusers"; then
    if grep "^\s*password" /boot/grub2/grub.cfg 2>/dev/null | grep -q "password_pbkdf2"; then
        sec_audit_report_pass 52 "bootloader password is set"
    else
        sec_audit_report_fail 52 "GRUB bootloader superuser/password_pbkdf2 is not configured as required in grub.cfg"
    fi
else
    sec_audit_report_fail 52 "GRUB bootloader superuser/password_pbkdf2 is not configured as required in grub.cfg"
fi

fi
if secaudit_rule_enabled 53; then
if stat -Lc '%a' /boot/grub2/grub.cfg 2>/dev/null | grep -q '^[0-6]00$'; then
    if stat -Lc '%U:%G' /boot/grub2/grub.cfg 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 53 "access to bootloader config is configured"
    else
        sec_audit_report_fail 53 "/boot/grub2/grub.cfg owner/mode is not root:root with restrictive permissions (600–root)"
    fi
else
    sec_audit_report_fail 53 "/boot/grub2/grub.cfg owner/mode is not root:root with restrictive permissions (600–root)"
fi

fi
if secaudit_rule_enabled 54; then
if systemctl show -p ExecStart --value rescue.service 2>/dev/null | grep -q sulogin; then
    sec_audit_report_pass 54 "rescue mode requires authentication (sulogin)"
else
    sec_audit_report_fail 54 "rescue.service does not invoke sulogin; rescue mode boots without authentication"
fi

fi
if secaudit_rule_enabled 55; then
if systemctl show -p ExecStart --value emergency.service 2>/dev/null | grep -q sulogin; then
    sec_audit_report_pass 55 "emergency mode requires authentication (sulogin)"
else
    sec_audit_report_fail 55 "emergency.service does not invoke sulogin; emergency mode boots without authentication"
fi

fi
if secaudit_rule_enabled 56; then
if sec_audit_have_bin grubby && grubby --info=ALL 2>/dev/null | grep -E '^\s*args=' | grep -q 'systemd\.confirm_spawn'; then
    sec_audit_report_fail 56 "systemd.confirm_spawn is present on a boot entry (interactive boot allowed)"
elif grep -Pqs 'systemd\.confirm_spawn' /etc/default/grub /etc/kernel/cmdline 2>/dev/null; then
    sec_audit_report_fail 56 "systemd.confirm_spawn is configured in the bootloader defaults"
else
    sec_audit_report_pass 56 "systemd.confirm_spawn is not set on any boot entry"
fi

fi
if secaudit_rule_enabled 57; then
_req52_r=$(sec_audit_sysctl_key_runtime fs.protected_hardlinks)
if sec_audit_sysctl_runtime_equals fs.protected_hardlinks 1; then
    sec_audit_report_pass 57 "fs.protected_hardlinks=1 in kernel$(sec_audit_sysctl_runtime_disk_hint fs.protected_hardlinks 1)"
else
    sec_audit_report_fail 57 "kernel fs.protected_hardlinks is '${_req52_r:-<unreadable>}', expected 1$(sec_audit_sysctl_runtime_disk_hint fs.protected_hardlinks 1)"
fi

fi
if secaudit_rule_enabled 58; then
_req53_r=$(sec_audit_sysctl_key_runtime fs.protected_symlinks)
if sec_audit_sysctl_runtime_equals fs.protected_symlinks 1; then
    sec_audit_report_pass 58 "fs.protected_symlinks=1 in kernel$(sec_audit_sysctl_runtime_disk_hint fs.protected_symlinks 1)"
else
    sec_audit_report_fail 58 "kernel fs.protected_symlinks is '${_req53_r:-<unreadable>}', expected 1$(sec_audit_sysctl_runtime_disk_hint fs.protected_symlinks 1)"
fi

fi
if secaudit_rule_enabled 59; then
_req54_r=$(sec_audit_sysctl_key_runtime fs.suid_dumpable)
if sec_audit_sysctl_runtime_equals fs.suid_dumpable 0; then
    sec_audit_report_pass 59 "fs.suid_dumpable=0 in kernel$(sec_audit_sysctl_runtime_disk_hint fs.suid_dumpable 0)"
else
    sec_audit_report_fail 59 "kernel fs.suid_dumpable is '${_req54_r:-<unreadable>}', expected 0$(sec_audit_sysctl_runtime_disk_hint fs.suid_dumpable 0)"
fi

fi
if secaudit_rule_enabled 60; then
_req55_r=$(sec_audit_sysctl_key_runtime kernel.dmesg_restrict)
if sec_audit_sysctl_runtime_equals kernel.dmesg_restrict 1; then
    sec_audit_report_pass 60 "kernel.dmesg_restrict=1 in kernel$(sec_audit_sysctl_runtime_disk_hint kernel.dmesg_restrict 1)"
else
    sec_audit_report_fail 60 "kernel.dmesg_restrict is '${_req55_r:-<unreadable>}', expected 1$(sec_audit_sysctl_runtime_disk_hint kernel.dmesg_restrict 1)"
fi

fi
if secaudit_rule_enabled 61; then
_req56_r=$(sec_audit_sysctl_key_runtime kernel.kptr_restrict)
if sec_audit_sysctl_runtime_matches_regex kernel.kptr_restrict '^[12]$'; then
    sec_audit_report_pass 61 "kernel.kptr_restrict is 1 or 2 in kernel$(sec_audit_sysctl_runtime_disk_hint kernel.kptr_restrict 2)"
else
    sec_audit_report_fail 61 "kernel.kptr_restrict is '${_req56_r:-<unreadable>}', expected 1 or 2$(sec_audit_sysctl_runtime_disk_hint kernel.kptr_restrict 2)"
fi

fi
if secaudit_rule_enabled 62; then
_req58_r=$(sec_audit_sysctl_key_runtime kernel.randomize_va_space)
if sec_audit_sysctl_runtime_equals kernel.randomize_va_space 2; then
    sec_audit_report_pass 62 "kernel.randomize_va_space=2 in kernel$(sec_audit_sysctl_runtime_disk_hint kernel.randomize_va_space 2)"
else
    sec_audit_report_fail 62 "kernel.randomize_va_space is '${_req58_r:-<unreadable>}', expected 2$(sec_audit_sysctl_runtime_disk_hint kernel.randomize_va_space 2)"
fi

fi
if secaudit_rule_enabled 63; then
_req57_r=$(sec_audit_sysctl_key_runtime kernel.yama.ptrace_scope)
if sec_audit_sysctl_runtime_matches_regex kernel.yama.ptrace_scope '^[123]$'; then
    sec_audit_report_pass 63 "kernel.yama.ptrace_scope is 1–3 in kernel$(sec_audit_sysctl_runtime_disk_hint kernel.yama.ptrace_scope 3)"
else
    sec_audit_report_fail 63 "kernel.yama.ptrace_scope is '${_req57_r:-<unreadable>}', expected 1, 2, or 3$(sec_audit_sysctl_runtime_disk_hint kernel.yama.ptrace_scope 3)"
fi

fi
if secaudit_rule_enabled 64; then
if sec_audit_limits_core_zero_and_systemd_ok; then
    sec_audit_report_pass 64 "limits * hard core 0 present and systemd DefaultLimitCORE does not allow unlimited core dumps"
elif grep -Psi '^\*\s+hard\s+core\s+0\b' /etc/security/limits.conf $(ls -d /etc/security/limits.d/* 2>/dev/null) /dev/null 2>/dev/null; then
    sec_audit_report_fail 64 "limits.conf sets hard core 0 but systemd DefaultLimitCORE contradicts (check system.conf / user.conf drop-ins)"
else
    sec_audit_report_fail 64 "core file size limits are not configured (limits * hard core 0 not found)"
fi

fi
if secaudit_rule_enabled 65; then
_req59_cat=$(systemd-analyze cat-config systemd/coredump.conf 2>/dev/null)
_req59_corep=$(sec_audit_sysctl_key_runtime kernel.core_pattern)
if builtin printf '%s\n' "$_req59_cat" | grep -Pq '^\h*ProcessSizeMax=\h*0\b'; then
    if [[ "$_req59_corep" == *systemd-coredump* ]] || [[ "$_req59_corep" == *coredump* ]]; then
        sec_audit_report_pass 65 "merged coredump.conf sets ProcessSizeMax=0; kernel.core_pattern uses systemd-coredump"
    else
        sec_audit_report_pass 65 "merged coredump.conf sets ProcessSizeMax=0 (kernel.core_pattern='${_req59_corep:-?}' may omit systemd-coredump text)"
    fi
else
    sec_audit_report_fail 65 "merged systemd/coredump.conf does not set ProcessSizeMax=0"
fi

fi
if secaudit_rule_enabled 66; then
_req60_cat=$(systemd-analyze cat-config systemd/coredump.conf 2>/dev/null)
if builtin printf '%s\n' "$_req60_cat" | grep -Pq '^\h*Storage=\h*none\b'; then
    sec_audit_report_pass 66 "merged systemd/coredump.conf sets Storage=none"
else
    sec_audit_report_fail 66 "merged systemd/coredump.conf does not set Storage=none"
fi

fi
if secaudit_rule_enabled 67; then
if grep -Pi '^\h*LEGACY\b' /etc/crypto-policies/config 2>/dev/null; then
    sec_audit_report_fail 67 "System-wide crypto policy is LEGACY in /etc/crypto-policies/config"
else
    sec_audit_report_pass 67 "system wide crypto policy is not set to legacy"
fi

fi
if secaudit_rule_enabled 68; then
FAIL_68=0
if awk -F= '($1~/(hash|sign)/ && $2~/SHA1/ && $2!~/^\s*\- \s*([^#\n\r]+)?SHA1/){found=1; exit} END{exit !found}' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null; then
	FAIL_68=1
fi
if ! grep -qPsi '^\h*sha1_in_certs\h*=\h*0\b' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null; then
	FAIL_68=1
fi
if [ "$FAIL_68" -eq 0 ]; then
	sec_audit_report_pass 68 "system wide crypto policy disables sha1 hash and signature support"
else
	sec_audit_report_fail 68 "SHA1 hash/signature support or sha1_in_certs is not disabled in CURRENT.pol"
fi

fi
if secaudit_rule_enabled 69; then
if grep -Pi '(^\h*mac\h*=\h*([^#\n\r]+)?-128|hmac-sha1)' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null; then
    sec_audit_report_fail 69 "Weak MAC algorithms still present in /etc/crypto-policies/state/CURRENT.pol"
else
    sec_audit_report_pass 69 "system wide crypto policy macs are configured"
fi

fi
if secaudit_rule_enabled 70; then
if grep -Piq '^\h*cipher@(lib|open)ssh(-server|-client)?\h*=\h*([^#\n\r]+)?-CBC\b' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null; then
    sec_audit_report_pass 70 "system wide crypto policy disables cbc for ssh"
elif grep -Piq '^\h*cipher\h*=\h*([^#\n\r]+)?-CBC\b' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null; then
    sec_audit_report_pass 70 "system wide crypto policy disables cbc for ssh"
else
    sec_audit_report_fail 70 "CBC ciphers for SSH are still allowed by crypto policy (CURRENT.pol)"
fi

fi
if secaudit_rule_enabled 71; then
if grep -Piq 'chacha20-poly1305' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null; then
	sec_audit_report_fail 71 "chacha20-poly1305 still present in CURRENT.pol"
else
	sec_audit_report_pass 71 "chacha20-poly1305 not present in crypto policy"
fi

fi
if secaudit_rule_enabled 72; then
if grep -qPiq '^\h*etm(@libssh|@openssh-client|@openssh-server)?\h*=\h*DISABLE_ETM\b' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null || \
	grep -qPiq '^\h*etm\h*=\h*DISABLE_ETM\b' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null; then
	sec_audit_report_pass 72 "EtM is disabled for ssh in crypto policy"
else
	sec_audit_report_fail 72 "EtM is not disabled for ssh in CURRENT.pol"
fi

fi
if secaudit_rule_enabled 73; then
if [ ! -e /usr/share/crypto-policies/policies/modules/PQ.pmod ]; then
    sec_audit_report_pass 73 "PQ subpolicy is not available on this release (recommendation not applicable)"
elif ! sec_audit_have_bin update-crypto-policies; then
    sec_audit_report_fail 73 "update-crypto-policies unavailable; cannot verify PQ subpolicy"
else
    _pol=$(update-crypto-policies --show 2>/dev/null)
    if printf '%s' "$_pol" | grep -qE '(^|:)PQ(:|$)'; then
        sec_audit_report_pass 73 "active crypto policy includes the PQ subpolicy (${_pol})"
    else
        sec_audit_report_fail 73 "active crypto policy does not include the PQ subpolicy (${_pol:-unknown})"
    fi
fi

fi
if secaudit_rule_enabled 74; then
if grep -Psi "(\\\v|\\\r|\\\m|\\\s|\b$(grep ^ID= /etc/os-release 2>/dev/null | cut -d= -f2 | sed -e 's/"//g')\b)" /etc/motd 2>/dev/null; then
    sec_audit_report_fail 74 "/etc/motd is missing or does not contain required banner content"
else
    sec_audit_report_pass 74 "/etc/motd is configured"
fi

fi
if secaudit_rule_enabled 75; then
if grep -Psi "(\\\v|\\\r|\\\m|\\\s|\b$(grep ^ID= /etc/os-release 2>/dev/null | cut -d= -f2 | sed -e 's/"//g')\b)" /etc/issue 2>/dev/null; then
    sec_audit_report_fail 75 "/etc/issue is missing or does not contain required local login banner"
else
    sec_audit_report_pass 75 "/etc/issue is configured"
fi

fi
if secaudit_rule_enabled 76; then
if [ -f /etc/issue.net ]; then
    if grep -Psi "(\\\v|\\\r|\\\m|\\\s|\b$(grep ^ID= /etc/os-release 2>/dev/null | cut -d= -f2 | sed -e 's/"//g')\b)" /etc/issue.net 2>/dev/null; then
        sec_audit_report_fail 76 "/etc/issue.net is missing or does not contain required remote login banner"
    else
        sec_audit_report_pass 76 "/etc/issue.net is configured"
    fi
else
    sec_audit_report_pass 76 "/etc/issue.net is configured"
fi

fi
if secaudit_rule_enabled 77; then
if [ -e /etc/motd ]; then
    if stat -Lc '%a' /etc/motd 2>/dev/null | grep -qE '^[0-6]44$'; then
        if stat -Lc '%U:%G' /etc/motd 2>/dev/null | grep -q '^root:root$'; then
            sec_audit_report_pass 77 "access to /etc/motd is configured"
        else
            sec_audit_report_fail 77 "File /etc/motd permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 77 "File /etc/motd permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 77 "access to /etc/motd is configured (file not found)"
fi

fi
if secaudit_rule_enabled 78; then
if stat -Lc '%a' /etc/issue 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' /etc/issue 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 78 "access to /etc/issue is configured"
    else
        sec_audit_report_fail 78 "File /etc/issue permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 78 "File /etc/issue permissions or ownership not correct"
fi

fi
if secaudit_rule_enabled 79; then
if [ -e /etc/issue.net ]; then
    if stat -Lc '%a' /etc/issue.net 2>/dev/null | grep -qE '^[0-6]44$'; then
        if stat -Lc '%U:%G' /etc/issue.net 2>/dev/null | grep -q '^root:root$'; then
            sec_audit_report_pass 79 "access to /etc/issue.net is configured"
        else
            sec_audit_report_fail 79 "File /etc/issue.net permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 79 "File /etc/issue.net permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 79 "access to /etc/issue.net is configured (file not found)"
fi

fi
if secaudit_rule_enabled 80; then
GDM_CONFIG="/etc/gdm/custom.conf"
if [ -f "$GDM_CONFIG" ]; then
    if grep -Pzo "\[org/gnome/login-screen\][^\[]*banner-message-enable=true" "$GDM_CONFIG" 2>/dev/null | grep -q .; then
        sec_audit_report_pass 80 "GDM login banner is configured"
    else
        sec_audit_report_fail 80 "GDM login banner is not configured in $GDM_CONFIG"
    fi
else
    sec_audit_report_fail 80 "GDM configuration file not found ($GDM_CONFIG)"
fi

fi
if secaudit_rule_enabled 81; then
if rpm -q gdm &>/dev/null && grep -q "DisableUserList=true" /etc/gdm/custom.conf 2>/dev/null; then
    sec_audit_report_pass 81 "GDM disable-user-list is configured"
elif ! rpm -q gdm &>/dev/null; then
    sec_audit_report_pass 81 "GDM is not installed"
else
    sec_audit_report_fail 81 "GDM disable-user-list is not configured"
fi

fi
if secaudit_rule_enabled 82; then
if grep -q "idle-delay=uint32" $(ls -d /etc/dconf/db/gdm.d/* 2>/dev/null) /dev/null 2>/dev/null || \
   grep -q "lock-delay=uint32" $(ls -d /etc/dconf/db/gdm.d/* 2>/dev/null) /dev/null 2>/dev/null; then
    sec_audit_report_pass 82 "GDM screen lock is configured"
else
    sec_audit_report_fail 82 "GDM screen lock is not configured"
fi

fi
if secaudit_rule_enabled 83; then
if grep -q "automount=false" $(ls -d /etc/dconf/db/gdm.d/* 2>/dev/null) /dev/null 2>/dev/null || \
   grep -q "automount-open=false" $(ls -d /etc/dconf/db/gdm.d/* 2>/dev/null) /dev/null 2>/dev/null; then
    sec_audit_report_pass 83 "GDM automount is configured"
else
    sec_audit_report_fail 83 "GDM automount is not configured"
fi

fi
if secaudit_rule_enabled 84; then
if grep -q "autorun-never=true" $(ls -d /etc/dconf/db/gdm.d/* 2>/dev/null) /dev/null 2>/dev/null; then
    sec_audit_report_pass 84 "GDM autorun-never is configured"
else
    sec_audit_report_fail 84 "GDM autorun-never is not configured"
fi

fi
if secaudit_rule_enabled 85; then
if ! sec_audit_gdm_package_installed; then
	sec_audit_report_pass 85 "GDM is not installed"
else
	if grep -Pqi '^\h*Enable\h*=\h*false' /etc/gdm/custom.conf 2>/dev/null || ! grep -qi '^\[xdmcp\]' /etc/gdm/custom.conf 2>/dev/null; then
		sec_audit_report_pass 85 "XDMCP is not enabled in GDM"
	else
		sec_audit_report_fail 85 "XDMCP may be enabled in /etc/gdm/custom.conf"
	fi
fi

fi
if secaudit_rule_enabled 86; then
if ! rpm -q gdm &>/dev/null; then
    sec_audit_report_pass 86 "GDM is not installed (Wayland recommendation not applicable)"
elif grep -Psi -- '^\h*WaylandEnable\h*=\h*false\b' /etc/gdm/custom.conf /etc/gdm3/custom.conf 2>/dev/null; then
    sec_audit_report_fail 86 "GDM is configured with WaylandEnable=false (Wayland disabled)"
else
    sec_audit_report_pass 86 "GDM is not configured to disable Wayland"
fi

fi
}

sec_audit_run_services() {
if secaudit_rule_enabled 87; then
if rpm -q autofs &>/dev/null; then
    if systemctl is-enabled autofs.service 2>/dev/null | grep -q 'enabled'; then
        sec_audit_report_fail 87 "autofs services are installed and enabled or actively running"
    elif systemctl is-active autofs.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_fail 87 "autofs services are installed and enabled or actively running"
    else
        sec_audit_report_pass 87 "autofs services are not in use"
    fi
else
    sec_audit_report_pass 87 "autofs services are not in use"
fi

fi
if secaudit_rule_enabled 88; then
if rpm -q avahi &>/dev/null; then
    if systemctl is-enabled avahi-daemon.socket avahi-daemon.service 2>/dev/null | grep -q 'enabled'; then
        sec_audit_report_fail 88 "avahi daemon services are installed and enabled or actively running"
    elif systemctl is-active avahi-daemon.socket avahi-daemon.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_fail 88 "avahi daemon services are installed and enabled or actively running"
    else
        sec_audit_report_pass 88 "avahi daemon services are not in use"
    fi
else
    sec_audit_report_pass 88 "avahi daemon services are not in use"
fi

fi
if secaudit_rule_enabled 89; then
if rpm -q cockpit-ws &>/dev/null; then
    if systemctl is-enabled cockpit.socket cockpit.service 2>/dev/null | grep -q 'enabled'; then
        sec_audit_report_fail 89 "cockpit web services are installed and enabled or actively running"
    elif systemctl is-active cockpit.socket cockpit.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_fail 89 "cockpit web services are installed and enabled or actively running"
    else
        sec_audit_report_pass 89 "cockpit web services are not in use"
    fi
else
    sec_audit_report_pass 89 "cockpit web services are not in use"
fi

fi
if secaudit_rule_enabled 90; then
if rpm -q dhcp-server &>/dev/null; then
    if systemctl is-enabled dhcpd.service dhcpd6.service 2>/dev/null | grep -q 'enabled'; then
        sec_audit_report_fail 90 "dhcp server services are installed and enabled or actively running"
    elif systemctl is-active dhcpd.service dhcpd6.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_fail 90 "dhcp server services are installed and enabled or actively running"
    else
        sec_audit_report_pass 90 "dhcp server services are not in use"
    fi
else
    sec_audit_report_pass 90 "dhcp server services are not in use"
fi

fi
if secaudit_rule_enabled 91; then
if rpm -q bind &>/dev/null; then
    if systemctl is-enabled named.service 2>/dev/null | grep -q 'enabled'; then
        sec_audit_report_fail 91 "dns server services are installed and enabled or actively running"
    elif systemctl is-active named.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_fail 91 "dns server services are installed and enabled or actively running"
    else
        sec_audit_report_pass 91 "dns server services are not in use"
    fi
else
    sec_audit_report_pass 91 "dns server services are not in use"
fi

fi
if secaudit_rule_enabled 92; then
if rpm -q dnsmasq &>/dev/null; then
    if systemctl is-enabled dnsmasq.service 2>/dev/null | grep -q 'enabled'; then
        sec_audit_report_fail 92 "dnsmasq services are installed and enabled or actively running"
    elif systemctl is-active dnsmasq.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_fail 92 "dnsmasq services are installed and enabled or actively running"
    else
        sec_audit_report_pass 92 "dnsmasq services are not in use"
    fi
else
    sec_audit_report_pass 92 "dnsmasq services are not in use"
fi

fi
if secaudit_rule_enabled 93; then
if rpm -q samba &>/dev/null; then
    if systemctl is-enabled smb.service 2>/dev/null | grep -q 'enabled'; then
        sec_audit_report_fail 93 "samba file server services are installed and enabled or actively running"
    elif systemctl is-active smb.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_fail 93 "samba file server services are installed and enabled or actively running"
    else
        sec_audit_report_pass 93 "samba file server services are not in use"
    fi
else
    sec_audit_report_pass 93 "samba file server services are not in use"
fi

fi
if secaudit_rule_enabled 94; then
if rpm -q vsftpd &>/dev/null; then
    if systemctl is-enabled vsftpd.service 2>/dev/null | grep -q 'enabled'; then
        sec_audit_report_fail 94 "ftp server services are installed and enabled or actively running"
    elif systemctl is-active vsftpd.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_fail 94 "ftp server services are installed and enabled or actively running"
    else
        sec_audit_report_pass 94 "ftp server services are not in use"
    fi
else
    sec_audit_report_pass 94 "ftp server services are not in use"
fi

fi
if secaudit_rule_enabled 95; then
if sec_audit_pkg_any_installed dovecot cyrus-imapd; then
    if systemctl is-enabled dovecot.socket dovecot.service cyrus-imapd.service 2>/dev/null | grep -q 'enabled'; then
        sec_audit_report_fail 95 "message access server services are installed and enabled or actively running"
    elif systemctl is-active dovecot.socket dovecot.service cyrus-imapd.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_fail 95 "message access server services are installed and enabled or actively running"
    else
        sec_audit_report_pass 95 "message access server services are not in use"
    fi
else
    sec_audit_report_pass 95 "message access server services are not in use"
fi

fi
if secaudit_rule_enabled 96; then
if rpm -q nfs-utils &>/dev/null; then
    if systemctl is-enabled nfs-server.service 2>/dev/null | grep -q 'enabled'; then
        sec_audit_report_fail 96 "network file system services are installed and enabled or actively running"
    elif systemctl is-active nfs-server.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_fail 96 "network file system services are installed and enabled or actively running"
    else
        sec_audit_report_pass 96 "network file system services are not in use"
    fi
else
    sec_audit_report_pass 96 "network file system services are not in use"
fi

fi
if secaudit_rule_enabled 97; then
if rpm -q cups &>/dev/null; then
    if systemctl is-enabled cups.socket cups.service 2>/dev/null | grep -q 'enabled'; then
        sec_audit_report_fail 97 "print server services are installed and enabled or actively running"
    elif systemctl is-active cups.socket cups.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_fail 97 "print server services are installed and enabled or actively running"
    else
        sec_audit_report_pass 97 "print server services are not in use"
    fi
else
    sec_audit_report_pass 97 "print server services are not in use"
fi

fi
if secaudit_rule_enabled 98; then
if rpm -q rpcbind &>/dev/null; then
    if systemctl is-enabled rpcbind.socket rpcbind.service 2>/dev/null | grep -q 'enabled'; then
        sec_audit_report_fail 98 "rpcbind services are installed and enabled or actively running"
    elif systemctl is-active rpcbind.socket rpcbind.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_fail 98 "rpcbind services are installed and enabled or actively running"
    else
        sec_audit_report_pass 98 "rpcbind services are not in use"
    fi
else
    sec_audit_report_pass 98 "rpcbind services are not in use"
fi

fi
if secaudit_rule_enabled 99; then
if rpm -q rsync-daemon &>/dev/null; then
    if systemctl is-enabled rsyncd.socket rsyncd.service 2>/dev/null | grep -q 'enabled'; then
        sec_audit_report_fail 99 "rsync services are installed and enabled or actively running"
    elif systemctl is-active rsyncd.socket rsyncd.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_fail 99 "rsync services are installed and enabled or actively running"
    else
        sec_audit_report_pass 99 "rsync services are not in use"
    fi
else
    sec_audit_report_pass 99 "rsync services are not in use"
fi

fi
if secaudit_rule_enabled 100; then
if rpm -q net-snmp &>/dev/null; then
    if systemctl is-enabled snmpd.service 2>/dev/null | grep -q 'enabled'; then
        sec_audit_report_fail 100 "snmp services are installed and enabled or actively running"
    elif systemctl is-active snmpd.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_fail 100 "snmp services are installed and enabled or actively running"
    else
        sec_audit_report_pass 100 "snmp services are not in use"
    fi
else
    sec_audit_report_pass 100 "snmp services are not in use"
fi

fi
if secaudit_rule_enabled 101; then
if rpm -q telnet-server &>/dev/null; then
    if systemctl is-enabled telnet.socket 2>/dev/null | grep -q 'enabled'; then
        sec_audit_report_fail 101 "telnet server services are installed and enabled or actively running"
    elif systemctl is-active telnet.socket 2>/dev/null | grep -q '^active'; then
        sec_audit_report_fail 101 "telnet server services are installed and enabled or actively running"
    else
        sec_audit_report_pass 101 "telnet server services are not in use"
    fi
else
    sec_audit_report_pass 101 "telnet server services are not in use"
fi

fi
if secaudit_rule_enabled 102; then
if rpm -q tftp-server &>/dev/null; then
    if systemctl is-enabled tftp.socket tftp.service 2>/dev/null | grep -q 'enabled'; then
        sec_audit_report_fail 102 "tftp server services are installed and enabled or actively running"
    elif systemctl is-active tftp.socket tftp.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_fail 102 "tftp server services are installed and enabled or actively running"
    else
        sec_audit_report_pass 102 "tftp server services are not in use"
    fi
else
    sec_audit_report_pass 102 "tftp server services are not in use"
fi

fi
if secaudit_rule_enabled 103; then
if rpm -q squid &>/dev/null; then
    if systemctl is-enabled squid.service 2>/dev/null | grep -q 'enabled'; then
        sec_audit_report_fail 103 "web proxy server services are installed and enabled or actively running"
    elif systemctl is-active squid.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_fail 103 "web proxy server services are installed and enabled or actively running"
    else
        sec_audit_report_pass 103 "web proxy server services are not in use"
    fi
else
    sec_audit_report_pass 103 "web proxy server services are not in use"
fi

fi
if secaudit_rule_enabled 104; then
if sec_audit_pkg_any_installed httpd nginx; then
    if systemctl is-enabled httpd.service nginx.service 2>/dev/null | grep -q 'enabled'; then
        sec_audit_report_fail 104 "web server services are installed and enabled or actively running"
    elif systemctl is-active httpd.service nginx.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_fail 104 "web server services are installed and enabled or actively running"
    else
        sec_audit_report_pass 104 "web server services are not in use"
    fi
else
    sec_audit_report_pass 104 "web server services are not in use"
fi

fi
if secaudit_rule_enabled 105; then
if rpm -q postfix &>/dev/null; then
	if postconf -n inet_interfaces 2>/dev/null | grep -qE '^(loopback-only|localhost)$'; then
		sec_audit_report_pass 105 "postfix inet_interfaces limited to local-only"
	else
		_pi=$(postconf -n inet_interfaces 2>/dev/null)
		sec_audit_report_fail 105 "postfix not local-only (inet_interfaces=${_pi:-unset})"
	fi
elif rpm -q sendmail &>/dev/null; then
	if grep -qiE '^O DaemonPortOptions=.*Addr=127\.0\.0\.1' /etc/mail/sendmail.cf 2>/dev/null; then
		sec_audit_report_pass 105 "sendmail listens on loopback only"
	else
		sec_audit_report_fail 105 "sendmail not configured for local-only mode"
	fi
else
	sec_audit_report_pass 105 "no MTA package installed (postfix/sendmail)"
fi

fi
if secaudit_rule_enabled 106; then
_gui_group=""
if sec_audit_have_bin dnf; then
    _gui_group=$(dnf grouplist 2>/dev/null | sed -n '/Installed Environment Groups:/,/Installed Groups:/p' | grep -i 'Server with GUI' || true)
fi
if [ -n "$_gui_group" ]; then
    sec_audit_report_fail 106 "the 'Server with GUI' environment group is installed"
elif [ "$(systemctl get-default 2>/dev/null)" = "graphical.target" ]; then
    sec_audit_report_fail 106 "default target is graphical.target (system boots into a GUI)"
else
    sec_audit_report_pass 106 "no GUI environment group installed and default target is not graphical"
fi

fi
if secaudit_rule_enabled 107; then
if rpm -q xorg-x11-server-Xwayland &>/dev/null; then
    sec_audit_report_fail 107 "X window server services are installed and enabled or actively running"
else
    sec_audit_report_pass 107 "X window server services are not in use"
fi

fi
if secaudit_rule_enabled 108; then
if ! rpm -q xorg-x11-server-Xwayland &>/dev/null; then
    sec_audit_report_pass 108 "xorg-x11-server-Xwayland package is not installed"
elif sec_audit_have_bin dnf && [ -n "$(dnf repoquery --installed --whatrequires xorg-x11-server-Xwayland 2>/dev/null | head -n1)" ]; then
    sec_audit_report_pass 108 "xorg-x11-server-Xwayland is a required dependency of an installed package (record in SSP)"
else
    sec_audit_report_fail 108 "xorg-x11-server-Xwayland is installed and not a required dependency"
fi

fi
if secaudit_rule_enabled 109; then
if ! sec_audit_have_bin ss; then
	sec_audit_report_fail 109 "ss unavailable; cannot enumerate listening services"
else
	_listen=$(ss -Htanl 2>/dev/null | awk '{print $4}' | grep -E '0\.0\.0\.0:|\[::\]:|:::|\*:' | sort -u | tr '\n' ' ')
	if [[ -z "${_listen// /}" ]]; then
		sec_audit_report_pass 109 "no services listening on all interfaces (review loopback-only listeners)"
	else
		sec_audit_report_fail 109 "services listening on all interfaces:${_listen}"
	fi
fi

fi
if secaudit_rule_enabled 110; then
if rpm -q ftp &>/dev/null; then
    sec_audit_report_fail 110 "ftp client package is installed"
else
    sec_audit_report_pass 110 "ftp client is not installed"
fi

fi
if secaudit_rule_enabled 111; then
if rpm -q openldap-clients &>/dev/null; then
    sec_audit_report_fail 111 "ldap client package is installed"
else
    sec_audit_report_pass 111 "ldap client is not installed"
fi

fi
if secaudit_rule_enabled 112; then
if rpm -q telnet &>/dev/null; then
    sec_audit_report_fail 112 "telnet client package is installed"
else
    sec_audit_report_pass 112 "telnet client is not installed"
fi

fi
if secaudit_rule_enabled 113; then
if rpm -q tftp &>/dev/null; then
    sec_audit_report_fail 113 "tftp client package is installed"
else
    sec_audit_report_pass 113 "tftp client is not installed"
fi

fi
if secaudit_rule_enabled 114; then
if rpm -q chrony &>/dev/null; then
    if systemctl is-active chronyd.service &>/dev/null; then
        sec_audit_report_pass 114 "chrony is installed and chronyd.service is active"
    else
        sec_audit_report_fail 114 "chrony is installed but chronyd.service is not active"
    fi
else
    sec_audit_report_fail 114 "time synchronization is not in use (chrony not installed)"
fi

fi
if secaudit_rule_enabled 115; then
_ch101_src=$(grep -Eh "^(server|pool)" /etc/chrony.conf $(ls -d /etc/chrony.d/*.conf 2>/dev/null) /dev/null 2>/dev/null | grep -cve '^[[:space:]]*$' || true)
if grep -Eh "^(server|pool)" /etc/chrony.conf $(ls -d /etc/chrony.d/*.conf 2>/dev/null) /dev/null 2>/dev/null | grep -qE "server|pool"; then
    _ch101_track=""
    if sec_audit_have_bin chronyc && systemctl is-active chronyd.service &>/dev/null; then
        if chronyc -n tracking 2>/dev/null | grep -qiE '^(reference time|stratum|leap status)'; then
            _ch101_track="; chronyc tracking responds"
        fi
        if chronyc -n sources 2>/dev/null | grep -qE '^\^[*\#]'; then
            _ch101_track="${_ch101_track}; chronyc sources lists a selected source"
        fi
    fi
    sec_audit_report_pass 115 "chrony has ${_ch101_src:-0} server/pool line(s) in conf or chrony.d${_ch101_track}"
else
    sec_audit_report_fail 115 "chrony is not configured with time sources (no server/pool in chrony.conf or chrony.d)"
fi

fi
if secaudit_rule_enabled 116; then
if grep -Psi -- '^\h*OPTIONS=\"?\h*([^#\n\r]+\h+)?-u\h+root\b' /etc/sysconfig/chronyd 2>/dev/null; then
    sec_audit_report_fail 116 "chronyd is configured to run as root (OPTIONS in /etc/sysconfig/chronyd)"
else
    sec_audit_report_pass 116 "chrony is not run as the root user"
fi

fi
if secaudit_rule_enabled 117; then
if systemctl is-enabled crond.service 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active crond.service 2>/dev/null | grep -q 'active'; then
        sec_audit_report_pass 117 "cron daemon is enabled and active"
    else
        sec_audit_report_fail 117 "crond service is not enabled or not active"
    fi
else
    sec_audit_report_fail 117 "crond service is not enabled or not active"
fi

fi
if secaudit_rule_enabled 118; then
if stat -Lc '%a' /etc/crontab 2>/dev/null | grep -q '^[0-6]00$'; then
    if stat -Lc '%U:%G' /etc/crontab 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 118 "access to /etc/crontab is configured"
    else
        sec_audit_report_fail 118 "File /etc/crontab permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 118 "File /etc/crontab permissions or ownership not correct"
fi

fi
if secaudit_rule_enabled 119; then
if stat -Lc '%a' /etc/cron.hourly 2>/dev/null | grep -q '^700$'; then
    if stat -Lc '%U:%G' /etc/cron.hourly 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 119 "access to /etc/cron.hourly is configured"
    else
        sec_audit_report_fail 119 "File /etc/cron.hourly permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 119 "File /etc/cron.hourly permissions or ownership not correct"
fi

fi
if secaudit_rule_enabled 120; then
if stat -Lc '%a' /etc/cron.daily 2>/dev/null | grep -q '^700$'; then
    if stat -Lc '%U:%G' /etc/cron.daily 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 120 "access to /etc/cron.daily is configured"
    else
        sec_audit_report_fail 120 "File /etc/cron.daily permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 120 "File /etc/cron.daily permissions or ownership not correct"
fi

fi
if secaudit_rule_enabled 121; then
if stat -Lc '%a' /etc/cron.weekly 2>/dev/null | grep -q '^700$'; then
    if stat -Lc '%U:%G' /etc/cron.weekly 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 121 "access to /etc/cron.weekly is configured"
    else
        sec_audit_report_fail 121 "File /etc/cron.weekly permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 121 "File /etc/cron.weekly permissions or ownership not correct"
fi

fi
if secaudit_rule_enabled 122; then
if stat -Lc '%a' /etc/cron.monthly 2>/dev/null | grep -q '^700$'; then
    if stat -Lc '%U:%G' /etc/cron.monthly 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 122 "access to /etc/cron.monthly is configured"
    else
        sec_audit_report_fail 122 "File /etc/cron.monthly permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 122 "File /etc/cron.monthly permissions or ownership not correct"
fi

fi
if secaudit_rule_enabled 123; then
if stat -Lc '%a' /etc/cron.yearly 2>/dev/null | grep -q '^700$'; then
    if stat -Lc '%U:%G' /etc/cron.yearly 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 123 "access to /etc/cron.yearly is configured"
    else
        sec_audit_report_fail 123 "File /etc/cron.yearly permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 123 "File /etc/cron.yearly permissions or ownership not correct"
fi

fi
if secaudit_rule_enabled 124; then
if stat -Lc '%a' /etc/cron.d 2>/dev/null | grep -q '^700$'; then
    if stat -Lc '%U:%G' /etc/cron.d 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 124 "access to /etc/cron.d is configured"
    else
        sec_audit_report_fail 124 "File /etc/cron.d permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 124 "File /etc/cron.d permissions or ownership not correct"
fi

fi
if secaudit_rule_enabled 125; then
if [ -e /etc/cron.allow ]; then
    if stat -Lc '%a' /etc/cron.allow 2>/dev/null | grep -qE '^640$'; then
        if stat -Lc '%U' /etc/cron.allow 2>/dev/null | grep -q 'root'; then
            if stat -Lc '%G' /etc/cron.allow 2>/dev/null | grep -qE 'root|crontab'; then
                sec_audit_report_pass 125 "access to crontab is configured"
            else
                sec_audit_report_fail 125 "File crontab permissions or ownership not correct"
            fi
        else
            sec_audit_report_fail 125 "File crontab permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 125 "File crontab permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 125 "File crontab permissions or ownership not correct"
fi

fi
if secaudit_rule_enabled 126; then
if [ -e /etc/at.allow ]; then
    if stat -Lc '%a' /etc/at.allow 2>/dev/null | grep -qE '^640$'; then
        if stat -Lc '%U' /etc/at.allow 2>/dev/null | grep -q 'root'; then
            if stat -Lc '%G' /etc/at.allow 2>/dev/null | grep -qE 'daemon|root'; then
                sec_audit_report_pass 126 "access to at is configured"
            else
                sec_audit_report_fail 126 "File at permissions or ownership not correct"
            fi
        else
            sec_audit_report_fail 126 "File at permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 126 "File at permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 126 "File at permissions or ownership not correct"
fi

fi
}

sec_audit_run_network() {
if secaudit_rule_enabled 127; then
if [ -f /proc/sys/net/ipv6/conf/all/disable_ipv6 ]; then
    sec_audit_report_pass 127 "IPv6 status is identified"
else
    sec_audit_report_fail 127 "IPv6 status is not identified"
fi

fi
if secaudit_rule_enabled 128; then
if compgen -G "/sys/class/net/*/wireless" >/dev/null; then
    sec_audit_report_fail 128 "Wireless interfaces are present under /sys/class/net"
else
    sec_audit_report_pass 128 "wireless interfaces are not available"
fi

fi
if secaudit_rule_enabled 129; then
if rpm -q bluez &>/dev/null; then
    if systemctl is-enabled bluetooth.service 2>/dev/null | grep -q 'enabled'; then
        sec_audit_report_fail 129 "bluetooth services are installed and enabled or actively running"
    elif systemctl is-active bluetooth.service 2>/dev/null | grep -q '^active'; then
        sec_audit_report_fail 129 "bluetooth services are installed and enabled or actively running"
    else
        sec_audit_report_pass 129 "bluetooth services are not in use"
    fi
else
    sec_audit_report_pass 129 "bluetooth services are not in use"
fi

fi
if secaudit_rule_enabled 130; then
if sec_audit_kernel_mod_in_modules_load dccp; then
    sec_audit_report_fail 130 "dccp kernel module is listed in modules-load.d (auto-load at boot)"
elif ! sec_audit_low_impact_find --timeout=20 /usr/lib/modules/ /lib/modules/ -xdev -ignore_readdir_race -type f -name "dccp.ko*" 2>/dev/null | grep -q .; then
    sec_audit_report_pass 130 "dccp kernel module is not available"
else
    if ! lsmod | grep -q dccp && modprobe --showconfig | grep -Pq '^\h*(blacklist|install)\h+dccp\b'; then
        sec_audit_report_pass 130 "dccp kernel module is not available"
    else
        sec_audit_report_fail 130 "dccp kernel module is available, loaded, or not effectively blocked (modprobe blacklist/install)"
    fi
fi

fi
if secaudit_rule_enabled 131; then
if sec_audit_kernel_mod_in_modules_load tipc; then
    sec_audit_report_fail 131 "tipc kernel module is listed in modules-load.d (auto-load at boot)"
elif ! sec_audit_low_impact_find --timeout=20 /usr/lib/modules/ /lib/modules/ -xdev -ignore_readdir_race -type f -name "tipc.ko*" 2>/dev/null | grep -q .; then
    sec_audit_report_pass 131 "tipc kernel module is not available"
else
    if ! lsmod | grep -q tipc && modprobe --showconfig | grep -Pq '^\h*(blacklist|install)\h+tipc\b'; then
        sec_audit_report_pass 131 "tipc kernel module is not available"
    else
        sec_audit_report_fail 131 "tipc kernel module is available, loaded, or not effectively blocked (modprobe blacklist/install)"
    fi
fi

fi
if secaudit_rule_enabled 132; then
if sec_audit_kernel_mod_in_modules_load rds; then
    sec_audit_report_fail 132 "rds kernel module is listed in modules-load.d (auto-load at boot)"
elif ! sec_audit_low_impact_find --timeout=20 /usr/lib/modules/ /lib/modules/ -xdev -ignore_readdir_race -type f -name "rds.ko*" 2>/dev/null | grep -q .; then
    sec_audit_report_pass 132 "rds kernel module is not available"
else
    if ! lsmod | grep -q rds && modprobe --showconfig | grep -Pq '^\h*(blacklist|install)\h+rds\b'; then
        sec_audit_report_pass 132 "rds kernel module is not available"
    else
        sec_audit_report_fail 132 "rds kernel module is available, loaded, or not effectively blocked (modprobe blacklist/install)"
    fi
fi

fi
if secaudit_rule_enabled 133; then
if sec_audit_kernel_mod_in_modules_load sctp; then
    sec_audit_report_fail 133 "sctp kernel module is listed in modules-load.d (auto-load at boot)"
elif ! sec_audit_low_impact_find --timeout=20 /usr/lib/modules/ /lib/modules/ -xdev -ignore_readdir_race -type f -name "sctp.ko*" 2>/dev/null | grep -q .; then
    sec_audit_report_pass 133 "sctp kernel module is not available"
else
    if ! lsmod | grep -q sctp && modprobe --showconfig | grep -Pq '^\h*(blacklist|install)\h+sctp\b'; then
        sec_audit_report_pass 133 "sctp kernel module is not available"
    else
        sec_audit_report_fail 133 "sctp kernel module is available, loaded, or not effectively blocked (modprobe blacklist/install)"
    fi
fi

fi
if secaudit_rule_enabled 134; then
if sec_audit_kernel_mod_in_modules_load atm; then
    sec_audit_report_fail 134 "atm kernel module is listed in modules-load.d (auto-load at boot)"
elif ! sec_audit_low_impact_find --timeout=20 /usr/lib/modules/ /lib/modules/ -xdev -ignore_readdir_race -type f -name "atm.ko*" 2>/dev/null | grep -q .; then
    sec_audit_report_pass 134 "atm kernel module is not available"
else
    if ! lsmod | grep -q atm && modprobe --showconfig | grep -Pq '^\h*(blacklist|install)\h+atm\b'; then
        sec_audit_report_pass 134 "atm kernel module is not available"
    else
        sec_audit_report_fail 134 "atm kernel module is available, loaded, or not effectively blocked (modprobe blacklist/install)"
    fi
fi

fi
if secaudit_rule_enabled 135; then
if sec_audit_kernel_mod_in_modules_load can; then
    sec_audit_report_fail 135 "can kernel module is listed in modules-load.d (auto-load at boot)"
elif ! sec_audit_low_impact_find --timeout=20 /usr/lib/modules/ /lib/modules/ -xdev -ignore_readdir_race -type f -name "can.ko*" 2>/dev/null | grep -q .; then
    sec_audit_report_pass 135 "can kernel module is not available"
else
    if ! lsmod | grep -q can && modprobe --showconfig | grep -Pq '^\h*(blacklist|install)\h+can\b'; then
        sec_audit_report_pass 135 "can kernel module is not available"
    else
        sec_audit_report_fail 135 "can kernel module is available, loaded, or not effectively blocked (modprobe blacklist/install)"
    fi
fi

fi
if secaudit_rule_enabled 136; then
sec_audit__req_sysctl_check 136 net.ipv4.ip_forward 0

fi
if secaudit_rule_enabled 137; then
sec_audit__req_sysctl_check 137 net.ipv4.conf.all.forwarding 0

fi
if secaudit_rule_enabled 138; then
sec_audit__req_sysctl_check 138 net.ipv4.conf.default.forwarding 0

fi
if secaudit_rule_enabled 139; then
sec_audit__req_sysctl_check 139 net.ipv4.conf.all.send_redirects 0

fi
if secaudit_rule_enabled 140; then
sec_audit__req_sysctl_check 140 net.ipv4.conf.default.send_redirects 0

fi
if secaudit_rule_enabled 141; then
sec_audit__req_sysctl_check 141 net.ipv4.icmp_ignore_bogus_error_responses 1

fi
if secaudit_rule_enabled 142; then
sec_audit__req_sysctl_check 142 net.ipv4.icmp_echo_ignore_broadcasts 1

fi
if secaudit_rule_enabled 143; then
sec_audit__req_sysctl_check 143 net.ipv4.conf.all.accept_redirects 0

fi
if secaudit_rule_enabled 144; then
sec_audit__req_sysctl_check 144 net.ipv4.conf.default.accept_redirects 0

fi
if secaudit_rule_enabled 145; then
sec_audit__req_sysctl_check 145 net.ipv4.conf.all.secure_redirects 0

fi
if secaudit_rule_enabled 146; then
sec_audit__req_sysctl_check 146 net.ipv4.conf.default.secure_redirects 0

fi
if secaudit_rule_enabled 147; then
sec_audit__req_sysctl_check 147 net.ipv4.conf.all.rp_filter 1

fi
if secaudit_rule_enabled 148; then
sec_audit__req_sysctl_check 148 net.ipv4.conf.default.rp_filter 1

fi
if secaudit_rule_enabled 149; then
sec_audit__req_sysctl_check 149 net.ipv4.conf.all.accept_source_route 0

fi
if secaudit_rule_enabled 150; then
sec_audit__req_sysctl_check 150 net.ipv4.conf.default.accept_source_route 0

fi
if secaudit_rule_enabled 151; then
sec_audit__req_sysctl_check 151 net.ipv4.conf.all.log_martians 1

fi
if secaudit_rule_enabled 152; then
sec_audit__req_sysctl_check 152 net.ipv4.conf.default.log_martians 1

fi
if secaudit_rule_enabled 153; then
sec_audit__req_sysctl_check 153 net.ipv4.tcp_syncookies 1

fi
if secaudit_rule_enabled 154; then
sec_audit__req_sysctl_check 154 net.ipv4.conf.all.route_localnet 0

fi
if secaudit_rule_enabled 155; then
sec_audit__req_sysctl_check 155 net.ipv4.conf.default.route_localnet 0

fi
if secaudit_rule_enabled 156; then
sec_audit__req_sysctl_check 156 net.ipv6.conf.all.forwarding 0

fi
if secaudit_rule_enabled 157; then
sec_audit__req_sysctl_check 157 net.ipv6.conf.default.forwarding 0

fi
if secaudit_rule_enabled 158; then
sec_audit__req_sysctl_check 158 net.ipv6.conf.all.accept_redirects 0

fi
if secaudit_rule_enabled 159; then
sec_audit__req_sysctl_check 159 net.ipv6.conf.default.accept_redirects 0

fi
if secaudit_rule_enabled 160; then
sec_audit__req_sysctl_check 160 net.ipv6.conf.all.accept_source_route 0

fi
if secaudit_rule_enabled 161; then
sec_audit__req_sysctl_check 161 net.ipv6.conf.default.accept_source_route 0

fi
if secaudit_rule_enabled 162; then
sec_audit__req_sysctl_check 162 net.ipv6.conf.all.accept_ra 0

fi
if secaudit_rule_enabled 163; then
sec_audit__req_sysctl_check 163 net.ipv6.conf.default.accept_ra 0

fi
}

sec_audit_run_logging_and_auditing() {
if secaudit_rule_enabled 164; then
if rpm -q firewalld &>/dev/null; then
    sec_audit_report_pass 164 "firewalld is installed"
else
    sec_audit_report_fail 164 "firewalld package is not installed"
fi

fi
if secaudit_rule_enabled 165; then
if grep -Psi 'FirewallBackend\h*=\h*nftables\b' /etc/firewalld/firewalld.conf 2>/dev/null; then
    _fw140_be=""
    if sec_audit_have_bin firewall-cmd && firewall-cmd --state 2>/dev/null | grep -qi running; then
        _fw140_be=$(firewall-cmd --get-backend 2>/dev/null)
        if [[ "$_fw140_be" == "nftables" ]]; then
            sec_audit_report_pass 165 "firewalld.conf uses nftables and runtime backend is nftables"
        else
            sec_audit_report_pass 165 "firewalld.conf uses nftables (runtime backend reports '${_fw140_be:-?}')"
        fi
    else
        sec_audit_report_pass 165 "firewalld.conf uses nftables (firewalld not running; runtime backend not verified)"
    fi
else
    sec_audit_report_fail 165 "firewalld backend is not configured (FirewallBackend=nftables missing in firewalld.conf)"
fi

fi
if secaudit_rule_enabled 166; then
if systemctl is-enabled firewalld.service 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active firewalld.service 2>/dev/null | grep -q 'active'; then
        _fw141_nft=""
        if sec_audit_have_bin nft && nft list ruleset 2>/dev/null | grep -q .; then
            _fw141_nft="; nftables ruleset is non-empty"
        fi
        sec_audit_report_pass 166 "firewalld.service is enabled and active${_fw141_nft}"
    else
        sec_audit_report_fail 166 "firewalld.service is not enabled or not active"
    fi
else
    sec_audit_report_fail 166 "firewalld.service is not enabled or not active"
fi

fi
if secaudit_rule_enabled 167; then
if systemctl is-active firewalld &>/dev/null; then
    ACTIVE_ZONE=$(firewall-cmd --get-default-zone 2>/dev/null)
    ZONE_TARGET=$(firewall-cmd --zone="$ACTIVE_ZONE" --get-target 2>/dev/null)
    _fw142_if=$(firewall-cmd --zone="$ACTIVE_ZONE" --list-interfaces 2>/dev/null | wc -w)
    if [ "$ZONE_TARGET" = "DROP" ] || [ "$ZONE_TARGET" = "REJECT" ]; then
        sec_audit_report_pass 167 "firewalld default zone '$ACTIVE_ZONE' target is $ZONE_TARGET (${_fw142_if:-0} interface(s) assigned)"
    else
        sec_audit_report_fail 167 "firewalld active zone target is not secure (current: $ZONE_TARGET)"
    fi
else
    sec_audit_report_fail 167 "firewalld is not active"
fi

fi
if secaudit_rule_enabled 168; then
if systemctl is-active firewalld &>/dev/null; then
    if firewall-cmd --list-rich-rules 2>/dev/null | grep -Eiq 'lo|loopback|127\.0\.0\.1|interface\s*=\s*\"lo\"|interface\s*=\s*lo\b'; then
        sec_audit_report_pass 168 "firewalld rich rules mention loopback / lo / localhost"
    else
        sec_audit_report_fail 168 "firewalld loopback traffic is not configured"
    fi
else
    sec_audit_report_fail 168 "firewalld is not active"
fi

fi
if secaudit_rule_enabled 169; then
if systemctl is-active firewalld &>/dev/null; then
    if firewall-cmd --list-rich-rules 2>/dev/null | grep -Eiq 'source\s+address=.*127\.0\.0\.1|interface\s*=\s*"?lo"?'; then
        sec_audit_report_pass 169 "firewalld loopback source address traffic is configured"
    else
        sec_audit_report_fail 169 "firewalld loopback source address traffic is not configured"
    fi
else
    sec_audit_report_fail 169 "firewalld is not active"
fi

fi
if secaudit_rule_enabled 170; then
if systemctl is-active firewalld &>/dev/null; then
    SERVICES=$(firewall-cmd --list-services 2>/dev/null | wc -w)
    PORTS=$(firewall-cmd --list-ports 2>/dev/null | wc -w)
    SERVICES_P=$(firewall-cmd --permanent --list-services 2>/dev/null | wc -w)
    PORTS_P=$(firewall-cmd --permanent --list-ports 2>/dev/null | wc -w)
    if [ "$SERVICES" -gt 0 ] || [ "$PORTS" -gt 0 ]; then
        sec_audit_report_pass 170 "firewalld exposes $SERVICES service(s) and $PORTS port(s) at runtime (permanent: $SERVICES_P / $PORTS_P)"
    elif [ "$SERVICES_P" -gt 0 ] || [ "$PORTS_P" -gt 0 ]; then
        sec_audit_report_fail 170 "permanent firewalld rules exist ($SERVICES_P services, $PORTS_P ports) but runtime lists none — run firewall-cmd --reload"
    else
        sec_audit_report_fail 170 "firewalld services and ports are not configured"
    fi
else
    sec_audit_report_fail 170 "firewalld is not active"
fi

fi
if secaudit_rule_enabled 171; then
if ! systemctl is-active firewalld &>/dev/null; then
    sec_audit_report_fail 171 "firewalld is not active"
else
    _zone=$(firewall-cmd --get-default-zone 2>/dev/null)
    if [ "$_zone" = "drop" ]; then
        sec_audit_report_pass 171 "firewalld default zone is drop"
    else
        sec_audit_report_fail 171 "firewalld default zone is '${_zone:-unknown}', expected drop"
    fi
fi

fi
if secaudit_rule_enabled 172; then
FAIL_172=0
if systemctl is-enabled nftables.service 2>/dev/null | grep -q '^enabled'; then
    sec_audit_report_fail 172 "standalone nftables.service is enabled"; FAIL_172=1
fi
if systemctl is-active nftables.service 2>/dev/null | grep -q '^active'; then
    sec_audit_report_fail 172 "standalone nftables.service is active"; FAIL_172=1
fi
for _pkg in iptables-services ufw; do
    if rpm -q "$_pkg" &>/dev/null; then
        sec_audit_report_fail 172 "conflicting firewall package ${_pkg} is installed"; FAIL_172=1
    fi
done
if [ $FAIL_172 -eq 0 ]; then
    sec_audit_report_pass 172 "no conflicting firewall utilities are in use with firewalld"
fi

fi
if secaudit_rule_enabled 173; then
if ! systemctl is-active firewalld &>/dev/null; then
    sec_audit_report_fail 173 "firewalld is not active"
else
    _log_denied=$(firewall-cmd --get-log-denied 2>/dev/null)
    case "$_log_denied" in
        all|unicast|broadcast|multicast)
            sec_audit_report_pass 173 "firewalld logs denied packets (${_log_denied})" ;;
        *)
            sec_audit_report_fail 173 "firewalld log-denied is '${_log_denied:-unknown}', expected all/unicast/broadcast/multicast" ;;
    esac
fi

fi
if secaudit_rule_enabled 174; then
if ! systemctl is-active firewalld &>/dev/null; then
    sec_audit_report_fail 174 "firewalld is not active"
else
    FAIL_174=0
    _zones=$(firewall-cmd --get-active-zones 2>/dev/null | awk '/^[^ ]/{print $1}')
    for _z in $_zones; do
        _tgt=$(firewall-cmd --permanent --zone="$_z" --get-target 2>/dev/null)
        [ "$_tgt" = "default" ] || continue
        if firewall-cmd --permanent --zone="$_z" --query-icmp-block-inversion 2>/dev/null | grep -qx yes; then
            continue
        fi
        _blocks=$(firewall-cmd --permanent --zone="$_z" --list-icmp-blocks 2>/dev/null)
        for _icmp in timestamp-request timestamp-reply; do
            printf '%s' "$_blocks" | grep -qw "$_icmp" || { sec_audit_report_fail 174 "zone '${_z}' does not block ${_icmp}"; FAIL_174=1; }
        done
    done
    if [ $FAIL_174 -eq 0 ]; then
        sec_audit_report_pass 174 "firewalld blocks ICMP timestamp requests and replies in filtering zones"
    fi
fi

fi
}

sec_audit_run_access_control() {
if secaudit_rule_enabled 175; then
if stat -Lc '%a' /etc/ssh/sshd_config 2>/dev/null | grep -q '^600$'; then
    if stat -Lc '%U:%G' /etc/ssh/sshd_config 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 175 "access to /etc/ssh/sshd_config is configured"
    else
        sec_audit_report_fail 175 "File /etc/ssh/sshd_config permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 175 "File /etc/ssh/sshd_config permissions or ownership not correct"
fi

fi
if secaudit_rule_enabled 176; then
if [ -d /etc/ssh/sshd_config.d ]; then
    _bad=$(find /etc/ssh/sshd_config.d/ -maxdepth 0 \( ! -user root -o ! -group root -o -perm /077 \) 2>/dev/null)
    if [ -n "$_bad" ]; then
        sec_audit_report_fail 176 "/etc/ssh/sshd_config.d/ ownership or mode is not configured"
    else
        sec_audit_report_pass 176 "access to /etc/ssh/sshd_config.d/ is configured"
    fi
else
    sec_audit_report_pass 176 "/etc/ssh/sshd_config.d/ is absent (no drop-in directory to check)"
fi

fi
if secaudit_rule_enabled 177; then
PRIV_KEYS=$(sec_audit_sshd_effective_dump | awk '$1=="hostkey" {print $2}')
FAIL_177=0
for key in $PRIV_KEYS; do
    if [ -f "$key" ]; then
        if ! stat -Lc '%a' "$key" 2>/dev/null | grep -q '^600$'; then
            FAIL_177=1
        fi
        if ! stat -Lc '%U:%G' "$key" 2>/dev/null | grep -q '^root:root$'; then
            FAIL_177=1
        fi
    else
        FAIL_177=1
    fi
done
if [ $FAIL_177 -eq 0 ]; then
    sec_audit_report_pass 177 "access to SSH private host key files is configured"
else
    sec_audit_report_fail 177 "File SSH private host key files permissions or ownership not correct"
fi

fi
if secaudit_rule_enabled 178; then
PUB_KEYS=$(sec_audit_sshd_effective_dump | awk '$1=="hostkey" {print $2".pub"}')
FAIL_178=0
for key in $PUB_KEYS; do
    if [ -f "$key" ]; then
        if ! stat -Lc '%a' "$key" 2>/dev/null | grep -qE '^[0-6]44$'; then
            FAIL_178=1
        fi
        if ! stat -Lc '%U:%G' "$key" 2>/dev/null | grep -q '^root:root$'; then
            FAIL_178=1
        fi
    else
        FAIL_178=1
    fi
done
if [ $FAIL_178 -eq 0 ]; then
    sec_audit_report_pass 178 "access to SSH public host key files is configured"
else
    sec_audit_report_fail 178 "File SSH public host key files permissions or ownership not correct"
fi

fi
if secaudit_rule_enabled 179; then
if sec_audit_sshd_t_grep -Piq '^ciphers\h+\"?([^#\n\r]+,)?((3des|blowfish|cast128|aes(128|192|256))-cbc|arcfour(128|256)?|rijndael-cbc@lysator\.liu\.se)\b'; then
    sec_audit_report_fail 179 "sshd Ciphers allow weak or legacy algorithms (see sshd -T)"
else
    sec_audit_report_pass 179 "sshd Ciphers are configured"
fi

fi
if secaudit_rule_enabled 180; then
if sec_audit_sshd_t_grep -Piq 'kexalgorithms\h+([^#\n\r]+,)?(diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1)\b'; then
    sec_audit_report_fail 180 "sshd KexAlgorithms does not meet the benchmark (see sshd -T)"
else
    sec_audit_report_pass 180 "sshd KexAlgorithms is configured"
fi

fi
if secaudit_rule_enabled 181; then
if sec_audit_sshd_t_grep -Piq 'macs\h+([^#\n\r]+,)?(hmac-md5|hmac-md5-96|hmac-ripemd160|hmac-sha1-96|umac-64@openssh\.com|hmac-md5-etm@openssh\.com|hmac-md5-96-etm@openssh\.com|hmac-ripemd160-etm@openssh\.com|hmac-sha1-96-etm@openssh\.com|umac-64-etm@openssh\.com|umac-128-etm@openssh\.com)\b'; then
    sec_audit_report_fail 181 "sshd MACs allow weak or legacy algorithms (see sshd -T)"
else
    sec_audit_report_pass 181 "sshd MACs are configured"
fi

fi
if secaudit_rule_enabled 182; then
if sec_audit_sshd_t_grep -Piq '^\h*(allow|deny)(users|groups)\h+\H+'; then
    sec_audit_report_pass 182 "sshd access is configured"
else
    sec_audit_report_fail 182 "sshd access controls (AllowUsers/DenyUsers/AllowGroups/DenyGroups) are not set as required"
fi

fi
if secaudit_rule_enabled 183; then
if sec_audit_sshd_t_grep -Piq '^banner\h+\/\H+'; then
    sec_audit_report_pass 183 "sshd Banner is configured"
else
    sec_audit_report_fail 183 "sshd Banner does not meet the benchmark (see sshd -T)"
fi

fi
if secaudit_rule_enabled 184; then
if sec_audit_sshd_t_grep -Piq 'clientaliveinterval\s+([1-9]|[1-9][0-9]+)'; then
    if sec_audit_sshd_t_grep -Piq 'clientalivecountmax\s+([1-9]|[1-9][0-9]+)'; then
        sec_audit_report_pass 184 "sshd ClientAliveInterval and ClientAliveCountMax are configured"
    else
        sec_audit_report_fail 184 "sshd ClientAliveInterval and ClientAliveCountMax are not configured as required (see sshd -T)"
    fi
else
    sec_audit_report_fail 184 "sshd ClientAliveInterval and ClientAliveCountMax are not configured as required (see sshd -T)"
fi

fi
if secaudit_rule_enabled 185; then
if sec_audit_sshd_t_grep -iq 'disableforwarding yes'; then
    sec_audit_report_pass 185 "sshd DisableForwarding is enabled"
else
    sec_audit_report_fail 185 "sshd DisableForwarding is not enabled in effective sshd -T output"
fi

fi
if secaudit_rule_enabled 186; then
if sec_audit_sshd_t_grep -iq 'gssapiauthentication no'; then
    sec_audit_report_pass 186 "sshd GSSAPIAuthentication is disabled"
else
    sec_audit_report_fail 186 "sshd GSSAPIAuthentication is not disabled in effective sshd -T output"
fi

fi
if secaudit_rule_enabled 187; then
if sec_audit_sshd_t_grep -iq 'hostbasedauthentication no'; then
    sec_audit_report_pass 187 "sshd HostbasedAuthentication is disabled"
else
    sec_audit_report_fail 187 "sshd HostbasedAuthentication is not disabled in effective sshd -T output"
fi

fi
if secaudit_rule_enabled 188; then
if sec_audit_sshd_t_grep -iq 'ignorerhosts yes'; then
    sec_audit_report_pass 188 "sshd IgnoreRhosts is enabled"
else
    sec_audit_report_fail 188 "sshd IgnoreRhosts is not enabled in effective sshd -T output"
fi

fi
if secaudit_rule_enabled 189; then
if sec_audit_sshd_t_grep -Piq 'logingracetime\s+([1-9]|[1-5][0-9]|60)\b'; then
    sec_audit_report_pass 189 "sshd LoginGraceTime is configured"
else
    sec_audit_report_fail 189 "sshd LoginGraceTime does not meet the benchmark (see sshd -T)"
fi

fi
if secaudit_rule_enabled 190; then
if sec_audit_sshd_t_grep -iq 'loglevel VERBOSE\|loglevel INFO'; then
    sec_audit_report_pass 190 "sshd LogLevel is configured"
else
    sec_audit_report_fail 190 "sshd LogLevel does not meet the benchmark (see sshd -T)"
fi

fi
if secaudit_rule_enabled 191; then
if sec_audit_sshd_t_grep -Piq 'maxauthtries\s+[1-4]\b'; then
    sec_audit_report_pass 191 "sshd MaxAuthTries is configured"
else
    sec_audit_report_fail 191 "sshd MaxAuthTries does not meet the benchmark (see sshd -T)"
fi

fi
if secaudit_rule_enabled 192; then
if sec_audit_sshd_t_awk '$1 ~ /^\s*maxstartups/{split($2, a, ":");{if(a[1] <= 10 && a[2] <= 30 && a[3] <= 60) print "ok"}}' | grep -q "ok"; then
    sec_audit_report_pass 192 "sshd MaxStartups is configured"
else
    sec_audit_report_fail 192 "sshd MaxStartups does not meet the benchmark (see sshd -T)"
fi

fi
if secaudit_rule_enabled 193; then
if sec_audit_sshd_t_grep -Piq 'maxsessions\s+([1-9]|10)\b'; then
    sec_audit_report_pass 193 "sshd MaxSessions is configured"
else
    sec_audit_report_fail 193 "sshd MaxSessions does not meet the benchmark (see sshd -T)"
fi

fi
if secaudit_rule_enabled 194; then
if sec_audit_sshd_t_grep -iq 'permitemptypasswords no'; then
    sec_audit_report_pass 194 "sshd PermitEmptyPasswords is disabled"
else
    sec_audit_report_fail 194 "sshd PermitEmptyPasswords is not disabled in effective sshd -T output"
fi

fi
if secaudit_rule_enabled 195; then
if sec_audit_sshd_t_grep -iq 'permitrootlogin no'; then
    sec_audit_report_pass 195 "sshd PermitRootLogin is disabled"
else
    sec_audit_report_fail 195 "sshd PermitRootLogin is not disabled in effective sshd -T output"
fi

fi
if secaudit_rule_enabled 196; then
if sec_audit_sshd_t_grep -iq 'permituserenvironment no'; then
    sec_audit_report_pass 196 "sshd PermitUserEnvironment is disabled"
else
    sec_audit_report_fail 196 "sshd PermitUserEnvironment is not disabled in effective sshd -T output"
fi

fi
if secaudit_rule_enabled 197; then
if sec_audit_sshd_t_grep -iq 'usepam yes'; then
    sec_audit_report_pass 197 "sshd UsePAM is enabled"
else
    sec_audit_report_fail 197 "sshd UsePAM is not enabled in effective sshd -T output"
fi

fi
if secaudit_rule_enabled 198; then
if rpm -q sudo &>/dev/null; then
    sec_audit_report_pass 198 "sudo is installed"
else
    sec_audit_report_fail 198 "sudo package is not installed"
fi

fi
if secaudit_rule_enabled 199; then
_bad=$(find /etc/sudoers /etc/sudoers.d/ -type f \( -perm /0337 -o ! -user root -o ! -group root \) 2>/dev/null | head -n 5)
if [ -n "$_bad" ]; then
    sec_audit_report_fail 199 "sudoers files have insecure mode or ownership: $(printf '%s' "$_bad" | tr '\n' ' ')"
else
    sec_audit_report_pass 199 "access on sudoers configuration files is configured"
fi

fi
if secaudit_rule_enabled 200; then
if [ -d /etc/sudoers.d ]; then
    _bad=$(find /etc/sudoers.d -maxdepth 0 -type d \( -perm /0027 -o ! -user root -o ! -group root \) 2>/dev/null)
    if [ -n "$_bad" ]; then
        sec_audit_report_fail 200 "/etc/sudoers.d directory permissions or ownership not correct"
    else
        sec_audit_report_pass 200 "access on the /etc/sudoers.d directory is configured"
    fi
else
    sec_audit_report_pass 200 "/etc/sudoers.d is absent (no directory to check)"
fi

fi
if secaudit_rule_enabled 201; then
if grep -rPi '^\h*Defaults\h+([^#\n\r]+,\h*)?use_pty\b' $(ls -d /etc/sudoers* 2>/dev/null) /dev/null 2>/dev/null; then
    if ! grep -rPi '^\h*Defaults\h+([^#\n\r]+,\h*)?!use_pty\b' $(ls -d /etc/sudoers* 2>/dev/null) /dev/null 2>/dev/null; then
        sec_audit_report_pass 201 "sudo commands use pty"
    else
        sec_audit_report_fail 201 "sudo is not configured to require a pseudo-terminal (use_pty)"
    fi
else
    sec_audit_report_fail 201 "sudo is not configured to require a pseudo-terminal (use_pty)"
fi

fi
if secaudit_rule_enabled 202; then
if grep -rPsi "^\h*Defaults\h+([^#]+,\h*)?logfile\h*=\h*(\"|\')?\H+(\"|\')?(,\h*\H+\h*)*\h*(#.*)?$" $(ls -d /etc/sudoers* 2>/dev/null) /dev/null 2>/dev/null; then
    sec_audit_report_pass 202 "sudo log file exists"
else
    sec_audit_report_fail 202 "sudo log file is missing or not configured"
fi

fi
if secaudit_rule_enabled 203; then
if grep -r "^[^#].*NOPASSWD" $(ls -d /etc/sudoers* 2>/dev/null) /dev/null 2>/dev/null; then
    sec_audit_report_fail 203 "NOPASSWD or password-less sudo rules violate escalation policy"
else
    sec_audit_report_pass 203 "users must provide password for escalation"
fi

fi
if secaudit_rule_enabled 204; then
if grep -q -rPi '^\h*Defaults\h+([^#\n\r]+,\h*)?!authenticate\b' /etc/sudoers $(ls -d /etc/sudoers.d/* 2>/dev/null) /dev/null 2>/dev/null; then
	sec_audit_report_fail 204 "sudo Defaults disables re-authentication (!authenticate)"
else
	sec_audit_report_pass 204 "sudo does not globally disable re-authentication"
fi

fi
if secaudit_rule_enabled 205; then
if grep -rPi -- '^\h*Defaults\h+([^#]+,\h*)?pwfeedback\b' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -q .; then
    sec_audit_report_fail 205 "sudo pwfeedback is enabled in sudoers"
else
    sec_audit_report_pass 205 "sudo pwfeedback is not enabled"
fi

fi
if secaudit_rule_enabled 206; then
if grep -rPi -- '^\h*Defaults\h+([^#]+,\h*)?visiblepw\b' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -q .; then
    sec_audit_report_fail 206 "sudo visiblepw is enabled in sudoers"
else
    sec_audit_report_pass 206 "sudo visiblepw is not enabled"
fi

fi
if secaudit_rule_enabled 207; then
TIMEOUT=$(sudo -V 2>/dev/null | sed -n 's/^Authentication timestamp timeout: \([0-9][0-9]*\).*/\1/p')
if [ -z "$TIMEOUT" ]; then
    sec_audit_report_fail 207 "sudo is not installed or the authentication timestamp timeout cannot be read"
elif [ "$TIMEOUT" -ge 0 ] && [ "$TIMEOUT" -le 15 ]; then
    sec_audit_report_pass 207 "sudo timestamp_timeout is configured (${TIMEOUT} minutes)"
else
    sec_audit_report_fail 207 "sudo timestamp_timeout is ${TIMEOUT} minutes, expected 0..15"
fi

fi
if secaudit_rule_enabled 208; then
if grep -rPi -- 'timestamp_type\h*=\h*global' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -q .; then
    sec_audit_report_fail 208 "sudo timestamp_type is set to global (timestamp shared across sessions)"
else
    sec_audit_report_pass 208 "sudo timestamp_type is not set to global"
fi

fi
if secaudit_rule_enabled 209; then
if grep -Pi '^\h*auth\h+(?:required|requisite)\h+pam_wheel\.so\h+(?:[^#\n\r]+\h+)?((?!\2)(use_uid\b|group=\H+\b))\h+(?:[^#\n\r]+\h+)?((?!\1)(use_uid\b|group=\H+\b))(\h+.*)?$' /etc/pam.d/su 2>/dev/null; then
    GROUP=$(grep -Pi '^\h*auth\h+(?:required|requisite)\h+pam_wheel\.so\h+(?:[^#\n\r]+\h+)?((?!\2)(use_uid\b|group=\H+\b))\h+(?:[^#\n\r]+\h+)?((?!\1)(use_uid\b|group=\H+\b))(\h+.*)?$' /etc/pam.d/su 2>/dev/null | grep -oP 'group=\K\H+')
    if [ -n "$GROUP" ]; then
        if ! grep "^$GROUP:" /etc/group 2>/dev/null | grep -q ":$GROUP:x:"; then
            sec_audit_report_pass 209 "access to the su command is restricted"
        else
            sec_audit_report_fail 209 "su is not restricted to the wheel group in PAM configuration"
        fi
    else
        sec_audit_report_pass 209 "access to the su command is restricted"
    fi
else
    sec_audit_report_fail 209 "su is not restricted to the wheel group in PAM configuration"
fi

fi
if secaudit_rule_enabled 210; then
_v=$(rpm -q --qf '%{VERSION}-%{RELEASE}\n' pam 2>/dev/null | head -n1)
if [ -z "$_v" ]; then
    sec_audit_report_fail 210 "pam package is not installed"
elif [ "$(printf '%s\n%s\n' '1.5.1-14' "$_v" | sort -V | head -n1)" = "1.5.1-14" ]; then
    sec_audit_report_pass 210 "pam version ${_v} satisfies >= 1.5.1-14"
else
    sec_audit_report_fail 210 "pam version ${_v} is older than 1.5.1-14"
fi

fi
if secaudit_rule_enabled 211; then
_v=$(rpm -q --qf '%{VERSION}-%{RELEASE}\n' authselect 2>/dev/null | head -n1)
if [ -z "$_v" ]; then
    sec_audit_report_fail 211 "authselect package is not installed"
elif [ "$(printf '%s\n%s\n' '1.2.6-1' "$_v" | sort -V | head -n1)" = "1.2.6-1" ]; then
    sec_audit_report_pass 211 "authselect version ${_v} satisfies >= 1.2.6-1"
else
    sec_audit_report_fail 211 "authselect version ${_v} is older than 1.2.6-1"
fi

fi
if secaudit_rule_enabled 212; then
_v=$(rpm -q --qf '%{VERSION}-%{RELEASE}\n' libpwquality 2>/dev/null | head -n1)
if [ -z "$_v" ]; then
    sec_audit_report_fail 212 "libpwquality package is not installed"
elif [ "$(printf '%s\n%s\n' '1.4.4-8' "$_v" | sort -V | head -n1)" = "1.4.4-8" ]; then
    sec_audit_report_pass 212 "libpwquality version ${_v} satisfies >= 1.4.4-8"
else
    sec_audit_report_fail 212 "libpwquality version ${_v} is older than 1.4.4-8"
fi

fi
if secaudit_rule_enabled 213; then
ACTIVE_PROFILE=$(head -1 /etc/authselect/authselect.conf 2>/dev/null)
if [ -z "$ACTIVE_PROFILE" ]; then
    sec_audit_report_fail 213 "active authselect profile does not include required pam modules"
elif sec_audit_have_bin authselect && ! authselect check &>/dev/null; then
    sec_audit_report_fail 213 "authselect reports configuration drift (run authselect check / apply changes)"
elif grep -P -- '\b(pam_pwquality\.so|pam_pwhistory\.so|pam_faillock\.so|pam_unix\.so)\b' /etc/authselect/"$ACTIVE_PROFILE"/{system,password}-auth 2>/dev/null; then
    sec_audit_report_pass 213 "active authselect profile includes pam modules (authselect check OK)"
else
    sec_audit_report_fail 213 "active authselect profile does not include required pam modules"
fi

fi
if secaudit_rule_enabled 214; then
if grep -Pq -- '\bpam_faillock\.so\b' /etc/pam.d/system-auth 2>/dev/null    && grep -Pq -- '\bpam_faillock\.so\b' /etc/pam.d/password-auth 2>/dev/null; then
    sec_audit_report_pass 214 "pam_faillock.so is enabled in system-auth and password-auth"
else
    sec_audit_report_fail 214 "pam_faillock.so is missing from the effective PAM configuration"
fi

fi
if secaudit_rule_enabled 215; then
if sec_audit_pam_password_line_has_module pam_pwquality.so && sec_audit_pam_password_pwquality_before_unix_all_stacks; then
    sec_audit_report_pass 215 "pam_pwquality.so on password stack and ordered before pam_unix.so"
elif sec_audit_pam_password_line_has_module pam_pwquality.so; then
    sec_audit_report_fail 215 "pam_pwquality.so present but not correctly ordered before pam_unix.so on password stack"
else
    sec_audit_report_fail 215 "pam_pwquality module is not enabled on the password stack"
fi

fi
if secaudit_rule_enabled 216; then
if sec_audit_pam_password_line_has_module pam_pwhistory.so; then
    sec_audit_report_pass 216 "pam_pwhistory.so on password stack in resolved password-auth/system-auth"
else
    sec_audit_report_fail 216 "pam_pwhistory module is not enabled on the password stack"
fi

fi
if secaudit_rule_enabled 217; then
if sec_audit_pam_password_line_has_module pam_unix.so; then
    sec_audit_report_pass 217 "pam_unix.so on password stack in resolved password-auth/system-auth"
else
    sec_audit_report_fail 217 "pam_unix module is not enabled on the password stack"
fi

fi
if secaudit_rule_enabled 218; then
if grep -Psi 'deny\h*=\h*[1-5]\b' /etc/security/faillock.conf 2>/dev/null; then
    sec_audit_report_pass 218 "password failed attempts lockout is configured"
else
    sec_audit_report_fail 218 "faillock deny threshold is not configured in /etc/security/faillock.conf"
fi

fi
if secaudit_rule_enabled 219; then
if grep -Psi 'unlock_time\h*=\h*(0|9[0-9][0-9]|[1-9][0-9]{3,})\b' /etc/security/faillock.conf 2>/dev/null; then
    sec_audit_report_pass 219 "password unlock time is configured"
else
    sec_audit_report_fail 219 "faillock unlock_time is not set within the required range"
fi

fi
if secaudit_rule_enabled 220; then
if grep -rPsi '^\h*even_deny_root\b' /etc/security/faillock.conf $(ls -d /etc/security/faillock.conf.d/*.conf 2>/dev/null) /dev/null 2>/dev/null; then
    sec_audit_report_pass 220 "password failed attempts lockout includes root account"
else
    sec_audit_report_fail 220 "even_deny_root is not set in faillock configuration"
fi

fi
if secaudit_rule_enabled 221; then
if grep -q -Psi '^\h*difok\h*=\h*[2-9]\b' /etc/security/pwquality.conf $(ls -d /etc/security/pwquality.conf.d/*.conf 2>/dev/null) /dev/null 2>/dev/null; then
    sec_audit_report_pass 221 "password number of changed characters is configured (difok)"
else
    sec_audit_report_fail 221 "pwquality difok is not configured within policy"
fi

fi
if secaudit_rule_enabled 222; then
if grep -Psi '^\h*minlen\h*=\h*(1[4-9]|[2-9][0-9]|[1-9][0-9]{2,})\b' /etc/security/pwquality.conf $(ls -d /etc/security/pwquality.conf.d/*.conf 2>/dev/null) /dev/null 2>/dev/null; then
    sec_audit_report_pass 222 "password length is configured"
else
    sec_audit_report_fail 222 "pwquality minlen (or equivalent) is not set to at least 14"
fi

fi
if secaudit_rule_enabled 223; then
if grep -Psi '^\h*(minclass|[dulo]credit)\b' /etc/security/pwquality.conf $(ls -d /etc/security/pwquality.conf.d/*.conf 2>/dev/null) /dev/null 2>/dev/null; then
    sec_audit_report_pass 223 "password complexity is configured"
else
    sec_audit_report_fail 223 "pwquality complexity (minclass/credits) is not configured"
fi

fi
if secaudit_rule_enabled 224; then
if grep -q -Psi '^\h*maxrepeat\h*=\h*[1-3]\b' /etc/security/pwquality.conf $(ls -d /etc/security/pwquality.conf.d/*.conf 2>/dev/null) /dev/null 2>/dev/null; then
    sec_audit_report_pass 224 "password same consecutive characters is configured (maxrepeat)"
else
    sec_audit_report_fail 224 "pwquality maxrepeat is not configured within policy"
fi

fi
if secaudit_rule_enabled 225; then
if grep -q -Psi '^\h*maxsequence\h*=\h*[1-3]\b' /etc/security/pwquality.conf $(ls -d /etc/security/pwquality.conf.d/*.conf 2>/dev/null) /dev/null 2>/dev/null; then
    sec_audit_report_pass 225 "password maximum sequential characters is configured (maxsequence)"
else
    sec_audit_report_fail 225 "pwquality maxsequence is not configured within policy"
fi

fi
if secaudit_rule_enabled 226; then
if ! grep -Psi '^\h*dictcheck\h*=\h*0\b' /etc/security/pwquality.conf $(ls -d /etc/security/pwquality.conf.d/*.conf 2>/dev/null) /dev/null 2>/dev/null; then
    sec_audit_report_pass 226 "password dictionary check is enabled"
else
    sec_audit_report_fail 226 "pwquality dictcheck is disabled or weak"
fi

fi
if secaudit_rule_enabled 227; then
if grep -Psi '\h*enforce_for_root\b' /etc/security/pwquality.conf $(ls -d /etc/security/pwquality.conf.d/*.conf 2>/dev/null) /dev/null 2>/dev/null; then
    sec_audit_report_pass 227 "password quality is enforced for the root user"
else
    sec_audit_report_fail 227 "pwquality enforce_for_root is not set"
fi

fi
if secaudit_rule_enabled 228; then
if grep -Psi 'remember\h*=\h*(2[4-9]|[3-9][0-9]|[1-9][0-9]{2,})\b' /etc/security/pwhistory.conf 2>/dev/null; then
    sec_audit_report_pass 228 "password history remember is configured"
elif grep -P '^\h*password\h+([^#\n\r]+)\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?remember=[0-9]+\b' /etc/pam.d/common-password 2>/dev/null | grep -q remember; then
    REMEMBER=$(grep -P '^\h*password\h+([^#\n\r]+)\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?remember=\K[0-9]+' /etc/pam.d/common-password 2>/dev/null)
    if [ "$REMEMBER" -ge 24 ]; then
        sec_audit_report_pass 228 "password history remember is configured"
    else
        sec_audit_report_fail 228 "pwhistory remember value is below policy or not configured"
    fi
else
    sec_audit_report_fail 228 "pwhistory remember value is below policy or not configured"
fi

fi
if secaudit_rule_enabled 229; then
if grep -Psi 'enforce_for_root\b' /etc/security/pwhistory.conf 2>/dev/null; then
    sec_audit_report_pass 229 "password history is enforced for the root user"
else
    sec_audit_report_fail 229 "pwhistory enforce_for_root is not set"
fi

fi
if secaudit_rule_enabled 230; then
if grep -P '^\h*password\h+([^#\n\r]+)\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?use_authtok\b' /etc/pam.d/common-password 2>/dev/null; then
    sec_audit_report_pass 230 "pam_pwhistory includes use_authtok"
else
    sec_audit_report_fail 230 "pam_pwhistory line lacks use_authtok"
fi

fi
if secaudit_rule_enabled 231; then
if ! grep -P '^\h*auth\h+sufficient\h+pam_unix\.so\b' /etc/pam.d/{password,system}-auth 2>/dev/null | grep -q nullok; then
    sec_audit_report_pass 231 "pam_unix does not include nullok"
else
    sec_audit_report_fail 231 "pam_unix still allows nullok in the auth stack"
fi

fi
if secaudit_rule_enabled 232; then
if grep -Pi '^\h*password\h+([^#\n\r]+\h+)?pam_unix\.so\b' /etc/pam.d/common-password 2>/dev/null | grep -qv "remember="; then
    sec_audit_report_pass 232 "pam_unix does not include remember"
else
    sec_audit_report_fail 232 "pam_unix password line still uses remember="
fi

fi
if secaudit_rule_enabled 233; then
if grep -rPsi '^\h*password\h+[^#\n\r]+\h+pam_unix\.so\h+([^#\n\r]+\h+)?(yescrypt|sha512)\b' /etc/pam.d/password-auth /etc/pam.d/system-auth 2>/dev/null; then
    sec_audit_report_pass 233 "pam_unix includes a strong password hashing algorithm"
else
    sec_audit_report_fail 233 "pam_unix does not use yescrypt or sha512 in PAM stacks"
fi

fi
if secaudit_rule_enabled 234; then
if grep -P '^\h*password\h+([^#\n\r]+)\h+pam_unix\.so\h+([^#\n\r]+\h+)?use_authtok\b' /etc/pam.d/common-password 2>/dev/null; then
    sec_audit_report_pass 234 "pam_unix includes use_authtok"
else
    sec_audit_report_fail 234 "pam_unix password line lacks use_authtok"
fi

fi
if secaudit_rule_enabled 235; then
if grep -Psi '^\h*PASS_MAX_DAYS\h+(36[0-5]|3[0-5][0-9]|[1-2][0-9][0-9]|[1-9][0-9]|[1-9])\b' /etc/login.defs 2>/dev/null; then
    if ! awk -F: '($2~/^\$.+\$/) {if($5 > 365 || $5 < 1)print}' /etc/shadow 2>/dev/null | grep -q '.'; then
        sec_audit_report_pass 235 "password expiration is configured"
    else
        sec_audit_report_fail 235 "PASS_MAX_DAYS or per-user shadow MAX exceeds policy or is unset"
    fi
else
    sec_audit_report_fail 235 "PASS_MAX_DAYS or per-user shadow MAX exceeds policy or is unset"
fi

fi
if secaudit_rule_enabled 236; then
if grep -q "^PASS_MIN_DAYS" /etc/login.defs 2>/dev/null; then
    MIN_DAYS=$(grep "^PASS_MIN_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
    if [ "$MIN_DAYS" -ge 7 ] 2>/dev/null; then
        sec_audit_report_pass 236 "Minimum password days is configured"
    else
        sec_audit_report_fail 236 "Minimum password days is too low (recommended 7+)"
    fi
else
    sec_audit_report_fail 236 "Minimum password days is not configured"
fi

fi
if secaudit_rule_enabled 237; then
if grep -Psi '^\h*PASS_WARN_AGE\h+([7-9]|[1-9][0-9]+)\b' /etc/login.defs 2>/dev/null; then
    if ! awk -F: '($2~/^\$.+\$/) {if($6 < 7)print}' /etc/shadow 2>/dev/null | grep -q '.'; then
        sec_audit_report_pass 237 "password expiration warning days is configured"
    else
        sec_audit_report_fail 237 "PASS_WARN_AGE is not set within policy in /etc/login.defs"
    fi
else
    sec_audit_report_fail 237 "PASS_WARN_AGE is not set within policy in /etc/login.defs"
fi

fi
if secaudit_rule_enabled 238; then
if grep -Psi '^\h*ENCRYPT_METHOD\h+(SHA512|YESCRYPT)\b' /etc/login.defs 2>/dev/null; then
    sec_audit_report_pass 238 "strong password hashing algorithm is configured"
else
    sec_audit_report_fail 238 "ENCRYPT_METHOD in /etc/login.defs does not use a strong hashing algorithm"
fi

fi
if secaudit_rule_enabled 239; then
if useradd -D 2>/dev/null | grep INACTIVE | cut -d= -f2 | grep -qE '^([1-9]|[1-4][0-9]|45)$'; then
    if ! awk -F: '($2~/^\$.+\$/) {if($7 > 45 || $7 < 0)print}' /etc/shadow 2>/dev/null | grep -q '.'; then
        sec_audit_report_pass 239 "inactive password lock is configured"
    else
        sec_audit_report_fail 239 "useradd INACTIVE or inactive lock policy is not configured"
    fi
else
    sec_audit_report_fail 239 "useradd INACTIVE or inactive lock policy is not configured"
fi

fi
if secaudit_rule_enabled 240; then
FAIL_240=0
while IFS=: read -r user pass last_change rest; do
    if [ -n "$last_change" ] && [ "$last_change" -gt 0 ] 2>/dev/null; then
        current_date=$(date +%s)
        last_change_seconds=$((last_change * 86400))
        if [ "$last_change_seconds" -gt "$current_date" ]; then
            sec_audit_report_fail 240 "User $user has password change date in the future"
            FAIL_240=1
        fi
    fi
done < /etc/shadow 2>/dev/null
if [ $FAIL_240 -eq 0 ]; then
    sec_audit_report_pass 240 "All users last password change date is in the past"
fi

fi
if secaudit_rule_enabled 241; then
if awk -F: '($3 == 0) { print $1 }' /etc/passwd 2>/dev/null | grep -qx "root"; then
    if [ $(awk -F: '($3 == 0) { print $1 }' /etc/passwd 2>/dev/null | wc -l) -eq 1 ]; then
        sec_audit_report_pass 241 "root is the only UID 0 account"
    else
        sec_audit_report_fail 241 "Multiple accounts with UID 0 exist in /etc/passwd"
    fi
else
    sec_audit_report_fail 241 "Multiple accounts with UID 0 exist in /etc/passwd"
fi

fi
if secaudit_rule_enabled 242; then
if awk -F: '($1 !~ /^(sync|shutdown|halt|operator)/ && $4=="0") {print $1":"$4}' /etc/passwd 2>/dev/null | grep -q "root:0"; then
    if [ $(awk -F: '($1 !~ /^(sync|shutdown|halt|operator)/ && $4=="0") {print}' /etc/passwd 2>/dev/null | wc -l) -eq 1 ]; then
        sec_audit_report_pass 242 "root is the only GID 0 account"
    else
        sec_audit_report_fail 242 "Multiple users use GID 0 outside policy"
    fi
else
    sec_audit_report_fail 242 "Multiple users use GID 0 outside policy"
fi

fi
if secaudit_rule_enabled 243; then
if awk -F: '$3=="0"{print $1":"$3}' /etc/group 2>/dev/null | grep -q "root:0"; then
    if [ $(awk -F: '$3=="0"{print}' /etc/group 2>/dev/null | wc -l) -eq 1 ]; then
        sec_audit_report_pass 243 "group root is the only GID 0 group"
    else
        sec_audit_report_fail 243 "Multiple groups share GID 0"
    fi
else
    sec_audit_report_fail 243 "Multiple groups share GID 0"
fi

fi
if secaudit_rule_enabled 244; then
if passwd -S root 2>/dev/null | awk '$2 ~ /^(P|L)/' | grep -q "root"; then
    sec_audit_report_pass 244 "root account access is controlled"
else
    sec_audit_report_fail 244 "root SSH/console access restrictions are not configured as required"
fi

fi
if secaudit_rule_enabled 245; then
FAIL_245=0
ROOT_PATH=$(sudo -i echo "\$PATH" 2>/dev/null || echo "$PATH")
if echo "$ROOT_PATH" | grep -q "::"; then
    sec_audit_report_fail 245 "Root PATH contains empty directory (::)"
    FAIL_245=1
fi
if echo "$ROOT_PATH" | grep -q "\.:"; then
    sec_audit_report_fail 245 "Root PATH contains current directory (.)"
    FAIL_245=1
fi
if [ $FAIL_245 -eq 0 ]; then
    sec_audit_report_pass 245 "Root path integrity is maintained"
fi

fi
if secaudit_rule_enabled 246; then
if ! grep -Psi '^\h*umask\h+((\d{1,2}(\d[^7]|[^2-7]\d)\b)|(u=[rwx]{1,3},)?(((g=[rx]?[rx]?w[rx]?[rx]?\b)(,o=[rwx]{1,3})?)|((g=[wrx]{1,3},)?o=[wrx]{1,3}\b)))' /root/.bash_profile /root/.bashrc 2>/dev/null; then
    sec_audit_report_pass 246 "root user umask is configured"
else
    sec_audit_report_fail 246 "root umask is not 027 (or stricter) in profile scripts"
fi

fi
if secaudit_rule_enabled 247; then
VALID_SHELLS=$(awk -F\/ '$NF != "nologin" && $NF != "false" {print}' /etc/shells 2>/dev/null | sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' -)
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs 2>/dev/null)
if awk -v pat="^($VALID_SHELLS)$" -v uidmin="$UID_MIN" -F: '($1!~/^(root|halt|sync|shutdown|nfsnobody)$/ && ($3<uidmin || $3==65534) && $NF ~ pat) {print}' /etc/passwd 2>/dev/null | grep -q '.'; then
    sec_audit_report_fail 247 "System accounts still have an interactive login shell"
else
    sec_audit_report_pass 247 "system accounts do not have a valid login shell"
fi

fi
if secaudit_rule_enabled 248; then
VALID_SHELLS=$(awk -F\/ '$NF != "nologin" && $NF != "false" {print}' /etc/shells 2>/dev/null | sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' -)
FAIL_248=0
while IFS= read -r l_user; do
    if passwd -S "$l_user" 2>/dev/null | awk '$2 !~ /^L/ {print "found"}' | grep -q "found"; then
        sec_audit_report_fail 248 "Accounts without a valid shell are not locked in /etc/shadow"
        FAIL_248=1
        break
    fi
done <<< "$(awk -v pat="^($VALID_SHELLS)$" -F: '($1 != "root" && $NF !~ pat) {print $1}' /etc/passwd 2>/dev/null)"
if [ $FAIL_248 -eq 0 ]; then
    sec_audit_report_pass 248 "accounts without a valid login shell are locked"
fi

fi
if secaudit_rule_enabled 249; then
if grep -Ps '^\h*([^#\n\r]+)?\/nologin\b' /etc/shells 2>/dev/null; then
    sec_audit_report_fail 249 "nologin appears in /etc/shells"
else
    sec_audit_report_pass 249 "nologin is not listed in /etc/shells"
fi

fi
if secaudit_rule_enabled 250; then
if grep -Psi '^([^#\n\r]+)?\bTMOUT=(9[0-9]{1,2}|[1-9][0-9]|[1-9])\b' $(ls -d /etc/*bashrc 2>/dev/null) /etc/profile $(ls -d /etc/profile.d/*.sh 2>/dev/null) /dev/null 2>/dev/null; then
    sec_audit_report_pass 250 "default user shell timeout is configured"
else
    sec_audit_report_fail 250 "TMOUT is not set for interactive shells in /etc/profile or profile.d"
fi

fi
if secaudit_rule_enabled 251; then
if grep -Psi '^\h*UMASK\h+0?(?:[0-7][2-7]7)\b' /etc/login.defs 2>/dev/null; then
    sec_audit_report_pass 251 "default user umask is configured in /etc/login.defs"
else
    sec_audit_report_fail 251 "UMASK 0027 (or more restrictive) is not set in /etc/login.defs"
fi

fi
if secaudit_rule_enabled 252; then
if grep -Psi '^\h*umask\h+0?(?:[0-7][2-7]7)\b' /etc/login.defs 2>/dev/null; then
    if grep -Psi '^\h*umask\h+0?027\b' $(ls -d /etc/profile.d/*.sh 2>/dev/null) /dev/null 2>/dev/null; then
        sec_audit_report_pass 252 "default user umask is configured"
    else
        sec_audit_report_fail 252 "Default user umask 027 is not set in /etc/profile or profile.d"
    fi
else
    sec_audit_report_fail 252 "Default user umask 027 is not set in /etc/profile or profile.d"
fi

fi
}

sec_audit_run_system_maintenance() {
if secaudit_rule_enabled 253; then
if systemctl is-enabled systemd-journald.service 2>/dev/null | grep -q 'static'; then
    if systemctl is-active systemd-journald.service 2>/dev/null | grep -q 'active'; then
        sec_audit_report_pass 253 "journald service is active"
    else
        sec_audit_report_fail 253 "systemd-journald is not active or not in expected state"
    fi
else
    sec_audit_report_fail 253 "systemd-journald is not active or not in expected state"
fi

fi
if secaudit_rule_enabled 254; then
if systemctl is-enabled systemd-journal-remote.socket systemd-journal-remote.service 2>/dev/null | grep -q 'enabled'; then
    sec_audit_report_fail 254 "systemd-journal-remote socket/service is enabled or active but should be disabled"
elif systemctl is-active systemd-journal-remote.socket systemd-journal-remote.service 2>/dev/null | grep -q 'active'; then
    sec_audit_report_fail 254 "systemd-journal-remote socket/service is enabled or active but should be disabled"
else
    sec_audit_report_pass 254 "systemd-journal-remote service is not in use"
fi

fi
if secaudit_rule_enabled 255; then
if systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -E '^ForwardToSyslog=yes' | head -1 | grep -q "ForwardToSyslog=yes"; then
    sec_audit_report_pass 255 "journald is configured to send logs to rsyslog"
else
    sec_audit_report_fail 255 "journald ForwardToSyslog or forwarding to rsyslog is not configured"
fi

fi
if secaudit_rule_enabled 256; then
if grep -q "^SystemMaxUse\|^SystemMaxFileSize\|^MaxFileSec" /etc/systemd/journald.conf 2>/dev/null; then
    sec_audit_report_pass 256 "journald log file rotation is configured"
else
    sec_audit_report_warn 256 "journald log file rotation using defaults (may be acceptable)"
fi

fi
if secaudit_rule_enabled 257; then
if [ -d /var/log/journal ]; then
    DIR_PERM=$(stat -c '%a' /var/log/journal 2>/dev/null)
    if [ "$DIR_PERM" = "755" ] || [ "$DIR_PERM" = "750" ]; then
        sec_audit_report_pass 257 "journald log file access is configured (directory mode: $DIR_PERM)"
    else
        sec_audit_report_fail 257 "journald log directory has insecure permissions: $DIR_PERM"
    fi
else
    sec_audit_report_pass 257 "journald log file access is configured (directory not found)"
fi

fi
if secaudit_rule_enabled 258; then
if rpm -q rsyslog &>/dev/null; then
    sec_audit_report_pass 258 "rsyslog is installed"
else
    sec_audit_report_fail 258 "rsyslog package is not installed"
fi

fi
if secaudit_rule_enabled 259; then
if systemctl is-enabled rsyslog 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active rsyslog.service 2>/dev/null | grep -q 'active'; then
        sec_audit_report_pass 259 "rsyslog service is enabled and active"
    else
        sec_audit_report_fail 259 "rsyslog is not enabled or not active"
    fi
else
    sec_audit_report_fail 259 "rsyslog is not enabled or not active"
fi

fi
if secaudit_rule_enabled 260; then
if grep -Ps '^\h*\$FileCreateMode\h+0[0,2,4,6][0,2,4]0\b' /etc/rsyslog.conf $(ls -d /etc/rsyslog.d/*.conf 2>/dev/null) /dev/null 2>/dev/null; then
    sec_audit_report_pass 260 "rsyslog log file creation mode is configured"
else
    sec_audit_report_fail 260 "rsyslog $FileCreateMode (or equivalent) does not meet policy"
fi

fi
if secaudit_rule_enabled 261; then
if [ ! -e /etc/rsyslog.conf ] && [ ! -d /etc/rsyslog.d ]; then
    sec_audit_report_pass 261 "rsyslog is not installed (recommendation not applicable)"
else
    _bad=$(find /etc/rsyslog.conf -not -type l \( ! -user root -o ! -group root -o -perm /0137 \) 2>/dev/null;            find /etc/rsyslog.d/ -type f -name '*.conf' \( ! -user root -o ! -group root -o -perm /0137 \) 2>/dev/null)
    if [ -n "$_bad" ]; then
        sec_audit_report_fail 261 "rsyslog configuration files have insecure mode or ownership: $(printf '%s' "$_bad" | tr '\n' ' ')"
    else
        sec_audit_report_pass 261 "access to rsyslog configuration files is configured"
    fi
fi

fi
if secaudit_rule_enabled 262; then
if [ ! -d /etc/rsyslog.d ]; then
    sec_audit_report_pass 262 "/etc/rsyslog.d is absent (recommendation not applicable)"
else
    _bad=$(find /etc/rsyslog.d/ -maxdepth 0 -type d \( ! -user root -o ! -group root -o -perm /0022 \) 2>/dev/null)
    if [ -n "$_bad" ]; then
        sec_audit_report_fail 262 "/etc/rsyslog.d directory permissions or ownership not correct"
    else
        sec_audit_report_pass 262 "access to the /etc/rsyslog.d directory is configured"
    fi
fi

fi
if secaudit_rule_enabled 263; then
_wd=$(grep -Pohsi -- '(?<=^\$WorkDirectory\h)[^[:space:]]+' /etc/rsyslog.conf $(ls -d /etc/rsyslog.d/*.conf 2>/dev/null) /dev/null 2>/dev/null | head -n1)
[ -n "$_wd" ] || _wd=$(grep -Pohsi -- 'workDirectory\h*=\h*"?\K[^"[:space:]]+' /etc/rsyslog.conf $(ls -d /etc/rsyslog.d/*.conf 2>/dev/null) /dev/null 2>/dev/null | head -n1)
[ -n "$_wd" ] || _wd=/var/lib/rsyslog
if [ ! -d "$_wd" ]; then
    sec_audit_report_fail 263 "rsyslog work directory ${_wd} does not exist"
else
    _bad=$(find "$_wd" -maxdepth 0 -type d \( ! -user root -o ! -group root -o -perm /0077 \) 2>/dev/null)
    if [ -n "$_bad" ]; then
        sec_audit_report_fail 263 "rsyslog work directory ${_wd} permissions or ownership not correct"
    else
        sec_audit_report_pass 263 "access to the rsyslog work directory (${_wd}) is configured"
    fi
fi

fi
if secaudit_rule_enabled 264; then
if ! rpm -q rsyslog &>/dev/null; then
	sec_audit_report_pass 264 "rsyslog not installed"
elif grep -rEi '^\s*module\(load="imtcp"|^\s*module\(load="imudp"|^\s*input\(' /etc/rsyslog.conf $(ls -d /etc/rsyslog.d/*.conf 2>/dev/null) /dev/null 2>/dev/null | grep -q .; then
	sec_audit_report_fail 264 "rsyslog configured to receive remote logs (imtcp/imudp/input)"
else
	sec_audit_report_pass 264 "rsyslog not configured as remote log receiver"
fi

fi
if secaudit_rule_enabled 265; then
if command -v rsyslogd &>/dev/null; then
    if [ -f /etc/rsyslog.conf ] && grep -v "^#" /etc/rsyslog.conf 2>/dev/null | grep -q "^\*\.\*\|^auth\|^mail\|^cron"; then
        sec_audit_report_pass 265 "rsyslog logging is configured"
    else
        sec_audit_report_fail 265 "rsyslog logging is not properly configured"
    fi
else
    sec_audit_report_pass 265 "rsyslog is not installed"
fi

fi
if secaudit_rule_enabled 266; then
if ! rpm -q rsyslog &>/dev/null; then
	sec_audit_report_pass 266 "rsyslog not installed (remote forwarding N/A)"
elif grep -rE '^[^#]*@(@[^[:space:];]+|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)' /etc/rsyslog.conf $(ls -d /etc/rsyslog.d/*.conf 2>/dev/null) /dev/null 2>/dev/null | grep -q .; then
	sec_audit_report_pass 266 "rsyslog forwards to remote host (@@/@ action present)"
else
	sec_audit_report_fail 266 "rsyslog remote log host forwarding not configured"
fi

fi
if secaudit_rule_enabled 267; then
if ! rpm -q rsyslog &>/dev/null; then
    sec_audit_report_pass 267 "rsyslog is not installed (TLS driver not required)"
elif rpm -q rsyslog-gnutls &>/dev/null || rpm -q rsyslog-openssl &>/dev/null; then
    sec_audit_report_pass 267 "a rsyslog TLS network stream driver is installed"
else
    sec_audit_report_fail 267 "neither rsyslog-gnutls nor rsyslog-openssl is installed"
fi

fi
if secaudit_rule_enabled 268; then
if ! rpm -q rsyslog &>/dev/null; then
    sec_audit_report_pass 268 "rsyslog is not installed (TLS forwarding not applicable)"
elif grep -Phsi -- '(driver\h*=\h*"?(gtls|ossl)|StreamDriver\h*=\h*"?(gtls|ossl))' /etc/rsyslog.conf $(ls -d /etc/rsyslog.d/*.conf 2>/dev/null) /dev/null 2>/dev/null | grep -q . \
     && grep -Phsi -- 'StreamDriver\.Mode\h*=\h*"?1|\$DefaultNetstreamDriverCertFile|DefaultNetstreamDriverCAFile' /etc/rsyslog.conf $(ls -d /etc/rsyslog.d/*.conf 2>/dev/null) /dev/null 2>/dev/null | grep -q .; then
    sec_audit_report_pass 268 "rsyslog network forwarding uses a TLS stream driver in TLS-only mode"
else
    sec_audit_report_fail 268 "rsyslog forwarding is not configured to use TLS"
fi

fi
if secaudit_rule_enabled 269; then
if ! rpm -q rsyslog &>/dev/null; then
    sec_audit_report_pass 269 "rsyslog is not installed (TLS CA not applicable)"
elif grep -Phsi -- '(DefaultNetstreamDriverCAFile|StreamDriver\.CAFile)' /etc/rsyslog.conf $(ls -d /etc/rsyslog.d/*.conf 2>/dev/null) /dev/null 2>/dev/null | grep -q .; then
    sec_audit_report_pass 269 "rsyslog TLS CA certificate is configured"
else
    sec_audit_report_fail 269 "no DefaultNetstreamDriverCAFile/StreamDriver.CAFile configured"
fi

fi
if secaudit_rule_enabled 270; then
if ! rpm -q rsyslog &>/dev/null; then
    sec_audit_report_pass 270 "rsyslog is not installed (TLS client certificate not applicable)"
elif grep -Phsi -- '(DefaultNetstreamDriverCertFile|StreamDriver\.CertFile)' /etc/rsyslog.conf $(ls -d /etc/rsyslog.d/*.conf 2>/dev/null) /dev/null 2>/dev/null | grep -q . \
     && grep -Phsi -- '(DefaultNetstreamDriverKeyFile|StreamDriver\.KeyFile)' /etc/rsyslog.conf $(ls -d /etc/rsyslog.d/*.conf 2>/dev/null) /dev/null 2>/dev/null | grep -q .; then
    sec_audit_report_pass 270 "rsyslog TLS client certificate and key are configured"
else
    sec_audit_report_fail 270 "rsyslog TLS client certificate or key is not configured"
fi

fi
if secaudit_rule_enabled 271; then
if command -v logrotate &>/dev/null; then
    if [ -f /etc/logrotate.conf ] && grep -q "^rotate\|^daily\|^weekly\|^monthly" /etc/logrotate.conf 2>/dev/null; then
        sec_audit_report_pass 271 "rsyslog logrotate is configured"
    else
        sec_audit_report_fail 271 "rsyslog logrotate is not properly configured"
    fi
else
    sec_audit_report_fail 271 "logrotate is not installed"
fi

fi
if secaudit_rule_enabled 272; then
FAIL_272=0
for logfile in /var/log/messages /var/log/secure /var/log/maillog /var/log/cron /var/log/boot.log; do
    if [ -f "$logfile" ]; then
        PERM=$(stat -c '%a' "$logfile" 2>/dev/null)
        OWNER=$(stat -c '%U' "$logfile" 2>/dev/null)
        if [ "$PERM" -gt 640 ] 2>/dev/null || [ "$OWNER" != "root" ]; then
            sec_audit_report_fail 272 "$logfile has insecure permissions ($PERM) or owner ($OWNER)"
            FAIL_272=1
        fi
    fi
done
[ $FAIL_272 -eq 0 ] && sec_audit_report_pass 272 "Access to all logfiles has been configured"

fi
if secaudit_rule_enabled 273; then
if rpm -q audit audit-libs &>/dev/null; then
    sec_audit_report_pass 273 "auditd packages are installed"
else
    sec_audit_report_fail 273 "audit audit-libs packages are not installed"
fi

fi
if secaudit_rule_enabled 274; then
if grep -Pq '\baudit=1\b' /proc/cmdline 2>/dev/null; then
	sec_audit_report_pass 274 "audit=1 on kernel command line"
elif grep -q -Prs '\baudit=1\b' /etc/default/grub /boot/grub2/grubenv 2>/dev/null; then
	sec_audit_report_pass 274 "audit=1 configured in bootloader/grub"
else
	sec_audit_report_fail 274 "audit=1 not set for processes prior to auditd"
fi

fi
if secaudit_rule_enabled 275; then
if grep -Psoi '^\h*GRUB_CMDLINE_LINUX=\"([^#\n\r]+\h+)?\baudit_backlog_limit=\d+\b' /etc/default/grub 2>/dev/null; then
    sec_audit_report_pass 275 "audit_backlog_limit is configured"
else
    sec_audit_report_fail 275 "audit_backlog_limit is not set appropriately in audit rules or sysctl"
fi

fi
if secaudit_rule_enabled 276; then
if systemctl is-enabled auditd 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active auditd 2>/dev/null | grep -q 'active'; then
        sec_audit_report_pass 276 "auditd service is enabled and active"
    else
        sec_audit_report_fail 276 "auditd is not enabled or not active"
    fi
else
    sec_audit_report_fail 276 "auditd is not enabled or not active"
fi

fi
if secaudit_rule_enabled 277; then
if grep -Po '^\h*max_log_file\h*=\h*\d+\b' /etc/audit/auditd.conf 2>/dev/null; then
    sec_audit_report_pass 277 "audit log storage size is configured"
else
    sec_audit_report_fail 277 "max_log_file or rotation policy in auditd.conf does not meet policy"
fi

fi
if secaudit_rule_enabled 278; then
if grep -Pi '^\h*max_log_file_action\h*=\h*keep_logs\b' /etc/audit/auditd.conf 2>/dev/null; then
    sec_audit_report_pass 278 "audit logs are not automatically deleted"
else
    sec_audit_report_fail 278 "max_log_file_action or keep_logs policy allows silent deletion"
fi

fi
if secaudit_rule_enabled 279; then
if grep -P '^\h*disk_full_action\h*=\h*(halt|single)\b' /etc/audit/auditd.conf 2>/dev/null; then
    if grep -P '^\h*disk_error_action\h*=\h*(syslog|single|halt)\b' /etc/audit/auditd.conf 2>/dev/null; then
        sec_audit_report_pass 279 "system is disabled when audit logs are full"
    else
        sec_audit_report_fail 279 "disk_full_action / space_left_action in auditd.conf does not meet policy"
    fi
else
    sec_audit_report_fail 279 "disk_full_action / space_left_action in auditd.conf does not meet policy"
fi

fi
if secaudit_rule_enabled 280; then
if grep -P '^\h*space_left_action\h*=\h*(email|exec|single|halt)\b' /etc/audit/auditd.conf 2>/dev/null; then
    if grep -P '^\h*admin_space_left_action\h*=\h*(single|halt)\b' /etc/audit/auditd.conf 2>/dev/null; then
        sec_audit_report_pass 280 "system warns when audit logs are low on space"
    else
        sec_audit_report_fail 280 "space_left_action / admin_space_left_action in auditd.conf are incomplete"
    fi
else
    sec_audit_report_fail 280 "space_left_action / admin_space_left_action in auditd.conf are incomplete"
fi

fi
if secaudit_rule_enabled 281; then
if sec_audit_audit_rule_loaded_and_on_disk -q "path=/etc/sudoers"; then
    if sec_audit_audit_rule_loaded_and_on_disk -q "dir=/etc/sudoers.d"; then
        sec_audit_report_pass 281 "sudoers and sudoers.d watch rules present in audit.rules and loaded in kernel"
    else
        sec_audit_report_fail 281 "/etc/sudoers.d directory watch missing on disk or not loaded"
    fi
else
    sec_audit_report_fail 281 "/etc/sudoers file watch missing on disk or not loaded"
fi

fi
if secaudit_rule_enabled 282; then
if sec_audit_audit_rule_loaded_and_on_disk -q "execve"; then
    sec_audit_report_pass 282 "execve auditing present on disk and loaded"
else
    sec_audit_report_fail 282 "actions as another user are not always logged (execve audit rule missing or not loaded)"
fi

fi
if secaudit_rule_enabled 283; then
if [ -f /var/log/sudo.log ]; then
    if sec_audit_audit_rule_loaded_and_on_disk -q "path=/var/log/sudo.log"; then
        sec_audit_report_pass 283 "audit rule for /var/log/sudo.log on disk and loaded"
    else
        sec_audit_report_fail 283 "events that modify the sudo log file are not collected (audit watch for /var/log/sudo.log missing or not loaded)"
    fi
else
    sec_audit_report_fail 283 "events that modify the sudo log file are not collected (/var/log/sudo.log not found)"
fi

fi
if secaudit_rule_enabled 284; then
if sec_audit_audit_rule_disk_or_loaded "adjtimex" && sec_audit_audit_rule_disk_or_loaded "settimeofday" && sec_audit_audit_rule_disk_or_loaded "clock_settime"; then
	sec_audit_report_pass 284 "audit rules present for policy check"
else
	sec_audit_report_fail 284 "required audit rules missing on disk or not loaded"
fi

fi
if secaudit_rule_enabled 285; then
if sec_audit_audit_rule_loaded_and_on_disk -q "sethostname" && sec_audit_audit_rule_loaded_and_on_disk -q "setdomainname"; then
    sec_audit_report_pass 285 "sethostname/setdomainname audit rules on disk and loaded"
else
    sec_audit_report_fail 285 "sethostname/setdomainname audit rules missing on disk or not loaded"
fi

fi
if secaudit_rule_enabled 286; then
if sec_audit_audit_rule_loaded_and_on_disk -q "path=/etc/issue" && sec_audit_audit_rule_loaded_and_on_disk -q "path=/etc/issue.net"; then
    sec_audit_report_pass 286 "/etc/issue and /etc/issue.net watches on disk and loaded"
else
    sec_audit_report_fail 286 "issue/issue.net audit watches missing on disk or not loaded"
fi

fi
if secaudit_rule_enabled 287; then
if sec_audit_audit_rule_loaded_and_on_disk -q "path=/etc/hosts" && sec_audit_audit_rule_loaded_and_on_disk -q "path=/etc/hostname"; then
    sec_audit_report_pass 287 "/etc/hosts and /etc/hostname watches on disk and loaded"
else
    sec_audit_report_fail 287 "hosts/hostname audit watches missing on disk or not loaded"
fi

fi
if secaudit_rule_enabled 288; then
if sec_audit_audit_rule_loaded_and_on_disk -q "path=/etc/sysconfig/network" && sec_audit_audit_rule_loaded_and_on_disk -q "dir=/etc/NetworkManager/system-connections"; then
    sec_audit_report_pass 288 "network configuration watches on disk and loaded"
else
    sec_audit_report_fail 288 "sysconfig/network or NetworkManager connections audit watches missing"
fi

fi
if secaudit_rule_enabled 289; then
if sec_audit_audit_rule_loaded_and_on_disk -q "dir=/etc/NetworkManager/"; then
    sec_audit_report_pass 289 "NetworkManager directory watch on disk and loaded"
else
    sec_audit_report_fail 289 "events that modify /etc/NetworkManager directory are not collected"
fi

fi
if secaudit_rule_enabled 290; then
if sec_audit_audit_rule_disk_or_loaded "/usr/bin/sudo" && sec_audit_audit_rule_disk_or_loaded "/usr/bin/su"; then
	sec_audit_report_pass 290 "audit rules present for policy check"
else
	sec_audit_report_fail 290 "required audit rules missing on disk or not loaded"
fi

fi
if secaudit_rule_enabled 291; then
if sec_audit_audit_rule_disk_or_loaded "EACCES" && sec_audit_audit_rule_disk_or_loaded "EPERM"; then
	sec_audit_report_pass 291 "audit rules present for policy check"
else
	sec_audit_report_fail 291 "required audit rules missing on disk or not loaded"
fi

fi
if secaudit_rule_enabled 292; then
if sec_audit_audit_rule_loaded_and_on_disk -q "path=/etc/group"; then
    sec_audit_report_pass 292 "/etc/group watch on disk and loaded"
else
    sec_audit_report_fail 292 "/etc/group audit watch missing on disk or not loaded"
fi

fi
if secaudit_rule_enabled 293; then
if sec_audit_audit_rule_loaded_and_on_disk -q "path=/etc/passwd"; then
    sec_audit_report_pass 293 "/etc/passwd watch on disk and loaded"
else
    sec_audit_report_fail 293 "/etc/passwd audit watch missing on disk or not loaded"
fi

fi
if secaudit_rule_enabled 294; then
if sec_audit_audit_rule_loaded_and_on_disk -q "path=/etc/shadow"; then
    if sec_audit_audit_rule_loaded_and_on_disk -q "path=/etc/gshadow"; then
        sec_audit_report_pass 294 "shadow and gshadow watches on disk and loaded"
    else
        sec_audit_report_fail 294 "events that modify /etc/gshadow are not collected (watch missing on disk or not loaded)"
    fi
else
    sec_audit_report_fail 294 "events that modify /etc/shadow are not collected (watch missing on disk or not loaded)"
fi

fi
if secaudit_rule_enabled 295; then
if sec_audit_audit_rule_loaded_and_on_disk -q "path=/etc/security/opasswd"; then
    sec_audit_report_pass 295 "/etc/security/opasswd watch on disk and loaded"
else
    sec_audit_report_fail 295 "/etc/security/opasswd audit watch missing on disk or not loaded"
fi

fi
if secaudit_rule_enabled 296; then
if sec_audit_audit_rule_loaded_and_on_disk -q "path=/etc/nsswitch.conf"; then
    sec_audit_report_pass 296 "/etc/nsswitch.conf watch on disk and loaded"
else
    sec_audit_report_fail 296 "/etc/nsswitch.conf audit watch missing on disk or not loaded"
fi

fi
if secaudit_rule_enabled 297; then
if sec_audit_audit_rule_loaded_and_on_disk -q "path=/etc/pam.conf" && sec_audit_audit_rule_loaded_and_on_disk -q "dir=/etc/pam.d"; then
    sec_audit_report_pass 297 "PAM configuration watches on disk and loaded"
else
    sec_audit_report_fail 297 "pam.conf/pam.d audit watches missing on disk or not loaded"
fi

fi
if secaudit_rule_enabled 298; then
if sec_audit_audit_rule_loaded_and_on_disk -q "chmod" && sec_audit_audit_rule_loaded_and_on_disk -q "fchmodat"; then
    sec_audit_report_pass 298 "chmod/fchmod/fchmodat events are collected"
else
    sec_audit_report_fail 298 "chmod/fchmod/fchmodat audit rules missing on disk or not loaded"
fi

fi
if secaudit_rule_enabled 299; then
if sec_audit_audit_rule_loaded_and_on_disk -q "chown" && sec_audit_audit_rule_loaded_and_on_disk -q "fchownat"; then
    sec_audit_report_pass 299 "chown/fchown/lchown/fchownat events are collected"
else
    sec_audit_report_fail 299 "chown/fchown/lchown/fchownat audit rules missing on disk or not loaded"
fi

fi
if secaudit_rule_enabled 300; then
if sec_audit_audit_rule_loaded_and_on_disk -q "setxattr" && sec_audit_audit_rule_loaded_and_on_disk -q "fremovexattr"; then
    sec_audit_report_pass 300 "extended attribute modification events are collected"
else
    sec_audit_report_fail 300 "setxattr/lsetxattr/fsetxattr/removexattr audit rules missing on disk or not loaded"
fi

fi
if secaudit_rule_enabled 301; then
if sec_audit_audit_rule_loaded_and_on_disk -q "mount"; then
    sec_audit_report_pass 301 "mount syscall auditing on disk and loaded"
else
    sec_audit_report_fail 301 "successful file system mounts are not collected"
fi

fi
if secaudit_rule_enabled 302; then
if sec_audit_audit_rule_loaded_and_on_disk -E -q 'utmp|wtmp|btmp'; then
    sec_audit_report_pass 302 "session initiation (utmp/wtmp/btmp) auditing on disk and loaded"
else
    sec_audit_report_fail 302 "session initiation information is not collected"
fi

fi
if secaudit_rule_enabled 303; then
if sec_audit_audit_rule_disk_or_loaded "lastlog" && sec_audit_audit_rule_disk_or_loaded "faillock" && sec_audit_audit_rule_disk_or_loaded "/var/run/utmp"; then
	sec_audit_report_pass 303 "audit rules present for policy check"
else
	sec_audit_report_fail 303 "required audit rules missing on disk or not loaded"
fi

fi
if secaudit_rule_enabled 304; then
if sec_audit_audit_rule_loaded_and_on_disk -q "unlink"; then
    sec_audit_report_pass 304 "unlink auditing on disk and loaded"
else
    sec_audit_report_fail 304 "unlink file deletion events by users are not collected"
fi

fi
if secaudit_rule_enabled 305; then
if sec_audit_audit_rule_loaded_and_on_disk -q "rename"; then
    sec_audit_report_pass 305 "rename file deletion events are collected"
else
    sec_audit_report_fail 305 "rename audit rules missing on disk or not loaded"
fi

fi
if secaudit_rule_enabled 306; then
if sec_audit_audit_rule_loaded_and_on_disk -q "MAC_POLICY_LOAD"; then
    sec_audit_report_pass 306 "MAC policy modification events are collected"
else
    sec_audit_report_fail 306 "MAC_POLICY_LOAD audit rules missing on disk or not loaded"
fi

fi
if secaudit_rule_enabled 307; then
if sec_audit_audit_rule_loaded_and_on_disk -q "/usr/bin/chcon"; then
    sec_audit_report_pass 307 "chcon command attempts are collected"
else
    sec_audit_report_fail 307 "chcon audit rules missing on disk or not loaded"
fi

fi
if secaudit_rule_enabled 308; then
if sec_audit_audit_rule_loaded_and_on_disk -q "/usr/bin/setfacl"; then
    sec_audit_report_pass 308 "setfacl command attempts are collected"
else
    sec_audit_report_fail 308 "setfacl audit rules missing on disk or not loaded"
fi

fi
if secaudit_rule_enabled 309; then
if sec_audit_audit_rule_loaded_and_on_disk -q "/usr/bin/chacl"; then
    sec_audit_report_pass 309 "chacl command attempts are collected"
else
    sec_audit_report_fail 309 "chacl audit rules missing on disk or not loaded"
fi

fi
if secaudit_rule_enabled 310; then
if sec_audit_audit_rule_loaded_and_on_disk -q "/usr/sbin/usermod"; then
    sec_audit_report_pass 310 "usermod command attempts are collected"
else
    sec_audit_report_fail 310 "usermod audit rules missing on disk or not loaded"
fi

fi
if secaudit_rule_enabled 311; then
if sec_audit_audit_rule_loaded_and_on_disk -q "init_module"; then
    sec_audit_report_pass 311 "init_module auditing on disk and loaded"
else
    sec_audit_report_fail 311 "kernel module loading unloading and modification is not collected"
fi

fi
if secaudit_rule_enabled 312; then
if sec_audit_audit_rule_loaded_and_on_disk -q "init_module" && sec_audit_audit_rule_loaded_and_on_disk -q "finit_module"; then
    sec_audit_report_pass 312 "init_module/finit_module auditing on disk and loaded"
else
    sec_audit_report_fail 312 "init_module/finit_module audit rules missing on disk or not loaded"
fi

fi
if secaudit_rule_enabled 313; then
if sec_audit_audit_rule_loaded_and_on_disk -q "delete_module"; then
    sec_audit_report_pass 313 "delete_module auditing on disk and loaded"
else
    sec_audit_report_fail 313 "delete_module audit rules missing on disk or not loaded"
fi

fi
if secaudit_rule_enabled 314; then
if sec_audit_audit_rules_files_grep -q -- '-D' || sec_audit_audit_rules_files_grep -q -- '-f'; then
    sec_audit_report_pass 314 "audit configuration load-on-error / continue policy present on disk"
else
    sec_audit_report_fail 314 "audit rules do not continue loading after errors (-D/-f)"
fi

fi
if secaudit_rule_enabled 315; then
if sec_audit_audit_rule_disk_or_loaded "-e 2"; then
	sec_audit_report_pass 315 "audit rules present for policy check"
else
	sec_audit_report_fail 315 "required audit rules missing on disk or not loaded"
fi

fi
if secaudit_rule_enabled 316; then
if augenrules --check 2>/dev/null | grep -q "No change"; then
    sec_audit_report_pass 316 "the running and on disk configuration is the same"
else
    sec_audit_report_fail 316 "Loaded audit rules differ from on-disk rules (augenrules --check)"
fi

fi
if secaudit_rule_enabled 317; then
if [ -f /etc/audit/auditd.conf ]; then
    LOG_DIR=$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")
    if [ -d "$LOG_DIR" ]; then
        if stat -Lc '%a' "$LOG_DIR" 2>/dev/null | grep -qE '^750$'; then
            sec_audit_report_pass 317 "the audit log file directory mode is configured"
        else
            sec_audit_report_fail 317 "Audit log directory mode is not 750 or directory missing"
        fi
    else
        sec_audit_report_fail 317 "Audit log directory mode is not 750 or directory missing"
    fi
else
    sec_audit_report_fail 317 "Audit log directory mode is not 750 or directory missing"
fi

fi
if secaudit_rule_enabled 318; then
if [ -f /etc/audit/auditd.conf ]; then
    LOG_DIR=$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")
    if [ -d "$LOG_DIR" ]; then
        if sec_audit_low_impact_find --timeout=10 "$LOG_DIR" -xdev -ignore_readdir_race -maxdepth 1 -type f -perm /0137 2>/dev/null | grep -q '.'; then
            sec_audit_report_fail 318 "One or more audit log files have overly permissive modes"
        else
            sec_audit_report_pass 318 "audit log files mode is configured"
        fi
    else
        sec_audit_report_fail 318 "One or more audit log files have overly permissive modes"
    fi
else
    sec_audit_report_fail 318 "One or more audit log files have overly permissive modes"
fi

fi
if secaudit_rule_enabled 319; then
if [ -f /etc/audit/auditd.conf ]; then
    LOG_DIR=$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")
    if [ -d "$LOG_DIR" ]; then
        if sec_audit_low_impact_find --timeout=10 "$LOG_DIR" -xdev -ignore_readdir_race -maxdepth 1 -type f ! -user root 2>/dev/null | grep -q '.'; then
            sec_audit_report_fail 319 "One or more audit log files are not owned by root"
        else
            sec_audit_report_pass 319 "audit log files owner is configured"
        fi
    else
        sec_audit_report_fail 319 "One or more audit log files are not owned by root"
    fi
else
    sec_audit_report_fail 319 "One or more audit log files are not owned by root"
fi

fi
if secaudit_rule_enabled 320; then
if [ -f /etc/audit/auditd.conf ]; then
    LOG_DIR=$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")
    LOG_GROUP=$(awk -F= '/^\s*log_group\s*/{print $2}' /etc/audit/auditd.conf | xargs)
    if [ "$LOG_GROUP" = "root" ] || [ "$LOG_GROUP" = "adm" ]; then
        if [ -d "$LOG_DIR" ]; then
            if sec_audit_low_impact_find --timeout=10 "$LOG_DIR" -xdev -ignore_readdir_race -maxdepth 1 -type f \( ! -group root -a ! -group adm \) 2>/dev/null | grep -q '.'; then
                sec_audit_report_fail 320 "Audit log files group ownership does not match log_group policy"
            else
                sec_audit_report_pass 320 "audit log files group owner is configured"
            fi
        else
            sec_audit_report_fail 320 "Audit log files group ownership does not match log_group policy"
        fi
    else
        sec_audit_report_fail 320 "Audit log files group ownership does not match log_group policy"
    fi
else
    sec_audit_report_fail 320 "Audit log files group ownership does not match log_group policy"
fi

fi
if secaudit_rule_enabled 321; then
if sec_audit_low_impact_find --timeout=10 /etc/audit/ -xdev -ignore_readdir_race -type f \( -name "*.conf" -o -name '*.rules' \) -perm /0137 2>/dev/null | grep -q '.'; then
    sec_audit_report_fail 321 "Audit .conf/.rules files have insecure permissions"
else
    sec_audit_report_pass 321 "audit configuration files mode is configured"
fi

fi
if secaudit_rule_enabled 322; then
if sec_audit_low_impact_find --timeout=10 /etc/audit/ -xdev -ignore_readdir_race -type f \( -name "*.conf" -o -name '*.rules' \) ! -user root 2>/dev/null | grep -q '.'; then
    sec_audit_report_fail 322 "Audit configuration files are not owned as required"
else
    sec_audit_report_pass 322 "audit configuration files owner is configured"
fi

fi
if secaudit_rule_enabled 323; then
if sec_audit_low_impact_find --timeout=10 /etc/audit/ -xdev -ignore_readdir_race -type f \( -name "*.conf" -o -name '*.rules' \) ! -group root 2>/dev/null | grep -q '.'; then
    sec_audit_report_fail 323 "Audit configuration files group ownership does not meet policy"
else
    sec_audit_report_pass 323 "audit configuration files group owner is configured"
fi

fi
if secaudit_rule_enabled 324; then
FAIL_324=0
for tool in /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules; do
    if [ -f "$tool" ]; then
        if [ $(( $(stat -Lc '%#a' "$tool" 2>/dev/null) & 0022 )) -gt 0 ]; then
            FAIL_324=1
        fi
    fi
done
if [ $FAIL_324 -eq 0 ]; then
    sec_audit_report_pass 324 "audit tools mode is configured"
else
    sec_audit_report_fail 324 "One or more /sbin/audit* tools have insecure permissions"
fi

fi
if secaudit_rule_enabled 325; then
FAIL_325=0
for tool in /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules; do
    if [ -f "$tool" ]; then
        if [ "$(stat -Lc '%U' "$tool" 2>/dev/null)" != "root" ]; then
            FAIL_325=1
        fi
    fi
done
if [ $FAIL_325 -eq 0 ]; then
    sec_audit_report_pass 325 "audit tools owner is configured"
else
    sec_audit_report_fail 325 "One or more /sbin/audit* tools are not owned by root"
fi

fi
if secaudit_rule_enabled 326; then
FAIL_326=0
for tool in /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules; do
    if [ -f "$tool" ]; then
        if [ "$(stat -Lc '%G' "$tool" 2>/dev/null)" != "root" ]; then
            FAIL_326=1
        fi
    fi
done
if [ $FAIL_326 -eq 0 ]; then
    sec_audit_report_pass 326 "audit tools group owner is configured"
else
    sec_audit_report_fail 326 "One or more /sbin/audit* tools have incorrect group ownership"
fi

fi
if secaudit_rule_enabled 327; then
if rpm -q aide &>/dev/null; then
    _a207_db=""
    if [ -f /var/lib/aide/aide.db.gz ] || [ -f /var/lib/aide/aide.db ]; then
        _a207_db="; AIDE database file present under /var/lib/aide"
    else
        _a207_db="; WARNING: no AIDE database under /var/lib/aide (initialize with aide --init)"
    fi
    sec_audit_report_pass 327 "AIDE package is installed${_a207_db}"
else
    sec_audit_report_fail 327 "AIDE package is not installed"
fi

fi
if secaudit_rule_enabled 328; then
if grep -Ers '^([^#]+\s+)?(\/usr\/s?bin\/|^\s*)aide(\.wrapper)?\s(--?\S+\s)*(-(check|update)|\$AIDEARGS)\b' $(ls -d /etc/cron.* 2>/dev/null) /etc/crontab /var/spool/cron/ /etc/cron.d /dev/null 2>/dev/null; then
    sec_audit_report_pass 328 "filesystem integrity is regularly checked (cron/cron.d entry references aide)"
elif systemctl is-enabled aidecheck.timer 2>/dev/null | grep -q 'enabled'; then
    if systemctl is-active aidecheck.timer 2>/dev/null | grep -q 'active'; then
        _a208_n=$(systemctl show aidecheck.timer -p NextElapseUSRealtime 2>/dev/null | cut -d= -f2-)
        sec_audit_report_pass 328 "aidecheck.timer enabled and active (next: ${_a208_n:-unknown})"
    else
        sec_audit_report_fail 328 "aidecheck.timer enabled but not active"
    fi
else
    sec_audit_report_fail 328 "filesystem integrity is regularly checked"
fi

fi
if secaudit_rule_enabled 329; then
if ! rpm -q aide &>/dev/null; then
	sec_audit_report_fail 329 "AIDE not installed; cannot verify integrity of audit tools"
elif ! [ -f /etc/aide.conf ]; then
	sec_audit_report_fail 329 "/etc/aide.conf missing"
elif grep -qE '/sbin/(audit|auditctl|ausearch|aureport|autrace|auid)' /etc/aide.conf 2>/dev/null || \
     grep -qE '/usr/sbin/(audit|auditctl|ausearch|aureport|autrace)' /etc/aide.conf 2>/dev/null; then
	sec_audit_report_pass 329 "AIDE configuration references audit tool paths"
else
	sec_audit_report_fail 329 "AIDE does not monitor audit binaries in /etc/aide.conf"
fi

fi
if secaudit_rule_enabled 330; then
if ! rpm -q aide &>/dev/null; then
    sec_audit_report_fail 330 "AIDE is not installed"
elif grep -P -- '^\h*report_url\h*=\h*syslog:' /etc/aide.conf 2>/dev/null | grep -q .; then
    sec_audit_report_pass 330 "AIDE report_url is configured to send reports to syslog"
else
    sec_audit_report_fail 330 "AIDE report_url does not resolve to a syslog: destination"
fi

fi
}

sec_audit_run_accounts() {
if secaudit_rule_enabled 331; then
if stat -Lc '%a' /etc/passwd 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' /etc/passwd 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 331 "access to /etc/passwd is configured"
    else
        sec_audit_report_fail 331 "File /etc/passwd permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 331 "File /etc/passwd permissions or ownership not correct"
fi

fi
if secaudit_rule_enabled 332; then
if [ -e /etc/passwd- ]; then
    if stat -Lc '%a' /etc/passwd- 2>/dev/null | grep -qE '^[0-6]44$'; then
        if stat -Lc '%U:%G' /etc/passwd- 2>/dev/null | grep -q '^root:root$'; then
            sec_audit_report_pass 332 "access to /etc/passwd- is configured"
        else
            sec_audit_report_fail 332 "File /etc/passwd- permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 332 "File /etc/passwd- permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 332 "/etc/passwd- is absent (optional file; permission check skipped)"
fi

fi
if secaudit_rule_enabled 333; then
if stat -Lc '%a' /etc/group 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' /etc/group 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 333 "access to /etc/group is configured"
    else
        sec_audit_report_fail 333 "File /etc/group permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 333 "File /etc/group permissions or ownership not correct"
fi

fi
if secaudit_rule_enabled 334; then
if [ -e /etc/group- ]; then
    if stat -Lc '%a' /etc/group- 2>/dev/null | grep -qE '^[0-6]44$'; then
        if stat -Lc '%U:%G' /etc/group- 2>/dev/null | grep -q '^root:root$'; then
            sec_audit_report_pass 334 "access to /etc/group- is configured"
        else
            sec_audit_report_fail 334 "File /etc/group- permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 334 "File /etc/group- permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 334 "/etc/group- is absent (optional file; permission check skipped)"
fi

fi
if secaudit_rule_enabled 335; then
if stat -Lc '%a' /etc/shadow 2>/dev/null | grep -qE '^[0-6]40$'; then
    if stat -Lc '%U' /etc/shadow 2>/dev/null | grep -q 'root'; then
        if stat -Lc '%G' /etc/shadow 2>/dev/null | grep -qE 'root|shadow'; then
            sec_audit_report_pass 335 "access to /etc/shadow is configured"
        else
            sec_audit_report_fail 335 "File /etc/shadow permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 335 "File /etc/shadow permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 335 "File /etc/shadow permissions or ownership not correct"
fi

fi
if secaudit_rule_enabled 336; then
if [ -e /etc/shadow- ]; then
    if stat -Lc '%a' /etc/shadow- 2>/dev/null | grep -qE '^[0-6]40$'; then
        if stat -Lc '%U' /etc/shadow- 2>/dev/null | grep -q 'root'; then
            if stat -Lc '%G' /etc/shadow- 2>/dev/null | grep -qE 'root|shadow'; then
                sec_audit_report_pass 336 "access to /etc/shadow- is configured"
            else
                sec_audit_report_fail 336 "File /etc/shadow- permissions or ownership not correct"
            fi
        else
            sec_audit_report_fail 336 "File /etc/shadow- permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 336 "File /etc/shadow- permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 336 "/etc/shadow- is absent (optional file; permission check skipped)"
fi

fi
if secaudit_rule_enabled 337; then
if [ -e /etc/gshadow ]; then
    if stat -Lc '%a' /etc/gshadow 2>/dev/null | grep -qE '^[0-6]40$'; then
        if stat -Lc '%U' /etc/gshadow 2>/dev/null | grep -q 'root'; then
            if stat -Lc '%G' /etc/gshadow 2>/dev/null | grep -qE 'root|shadow'; then
                sec_audit_report_pass 337 "access to /etc/gshadow is configured"
            else
                sec_audit_report_fail 337 "File /etc/gshadow permissions or ownership not correct"
            fi
        else
            sec_audit_report_fail 337 "File /etc/gshadow permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 337 "File /etc/gshadow permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 337 "/etc/gshadow is absent (optional file; permission check skipped)"
fi

fi
if secaudit_rule_enabled 338; then
if [ -e /etc/gshadow- ]; then
    if stat -Lc '%a' /etc/gshadow- 2>/dev/null | grep -qE '^[0-6]40$'; then
        if stat -Lc '%U' /etc/gshadow- 2>/dev/null | grep -q 'root'; then
            if stat -Lc '%G' /etc/gshadow- 2>/dev/null | grep -qE 'root|shadow'; then
                sec_audit_report_pass 338 "access to /etc/gshadow- is configured"
            else
                sec_audit_report_fail 338 "File /etc/gshadow- permissions or ownership not correct"
            fi
        else
            sec_audit_report_fail 338 "File /etc/gshadow- permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 338 "File /etc/gshadow- permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 338 "/etc/gshadow- is absent (optional file; permission check skipped)"
fi

fi
if secaudit_rule_enabled 339; then
if stat -Lc '%a' /etc/shells 2>/dev/null | grep -qE '^[0-6]44$'; then
    if stat -Lc '%U:%G' /etc/shells 2>/dev/null | grep -q '^root:root$'; then
        sec_audit_report_pass 339 "access to /etc/shells is configured"
    else
        sec_audit_report_fail 339 "File /etc/shells permissions or ownership not correct"
    fi
else
    sec_audit_report_fail 339 "File /etc/shells permissions or ownership not correct"
fi

fi
if secaudit_rule_enabled 340; then
if [ -e /etc/security/opasswd ]; then
    if stat -Lc '%a' /etc/security/opasswd 2>/dev/null | grep -q '^600$'; then
        if stat -Lc '%U:%G' /etc/security/opasswd 2>/dev/null | grep -q '^root:root$'; then
            sec_audit_report_pass 340 "access to /etc/security/opasswd is configured"
        else
            sec_audit_report_fail 340 "File /etc/security/opasswd permissions or ownership not correct"
        fi
    else
        sec_audit_report_fail 340 "File /etc/security/opasswd permissions or ownership not correct"
    fi
else
    sec_audit_report_pass 340 "/etc/security/opasswd is absent (optional file; permission check skipped)"
fi

fi
if secaudit_rule_enabled 341; then
CRITICAL_PATHS="/bin /sbin /usr/bin /usr/sbin /etc /var /home"
WW_FILES=$(sec_audit_low_impact_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type f -perm -0002 -print 2>/dev/null | wc -l)
WW_DIRS=$(sec_audit_low_impact_find --timeout=10 $CRITICAL_PATHS -xdev -ignore_readdir_race -maxdepth 2 -type d -perm -0002 -print 2>/dev/null | wc -l)
if [ $WW_FILES -eq 0 ] && [ $WW_DIRS -eq 0 ]; then
    sec_audit_report_pass 341 "No critical world writable files or directories found"
else
    sec_audit_report_fail 341 "Found potential world-writable items ($WW_FILES files, $WW_DIRS dirs)"
fi

fi
if secaudit_rule_enabled 342; then
_orph=$(sec_audit_low_impact_find --timeout=120 $(sec_audit_safe_find_roots | tr '\n' ' ') -xdev \( -nouser -o -nogroup \) 2>/dev/null | head -n 5)
if [[ -z "$_orph" ]]; then
	sec_audit_report_pass 342 "no unowned/ungrouped files found on local filesystems"
else
	sec_audit_report_fail 342 "unowned or ungrouped objects found (sample): $(echo "$_orph" | tr '\n' ';')"
fi

fi
if secaudit_rule_enabled 343; then
SPECIAL_COUNTS=$(
    while IFS= read -r mount_point; do
        [ -d "$mount_point" ] || continue
        sec_audit_low_impact_find --timeout=120 "$mount_point" -xdev -ignore_readdir_race -type f -perm /6000 -printf '%m\n' 2>/dev/null
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
    sec_audit_report_review 343 "SUID and SGID files found ($SUID_FILES SUID, $SGID_FILES SGID). Please review manually."
else
    sec_audit_report_pass 343 "No SUID or SGID files found"
fi

fi
if secaudit_rule_enabled 344; then
if awk -F: '($2 != "x" ) { print }' /etc/passwd 2>/dev/null | grep -q '.'; then
    sec_audit_report_fail 344 "Non-shadow password field found in /etc/passwd (second field not "x")"
else
    sec_audit_report_pass 344 "accounts in /etc/passwd use shadowed passwords"
fi

fi
if secaudit_rule_enabled 345; then
if awk -F: '($2 == "" ) { print }' /etc/shadow 2>/dev/null | grep -q '.'; then
    sec_audit_report_fail 345 "Empty password hash found in /etc/shadow"
else
    sec_audit_report_pass 345 "/etc/shadow password fields are not empty"
fi

fi
if secaudit_rule_enabled 346; then
FAIL_346=0
while IFS=: read -r user pass uid gid rest; do
    if ! grep -q "^.*:.*:$gid:" /etc/group 2>/dev/null; then
        sec_audit_report_fail 346 "User $user has primary group GID $gid which does not exist in /etc/group"
        FAIL_346=1
    fi
done < /etc/passwd 2>/dev/null
[ $FAIL_346 -eq 0 ] && sec_audit_report_pass 346 "All groups in /etc/passwd exist in /etc/group"

fi
if secaudit_rule_enabled 347; then
if cut -f3 -d":" /etc/passwd 2>/dev/null | sort -n | uniq -c | while read -r count uid; do [ "$count" -gt 1 ] && echo "found"; done | grep -q "found"; then
    sec_audit_report_fail 347 "Duplicate UID entries exist in /etc/passwd"
else
    sec_audit_report_pass 347 "no duplicate UIDs exist"
fi

fi
if secaudit_rule_enabled 348; then
if cut -f3 -d":" /etc/group 2>/dev/null | sort -n | uniq -c | while read -r count gid; do [ "$count" -gt 1 ] && echo "found"; done | grep -q "found"; then
    sec_audit_report_fail 348 "Duplicate GID entries exist in /etc/group"
else
    sec_audit_report_pass 348 "no duplicate GIDs exist"
fi

fi
if secaudit_rule_enabled 349; then
if cut -f1 -d":" /etc/passwd 2>/dev/null | sort -n | uniq -c | while read -r count user; do [ "$count" -gt 1 ] && echo "found"; done | grep -q "found"; then
    sec_audit_report_fail 349 "Duplicate user names exist in /etc/passwd"
else
    sec_audit_report_pass 349 "no duplicate user names exist"
fi

fi
if secaudit_rule_enabled 350; then
if cut -f1 -d":" /etc/group 2>/dev/null | sort -n | uniq -c | while read -r count group; do [ "$count" -gt 1 ] && echo "found"; done | grep -q "found"; then
    sec_audit_report_fail 350 "Duplicate group names exist in /etc/group"
else
    sec_audit_report_pass 350 "no duplicate group names exist"
fi

fi
if secaudit_rule_enabled 351; then
FAIL_351=0
while IFS=: read -r user _ uid _ _ home shell; do
	[[ "$uid" -ge 1000 && "$uid" -lt 65534 ]] || continue
	[[ -n "$home" && "$home" != "/" ]] || { sec_audit_report_fail 351 "User $user has invalid home"; FAIL_351=1; continue; }
	if [[ ! -d "$home" ]]; then
		sec_audit_report_fail 351 "User $user home $home does not exist"; FAIL_351=1
	elif [[ "$(stat -c '%U' "$home" 2>/dev/null)" != "$user" ]]; then
		sec_audit_report_fail 351 "User $user does not own home $home"; FAIL_351=1
	fi
done < /etc/passwd
[[ $FAIL_351 -eq 0 ]] && sec_audit_report_pass 351 "local interactive user home directories are configured"

fi
if secaudit_rule_enabled 352; then
FAIL_352=0
while IFS=: read -r user pass uid gid rest; do
    if [ "$uid" -ge 1000 ] 2>/dev/null && [ "$uid" -lt 65534 ]; then
        home=$(echo "$rest" | cut -d: -f1)
        for dotfile in "$home/.bashrc" "$home/.bash_profile" "$home/.profile" "$home/.bash_logout"; do
            if [ -f "$dotfile" ]; then
                perm=$(stat -c '%a' "$dotfile" 2>/dev/null)
                if [ "${perm:2:1}" -gt 0 ] 2>/dev/null || [ "${perm:1:1}" -gt 0 ] 2>/dev/null; then
                    sec_audit_report_fail 352 "User $user dot file $dotfile has world/group write permissions ($perm)"
                    FAIL_352=1
                fi
            fi
        done
    fi
done < /etc/passwd 2>/dev/null
[ $FAIL_352 -eq 0 ] && sec_audit_report_pass 352 "Local interactive user dot files access is configured"

fi
}

sec_audit_main() {
    sec_audit_run_initial_setup
    sec_audit_run_services
    sec_audit_run_network
    sec_audit_run_logging_and_auditing
    sec_audit_run_access_control
    sec_audit_run_system_maintenance
    sec_audit_run_accounts
    exit 0
}

sec_audit_main "$@"
