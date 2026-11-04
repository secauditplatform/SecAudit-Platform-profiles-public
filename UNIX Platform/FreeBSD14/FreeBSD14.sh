#!/usr/local/bin/bash

export LC_ALL=C

if [ -z "${BASH_VERSION:-}" ]; then
    if command -v bash >/dev/null 2>&1; then
        exec bash "$0" "$@"
    fi
    printf '%s\n' "ERROR: bash is required." >&2
    exit 1
fi

sec_audit_have_cmd() { command -v "$1" >/dev/null 2>&1; }

sec_audit_report_pass() { printf 'RULE%s= PASS: %s\n' "$1" "$2"; }
sec_audit_report_fail() { printf 'RULE%s= FAIL: %s\n' "$1" "$2"; }
sec_audit_report_review() { printf 'RULE%s= REVIEW: %s\n' "$1" "$2"; }

sec_audit_bsd_mode() {
    local f="$1" m
    [ -e "$f" ] || return 1
    if m=$(stat -c '%a' "$f" 2>/dev/null) && [[ "$m" =~ ^[0-7]+$ ]]; then
        printf '%s' "$m"
        return 0
    fi
    m=$(stat -Lf '%OLp' "$f" 2>/dev/null) || m=$(stat -f '%OLp' "$f" 2>/dev/null) || m=$(stat -Lf '%Lp' "$f" 2>/dev/null)
    printf '%s' "$m" | tr -d ' '
}

sec_audit_bsd_owner() {
    local f="$1" o
    [ -e "$f" ] || return 1
    if o=$(stat -c '%U' "$f" 2>/dev/null) && [ -n "$o" ] && [[ "$o" != *" "* ]]; then
        printf '%s' "$o"
        return 0
    fi
    stat -Lf '%Su' "$f" 2>/dev/null || stat -f '%Su' "$f" 2>/dev/null
}

sec_audit_bsd_group() {
    local f="$1" g
    [ -e "$f" ] || return 1
    if g=$(stat -c '%G' "$f" 2>/dev/null) && [ -n "$g" ] && [[ "$g" != *" "* ]]; then
        printf '%s' "$g"
        return 0
    fi
    stat -Lf '%Sg' "$f" 2>/dev/null || stat -f '%Sg' "$f" 2>/dev/null
}

sec_audit_mode_le() {
    local mode="$1" maxm="$2"
    [[ "$mode" =~ ^[0-7]+$ ]] || return 1
    (( (8#$mode | 8#$maxm) == 8#$maxm ))
}

sec_audit_mode_no_go_write() {
    local mode="$1"
    [[ "$mode" =~ ^[0-7]+$ ]] || return 1
    (( (8#$mode & 8#022) == 0 ))
}

sec_audit_kld_loaded() {
    sec_audit_have_cmd kldstat || return 1
    kldstat -q -m "$1" 2>/dev/null
}

sec_audit_kld_disabled_in_loader() {
    local mod="$1"
    grep -Eqi "^[[:space:]]*${mod}_load[[:space:]]*=[[:space:]]*\"?NO\"?" /boot/loader.conf /boot/loader.conf.local 2>/dev/null
}

sec_audit_check_kld_unavailable() {
    local req="$1" mod="$2"
    if [ "$mod" = zfs ] && mount 2>/dev/null | grep -Eq ' on / \(zfs[,)]'; then
        sec_audit_report_review "$req" "zfs required for root filesystem"
        return
    fi
    if sec_audit_kld_loaded "$mod"; then
        sec_audit_report_fail "$req" "${mod} kernel module is loaded"
    elif sec_audit_kld_disabled_in_loader "$mod"; then
        sec_audit_report_pass "$req" "${mod} not loaded and ${mod}_load=NO in loader.conf"
    else
        sec_audit_report_fail "$req" "${mod} not loaded but still loadable (set ${mod}_load=NO)"
    fi
}

sec_audit_low_impact_find() {
    local timeout_seconds="" cmd=()
    if [[ "${1:-}" == --timeout=* ]]; then
        timeout_seconds="${1#--timeout=}"
        shift
    fi
    [ -n "$timeout_seconds" ] && sec_audit_have_cmd timeout && cmd+=(timeout "$timeout_seconds")
    sec_audit_have_cmd nice && cmd+=(nice -n 19)
    cmd+=(find "$@")
    "${cmd[@]}"
}

sec_audit_local_mount_roots() {
    local roots
    roots=$(mount -p 2>/dev/null | awk '$3 ~ /^(ufs|zfs|msdosfs|ext2fs)$/ { print $2 }')
    if [ -z "$roots" ]; then
        roots=$(mount 2>/dev/null | awk '
            BEGIN { skip = "(nfs|nfs4|smbfs|cifs|procfs|devfs|fdescfs|linprocfs|linsysfs|nullfs|unionfs|tmpfs)" }
            $0 ~ skip { next }
            {
                for (i = 1; i <= NF; i++) {
                    if ($i == "on") { print $(i + 1); break }
                }
            }')
    fi
    if [ -z "$roots" ]; then
        printf '%s\n' /
    else
        printf '%s\n' "$roots" | awk 'NF' | sort -u
    fi
}

sec_audit_mount_line_for() {
    local mp="$1"
    mount 2>/dev/null | awk -v mp="$mp" '
        {
            for (i = 1; i <= NF; i++) {
                if ($i == "on" && $(i+1) == mp) { print; exit }
            }
        }'
}

sec_audit_mount_exists() {
    [ -n "$(sec_audit_mount_line_for "$1")" ]
}

sec_audit_mount_has_opt() {
    local mp="$1" opt="$2" line
    line=$(sec_audit_mount_line_for "$mp")
    [ -n "$line" ] || return 1
    printf '%s' "$line" | grep -Eq "(^|[, (])${opt}([, )]|$)"
}

sec_audit_check_separate_mount() {
    local req="$1" mp="$2"
    if sec_audit_mount_exists "$mp"; then
        sec_audit_report_pass "$req" "${mp} is a separate mount"
    else
        if [ "$mp" = "/tmp" ] && sec_audit_have_cmd sysrc; then
            local t
            t=$(sysrc -n tmpmfs 2>/dev/null || true)
            if [ "$(printf '%s' "$t" | tr '[:lower:]' '[:upper:]')" = "YES" ]; then
                sec_audit_report_pass "$req" "/tmp uses tmpmfs=YES"
                return
            fi
        fi
        sec_audit_report_fail "$req" "${mp} is not a separate mount"
    fi
}

sec_audit_check_mount_opt() {
    local req="$1" mp="$2" opt="$3"
    if ! sec_audit_mount_exists "$mp"; then
        sec_audit_report_fail "$req" "${mp} is not mounted separately; cannot verify ${opt}"
        return
    fi
    local line
    line=$(sec_audit_mount_line_for "$mp")
    if [ "$mp" = "/tmp" ] && printf '%s' "$line" | grep -Eq '\(tmpfs'; then
        if sec_audit_mount_has_opt "$mp" "$opt"; then
            sec_audit_report_pass "$req" "${opt} set on ${mp} (tmpfs)"
        else
            sec_audit_report_fail "$req" "${opt} is not set on ${mp}"
        fi
        return
    fi
    if sec_audit_mount_has_opt "$mp" "$opt"; then
        sec_audit_report_pass "$req" "${opt} set on ${mp}"
    else
        sec_audit_report_fail "$req" "${opt} is not set on ${mp}"
    fi
}

sec_audit_sysrc_n() {
    sec_audit_have_cmd sysrc || { printf ''; return 1; }
    sysrc -n "$1" 2>/dev/null || true
}

sec_audit_sysrc_enabled_yes() {
    local v
    v=$(sec_audit_sysrc_n "$1")
    case "$(printf '%s' "$v" | tr '[:lower:]' '[:upper:]')" in
        YES|TRUE|1) return 0 ;;
        *) return 1 ;;
    esac
}

sec_audit_pkg_installed() {
    sec_audit_have_cmd pkg || return 1
    pkg query %n "$1" >/dev/null 2>&1
}

sec_audit_pkg_query_glob() {
    sec_audit_have_cmd pkg || return 1
    pkg query -g %n "$1" 2>/dev/null | grep -q .
}

sec_audit_inetd_service_enabled() {
    local svc="$1"
    [ -f /etc/inetd.conf ] || return 1
    grep -Eq "^${svc}[[:space:]]" /etc/inetd.conf 2>/dev/null
}

sec_audit_check_file_mode_owner() {
    local req="$1" f="$2" max_mode="$3" owner="$4" group="$5"
    if [ ! -e "$f" ]; then
        sec_audit_report_fail "$req" "${f} does not exist"
        return
    fi
    local mode ou og
    mode=$(sec_audit_bsd_mode "$f")
    ou=$(sec_audit_bsd_owner "$f")
    og=$(sec_audit_bsd_group "$f")
    if sec_audit_mode_le "$mode" "$max_mode" && [ "$ou" = "$owner" ] && [ "$og" = "$group" ]; then
        sec_audit_report_pass "$req" "${f} mode=${mode} owner=${ou}:${og}"
    else
        sec_audit_report_fail "$req" "${f} mode=${mode:-?} owner=${ou:-?}:${og:-?} (want <=${max_mode} ${owner}:${group})"
    fi
}

sec_audit_sshd_host() { hostname 2>/dev/null || echo localhost; }
sec_audit_sshd_addr() {
    local h a
    h=$(sec_audit_sshd_host)
    a=$(grep -E "[[:space:]]${h}([[:space:]]|$)" /etc/hosts 2>/dev/null | awk '{print $1; exit}')
    [ -n "$a" ] || a=127.0.0.1
    printf '%s' "$a"
}

_SSHD_T=""
_SSHD_T_READY=0
sec_audit_sshd_T() {
    if [ "$_SSHD_T_READY" -eq 1 ]; then
        [ -n "$_SSHD_T" ] || return 1
        printf '%s\n' "$_SSHD_T"
        return 0
    fi
    sec_audit_have_cmd sshd || { _SSHD_T_READY=1; return 1; }
    _SSHD_T=$(sshd -T -C "user=root" -C "host=$(sec_audit_sshd_host)" -C "addr=$(sec_audit_sshd_addr)" 2>/dev/null || true)
    _SSHD_T_READY=1
    [ -n "$_SSHD_T" ] || return 1
    printf '%s\n' "$_SSHD_T"
}

sec_audit_sshd_opt() {
    local opt="$1"
    sec_audit_sshd_T | awk -v o="$(printf '%s' "$opt" | tr '[:upper:]' '[:lower:]')" 'tolower($1)==o {print $2; exit}'
}

sec_audit_check_sshd_eq() {
    local req="$1" opt="$2" want="$3"
    local got
    got=$(sec_audit_sshd_opt "$opt")
    if [ -z "$got" ]; then
        sec_audit_report_fail "$req" "sshd option ${opt} not readable"
        return
    fi
    if [ "$(printf '%s' "$got" | tr '[:upper:]' '[:lower:]')" = "$(printf '%s' "$want" | tr '[:upper:]' '[:lower:]')" ]; then
        sec_audit_report_pass "$req" "${opt}=${got}"
    else
        sec_audit_report_fail "$req" "${opt}=${got}, expected ${want}"
    fi
}

sec_audit_sysctl_n() {
    sec_audit_have_cmd sysctl || return 1
    sysctl -nq "$1" 2>/dev/null
}

sec_audit_check_sysctl_eq() {
    local req="$1" key="$2" want="$3"
    local got
    got=$(sec_audit_sysctl_n "$key")
    if [ -z "$got" ] && ! sysctl -n "$key" >/dev/null 2>&1; then
        sec_audit_report_fail "$req" "sysctl ${key} not available"
        return
    fi
    if [ "$got" = "$want" ]; then
        sec_audit_report_pass "$req" "${key}=${got}"
    else
        sec_audit_report_fail "$req" "${key}=${got:-?}, expected ${want}"
    fi
}

_AUDIT_FLAGS=""
_AUDIT_FLAGS_READY=0
sec_audit_audit_flags() {
    if [ "$_AUDIT_FLAGS_READY" -eq 1 ]; then
        [ -n "$_AUDIT_FLAGS" ] || return 1
        printf '%s\n' "$_AUDIT_FLAGS"
        return 0
    fi
    _AUDIT_FLAGS_READY=1
    [ -f /etc/security/audit_control ] || return 1
    _AUDIT_FLAGS=$(grep -E '^flags:' /etc/security/audit_control 2>/dev/null | head -n1)
    [ -n "$_AUDIT_FLAGS" ] || return 1
    printf '%s\n' "$_AUDIT_FLAGS"
}

sec_audit_audit_flags_has() {
    local class="$1" flags
    flags=$(sec_audit_audit_flags) || return 1
    printf '%s' "$flags" | grep -Eq "(^|[,:])${class}([,:]|$)"
}

sec_audit_check_audit_flag() {
    local req="$1" class="$2" desc="$3"
    if sec_audit_audit_flags_has "$class"; then
        sec_audit_report_pass "$req" "audit flags include ${class} (${desc})"
    else
        sec_audit_report_fail "$req" "audit flags missing ${class} (${desc}): $(sec_audit_audit_flags 2>/dev/null || echo none)"
    fi
}

sec_audit_audit_dir() {
    [ -f /etc/security/audit_control ] || return 1
    awk -F: '/^dir:/ {print $2; exit}' /etc/security/audit_control 2>/dev/null
}

sec_audit_sudoers_files() {
    local f
    [ -f /usr/local/etc/sudoers ] && printf '%s\n' /usr/local/etc/sudoers
    if [ -d /usr/local/etc/sudoers.d ]; then
        for f in /usr/local/etc/sudoers.d/*; do
            [ -f "$f" ] && printf '%s\n' "$f"
        done
    fi
}

sec_audit_sudoers_grep() {
    local files=()
    mapfile -t files < <(sec_audit_sudoers_files)
    [ "${#files[@]}" -gt 0 ] || return 1
    grep "$@" "${files[@]}"
}

sec_audit_login_conf_days() {
    local raw="$1" n u
    raw=$(printf '%s' "$raw" | tr -d '[:space:]')
    raw=${raw#*:}
    raw=${raw%%:*}
    raw=${raw#*=}
    [[ "$raw" =~ ^([0-9]+)([smhdwMy]?)$ ]] || return 1
    n="${BASH_REMATCH[1]}"
    u="${BASH_REMATCH[2]:-d}"
    case "$u" in
        s) printf '%s' 0 ;;
        m) printf '%s' 0 ;;
        h) printf '%s' $(( (n + 23) / 24 )) ;;
        d|"") printf '%s' "$n" ;;
        w) printf '%s' $((n * 7)) ;;
        M) printf '%s' $((n * 30)) ;;
        y) printf '%s' $((n * 365)) ;;
        *) return 1 ;;
    esac
}

sec_audit_check_kld_unavailable 1 ext2fs
sec_audit_check_kld_unavailable 2 msdosfs
sec_audit_check_kld_unavailable 3 zfs
sec_audit_check_separate_mount 4 /tmp
sec_audit_check_separate_mount 7 /home
sec_audit_check_separate_mount 9 /var
sec_audit_check_separate_mount 11 /var/tmp
sec_audit_check_separate_mount 14 /var/log
sec_audit_check_separate_mount 17 /var/audit
sec_audit_check_mount_opt 5 /tmp nosuid
sec_audit_check_mount_opt 6 /tmp noexec
sec_audit_check_mount_opt 8 /home nosuid
sec_audit_check_mount_opt 10 /var nosuid
sec_audit_check_mount_opt 12 /var/tmp nosuid
sec_audit_check_mount_opt 13 /var/tmp noexec
sec_audit_check_mount_opt 15 /var/log nosuid
sec_audit_check_mount_opt 16 /var/log noexec
sec_audit_check_mount_opt 18 /var/audit nosuid
sec_audit_check_mount_opt 19 /var/audit noexec

if [ -d /usr/share/keys/pkg ] || [ -f /etc/freebsd-update.conf ]; then
    if grep -Eqs 'KeyPrint|Untrusted|ServerKeyPrint' /etc/freebsd-update.conf 2>/dev/null \
        || [ -d /usr/share/keys/pkg ]; then
        sec_audit_report_pass 20 "freebsd-update / pkg key fingerprints present"
    else
        sec_audit_report_fail 20 "update server certificate fingerprints not configured"
    fi
else
    sec_audit_report_fail 20 "freebsd-update.conf / pkg keys not found"
fi

if sec_audit_have_cmd pkg && pkg -vv 2>/dev/null | grep -A20 '^Repositories:' | grep -Eqi 'url|FreeBSD'; then
    sec_audit_report_pass 21 "pkg repositories are configured"
else
    sec_audit_report_fail 21 "pkg repositories are not configured"
fi

if sec_audit_have_cmd freebsd-update; then
    out=$(freebsd-update updatesready 2>&1 || true)
    if printf '%s' "$out" | grep -Eqi 'updates.*ready|ready to be installed|install these updates'; then
        sec_audit_report_fail 22 "pending freebsd-update patches: $(printf '%s' "$out" | tr '\n' ' ' | cut -c1-120)"
    else
        sec_audit_report_review 22 "no queued freebsd-update install; verify patches applied (updatesready is not full status)"
    fi
else
    sec_audit_report_fail 22 "freebsd-update not available"
fi

if grep -Eq '^[[:space:]]*password=' /boot/loader.conf /boot/loader.conf.local 2>/dev/null; then
    sec_audit_report_pass 23 "bootloader password is set in loader.conf"
else
    sec_audit_report_fail 23 "bootloader password is not set"
fi

ok24=1; detail24=""
for f in /boot/loader.conf /boot/loader.conf.local; do
    [ -e "$f" ] || continue
    m=$(sec_audit_bsd_mode "$f"); o=$(sec_audit_bsd_owner "$f"); g=$(sec_audit_bsd_group "$f")
    if ! sec_audit_mode_le "${m:-777}" 600 || [ "$o" != root ] || [ "$g" != wheel ]; then
        ok24=0
        detail24="${detail24}${f} mode=${m:-?} owner=${o:-?}:${g:-?}; "
    fi
done
if [ $ok24 -eq 1 ]; then sec_audit_report_pass 24 "bootloader config permissions configured"
else sec_audit_report_fail 24 "${detail24}(want <=600 root:wheel)"; fi

sec_audit_check_sysctl_eq 25 kern.elf64.aslr.enable 1

if sec_audit_sysrc_enabled_yes savecore_enable; then
    sec_audit_report_fail 26 "savecore_enable is YES (should be disabled)"
else
    sec_audit_report_pass 26 "savecore is not enabled"
fi

dv=$(sec_audit_sysrc_n dumpdev)
case "$(printf '%s' "$dv" | tr '[:lower:]' '[:upper:]')" in
    NO|"") sec_audit_report_pass 27 "dumpdev=${dv:-NO}" ;;
    *) sec_audit_report_fail 27 "dumpdev=${dv}, expected NO" ;;
esac

if [ -f /etc/motd ]; then
    if [ -r /etc/os-release ] && grep -E '^VERSION=' /etc/os-release >/dev/null 2>&1; then
        ver=$(grep '^VERSION=' /etc/os-release | cut -d= -f2 | tr -d '"')
        if [ -n "$ver" ] && grep -Eiq -- "$ver" /etc/motd; then
            sec_audit_report_fail 28 "/etc/motd contains OS version string"
        else
            sec_audit_report_pass 28 "/etc/motd present and does not leak VERSION"
        fi
    else
        sec_audit_report_pass 28 "/etc/motd is present"
    fi
else
    sec_audit_report_fail 28 "/etc/motd is missing"
fi

if [ -f /etc/issue ]; then
    if [ -r /etc/os-release ]; then
        ver=$(grep '^VERSION=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')
        if [ -n "$ver" ] && grep -Eiq -- "$ver" /etc/issue; then
            sec_audit_report_fail 29 "/etc/issue contains OS version string"
        else
            sec_audit_report_pass 29 "/etc/issue is configured"
        fi
    else
        sec_audit_report_pass 29 "/etc/issue is present"
    fi
else
    sec_audit_report_fail 29 "/etc/issue is missing"
fi

if [ -f /etc/issue.net ]; then
    if [ -r /etc/os-release ]; then
        ver=$(grep '^VERSION=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')
        if [ -n "$ver" ] && grep -Eiq -- "$ver" /etc/issue.net; then
            sec_audit_report_fail 30 "/etc/issue.net contains OS version string"
        else
            sec_audit_report_pass 30 "/etc/issue.net is configured"
        fi
    else
        sec_audit_report_pass 30 "/etc/issue.net is present"
    fi
else
    sec_audit_report_fail 30 "/etc/issue.net is missing"
fi

if [ -e /etc/motd ]; then
    sec_audit_check_file_mode_owner 31 /etc/motd 644 root wheel
else
    sec_audit_report_pass 31 "/etc/motd does not exist"
fi

if [ -e /etc/issue ]; then
    sec_audit_check_file_mode_owner 32 /etc/issue 644 root wheel
else
    sec_audit_report_fail 32 "/etc/issue does not exist"
fi

if sec_audit_have_cmd service && service ntpd status >/dev/null 2>&1; then
    sec_audit_report_pass 33 "ntpd is running"
elif sec_audit_sysrc_enabled_yes ntpd_enable; then
    sec_audit_report_pass 33 "ntpd_enable=YES"
else
    sec_audit_report_fail 33 "ntpd is not enabled/running"
fi

if sec_audit_sysrc_enabled_yes autofs_enable; then
    sec_audit_report_fail 34 "autofs_enable=YES"
else
    sec_audit_report_pass 34 "autofs is not enabled"
fi

if sec_audit_inetd_service_enabled ftp || sec_audit_pkg_query_glob 'vsftpd*'; then
    sec_audit_report_fail 35 "ftp/vsftpd appears enabled or installed"
else
    sec_audit_report_pass 35 "ftp server services are not in use"
fi

if sec_audit_pkg_query_glob 'dovecot*' || sec_audit_pkg_query_glob 'cyrus-imapd*' \
    || sec_audit_sysrc_enabled_yes dovecot_enable || sec_audit_sysrc_enabled_yes cyrus_imapd_enable; then
    sec_audit_report_fail 36 "IMAP/POP message access server in use"
else
    sec_audit_report_pass 36 "message access server services are not in use"
fi

if sec_audit_sysrc_enabled_yes nfs_server_enable; then
    sec_audit_report_fail 37 "nfs_server_enable=YES"
else
    sec_audit_report_pass 37 "nfs server is not enabled"
fi

if sec_audit_sysrc_enabled_yes nis_server_enable; then
    sec_audit_report_fail 38 "nis_server_enable=YES"
else
    sec_audit_report_pass 38 "nis server is not enabled"
fi

if sec_audit_sysrc_enabled_yes rpcbind_enable; then
    sec_audit_report_fail 39 "rpcbind_enable=YES"
else
    sec_audit_report_pass 39 "rpcbind is not enabled"
fi

if sec_audit_pkg_installed net-snmp || sec_audit_sysrc_enabled_yes snmpd_enable; then
    sec_audit_report_fail 40 "snmp package installed or snmpd enabled"
else
    sec_audit_report_pass 40 "snmp services are not in use"
fi

if sec_audit_pkg_installed freebsd-telnetd || sec_audit_inetd_service_enabled telnet; then
    sec_audit_report_fail 41 "telnet server is installed or enabled"
else
    sec_audit_report_pass 41 "telnet server services are not in use"
fi

if sec_audit_inetd_service_enabled tftp; then
    sec_audit_report_fail 42 "tftp is enabled in inetd.conf"
else
    sec_audit_report_pass 42 "tftp server services are not in use"
fi

if sec_audit_pkg_query_glob 'squid*' || sec_audit_sysrc_enabled_yes squid_enable; then
    sec_audit_report_fail 43 "squid is installed or enabled"
else
    sec_audit_report_pass 43 "web proxy server services are not in use"
fi

if sec_audit_have_cmd sockstat; then
    bad=$(sockstat -46L 2>/dev/null | grep -E '[:.](25|465|587)[[:space:]]' | grep -Ev '127\.0\.0\.1|::1' || true)
    if [ -n "$bad" ]; then
        sec_audit_report_fail 44 "MTA listening on non-loopback: $(printf '%s' "$bad" | tr '\n' ';' | cut -c1-120)"
    else
        sec_audit_report_pass 44 "MTA not listening on non-loopback addresses"
    fi
else
    sec_audit_report_fail 44 "sockstat not available"
fi

if sec_audit_have_cmd sockstat; then
    sec_audit_report_review 45 "review listening services: $(sockstat -46L 2>/dev/null | tr '\n' ';' | cut -c1-200)"
else
    sec_audit_report_fail 45 "sockstat not available"
fi

if [ "$(sec_audit_sysctl_n kern.features.inet6)" = "1" ]; then
    sec_audit_report_pass 46 "IPv6 is enabled (identified)"
else
    sec_audit_report_pass 46 "IPv6 is not enabled (identified)"
fi

sec_audit_check_kld_unavailable 47 sctp

ok48=1; detail48=""
for k in net.inet.ip.forwarding net.inet6.ip6.forwarding; do
    g=$(sec_audit_sysctl_n "$k" 2>/dev/null || true)
    [ -z "$g" ] && continue
    if [ "$g" != "0" ]; then
        ok48=0
        detail48="${detail48}${k}=${g}; "
    fi
done
if [ $ok48 -eq 1 ]; then sec_audit_report_pass 48 "ip forwarding disabled"
else sec_audit_report_fail 48 "${detail48}expected 0"; fi

ok49=1; detail49=""
for pair in "net.inet.ip.redirect:0" "net.inet6.ip6.redirect:0"; do
    k=${pair%%:*}; w=${pair##*:}
    g=$(sec_audit_sysctl_n "$k" 2>/dev/null || true)
    [ -z "$g" ] && continue
    if [ "$g" != "$w" ]; then ok49=0; detail49="${detail49}${k}=${g}; "; fi
done
if [ $ok49 -eq 1 ]; then sec_audit_report_pass 49 "packet redirect sending disabled"
else sec_audit_report_fail 49 "${detail49}"; fi

ok50=1; detail50=""
for pair in "net.inet.icmp.bmcastecho:0" "net.inet.icmp.tstamprepl:0"; do
    k=${pair%%:*}; w=${pair##*:}
    g=$(sec_audit_sysctl_n "$k" 2>/dev/null || true)
    [ -z "$g" ] && continue
    if [ "$g" != "$w" ]; then ok50=0; detail50="${detail50}${k}=${g}; "; fi
done
if [ $ok50 -eq 1 ]; then sec_audit_report_pass 50 "broadcast/multicast ICMP ignored"
else sec_audit_report_fail 50 "${detail50}"; fi

ok51=1; detail51=""
g=$(sec_audit_sysctl_n net.inet.icmp.drop_redirect 2>/dev/null || true)
if [ -n "$g" ] && [ "$g" != "1" ]; then ok51=0; detail51="${detail51}net.inet.icmp.drop_redirect=${g}; "; fi
g=$(sec_audit_sysctl_n net.inet6.icmp6.rediraccept 2>/dev/null || true)
if [ -n "$g" ] && [ "$g" != "0" ]; then ok51=0; detail51="${detail51}net.inet6.icmp6.rediraccept=${g}; "; fi
if [ $ok51 -eq 1 ]; then sec_audit_report_pass 51 "ICMP redirects not accepted"
else sec_audit_report_fail 51 "${detail51}"; fi

sec_audit_check_sysctl_eq 52 net.inet.ip.accept_sourceroute 0

sec_audit_check_sysctl_eq 53 net.inet.tcp.syncookies 1

sec_audit_check_sysctl_eq 54 net.inet6.ip6.accept_rtadv 0

if sec_audit_have_cmd service && service ipfw status 2>/dev/null | grep -Eqi 'enabled|running'; then
    sec_audit_report_pass 55 "ipfw is enabled"
elif sec_audit_sysrc_enabled_yes firewall_enable; then
    sec_audit_report_pass 55 "firewall_enable=YES (ipfw)"
else
    sec_audit_report_fail 55 "ipfw is not enabled"
fi

fw=0
sec_audit_sysrc_enabled_yes firewall_enable && fw=$((fw+1))
sec_audit_sysrc_enabled_yes ipfilter_enable && fw=$((fw+1))
sec_audit_sysrc_enabled_yes pf_enable && fw=$((fw+1))
if [ "$fw" -eq 1 ]; then
    sec_audit_report_pass 56 "exactly one firewall utility is enabled"
elif [ "$fw" -eq 0 ]; then
    sec_audit_report_fail 56 "no firewall utility enabled"
else
    sec_audit_report_fail 56 "multiple firewall utilities enabled (count=${fw})"
fi

if [ -e /etc/crontab ]; then
    m=$(sec_audit_bsd_mode /etc/crontab); o=$(sec_audit_bsd_owner /etc/crontab); g=$(sec_audit_bsd_group /etc/crontab)
    if sec_audit_mode_no_go_write "${m:-777}" && [ "$o" = root ] && [ "$g" = wheel ]; then
        sec_audit_report_pass 57 "/etc/crontab mode=${m} owner=${o}:${g}"
    else
        sec_audit_report_fail 57 "/etc/crontab mode=${m:-?} owner=${o:-?}:${g:-?}"
    fi
else
    sec_audit_report_fail 57 "/etc/crontab missing"
fi

if [ -e /etc/cron.d ]; then
    m=$(sec_audit_bsd_mode /etc/cron.d); o=$(sec_audit_bsd_owner /etc/cron.d); g=$(sec_audit_bsd_group /etc/cron.d)
    if sec_audit_mode_no_go_write "${m:-777}" && [ "$o" = root ] && [ "$g" = wheel ]; then
        sec_audit_report_pass 58 "/etc/cron.d mode=${m} owner=${o}:${g}"
    else
        sec_audit_report_fail 58 "/etc/cron.d mode=${m:-?} owner=${o:-?}:${g:-?}"
    fi
else
    sec_audit_report_fail 58 "/etc/cron.d missing"
fi

if [ -f /var/cron/allow ]; then
    if [ -e /var/cron/deny ]; then
        sec_audit_report_fail 59 "/var/cron/deny exists (should not when allow is used)"
    else
        m=$(sec_audit_bsd_mode /var/cron/allow); o=$(sec_audit_bsd_owner /var/cron/allow); g=$(sec_audit_bsd_group /var/cron/allow)
        if sec_audit_mode_le "${m:-777}" 640 && [ "$o" = root ] && [ "$g" = wheel ]; then
            sec_audit_report_pass 59 "/var/cron/allow mode=${m} owner=${o}:${g}"
        else
            sec_audit_report_fail 59 "/var/cron/allow mode=${m:-?} owner=${o:-?}:${g:-?}"
        fi
    fi
else
    sec_audit_report_fail 59 "/var/cron/allow does not exist"
fi

if [ -f /var/at/at.allow ]; then
    m=$(sec_audit_bsd_mode /var/at/at.allow); o=$(sec_audit_bsd_owner /var/at/at.allow); g=$(sec_audit_bsd_group /var/at/at.allow)
    if sec_audit_mode_le "${m:-777}" 640 && { [ "$o" = root ] || [ "$o" = daemon ]; } && [ "$g" = wheel ]; then
        if [ -e /var/at/at.deny ]; then
            sec_audit_report_fail 60 "/var/at/at.deny exists"
        else
            sec_audit_report_pass 60 "/var/at/at.allow configured"
        fi
    else
        sec_audit_report_fail 60 "/var/at/at.allow mode=${m:-?} owner=${o:-?}:${g:-?}"
    fi
else
    sec_audit_report_fail 60 "/var/at/at.allow does not exist"
fi

sec_audit_check_file_mode_owner 61 /etc/ssh/sshd_config 644 root wheel

ok62=1; found62=0; detail62=""
while IFS= read -r f; do
    found62=1
    m=$(sec_audit_bsd_mode "$f"); o=$(sec_audit_bsd_owner "$f"); g=$(sec_audit_bsd_group "$f")
    if ! sec_audit_mode_le "${m:-777}" 600 || [ "$o" != root ]; then
        ok62=0
        detail62="${detail62}${f} mode=${m:-?} owner=${o:-?}:${g:-?}; "
    fi
done < <(find /etc/ssh -type f -name 'ssh_host_*_key' 2>/dev/null)
if [ $found62 -eq 0 ]; then sec_audit_report_fail 62 "no SSH private host keys found"
elif [ $ok62 -eq 1 ]; then sec_audit_report_pass 62 "SSH private host key permissions OK"
else sec_audit_report_fail 62 "${detail62}"; fi

ok63=1; found63=0; detail63=""
while IFS= read -r f; do
    found63=1
    m=$(sec_audit_bsd_mode "$f"); o=$(sec_audit_bsd_owner "$f"); g=$(sec_audit_bsd_group "$f")
    if ! sec_audit_mode_le "${m:-777}" 644 || [ "$o" != root ] || [ "$g" != wheel ]; then
        ok63=0
        detail63="${detail63}${f} mode=${m:-?} owner=${o:-?}:${g:-?}; "
    fi
done < <(find /etc/ssh -type f -name 'ssh_host_*_key.pub' 2>/dev/null)
if [ $found63 -eq 0 ]; then sec_audit_report_fail 63 "no SSH public host keys found"
elif [ $ok63 -eq 1 ]; then sec_audit_report_pass 63 "SSH public host key permissions OK"
else sec_audit_report_fail 63 "${detail63}"; fi

acc=$(sec_audit_sshd_T 2>/dev/null | grep -Ei '^(allow|deny)(users|groups)[[:space:]]' || true)
if [ -n "$acc" ]; then
    sec_audit_report_pass 64 "sshd access controls: $(printf '%s' "$acc" | tr '\n' ';' | cut -c1-120)"
else
    sec_audit_report_fail 64 "no AllowUsers/AllowGroups/DenyUsers/DenyGroups configured"
fi

b=$(sec_audit_sshd_opt banner)
if [ -n "$b" ] && [ "$b" != "none" ]; then
    sec_audit_report_pass 65 "sshd Banner=${b}"
else
    sec_audit_report_fail 65 "sshd Banner is not configured"
fi

ciph=$(sec_audit_sshd_opt ciphers)
weak66=0
for w in 3des-cbc aes128-cbc aes192-cbc aes256-cbc 'rijndael-cbc@lysator.liu.se'; do
    printf '%s' "$ciph" | grep -Fqi "$w" && weak66=1
done
if [ -z "$ciph" ]; then sec_audit_report_fail 66 "sshd Ciphers not readable"
elif [ $weak66 -eq 1 ]; then sec_audit_report_fail 66 "weak sshd Ciphers present: ${ciph}"
else sec_audit_report_pass 66 "sshd Ciphers OK"; fi

cai=$(sec_audit_sshd_opt clientaliveinterval); cam=$(sec_audit_sshd_opt clientalivecountmax)
if [ -n "$cai" ] && [ -n "$cam" ] && [ "$cai" -gt 0 ] 2>/dev/null && [ "$cam" -gt 0 ] 2>/dev/null; then
    sec_audit_report_pass 67 "ClientAliveInterval=${cai} ClientAliveCountMax=${cam}"
else
    sec_audit_report_fail 67 "ClientAliveInterval=${cai:-?} ClientAliveCountMax=${cam:-?} (both must be >0)"
fi

sec_audit_check_sshd_eq 68 disableforwarding yes
sec_audit_check_sshd_eq 69 hostbasedauthentication no
sec_audit_check_sshd_eq 70 ignorerhosts yes

kex=$(sec_audit_sshd_opt kexalgorithms)
weak71=0
for w in diffie-hellman-group1-sha1 diffie-hellman-group14-sha1 diffie-hellman-group-exchange-sha1; do
    printf '%s' "$kex" | grep -Fqi "$w" && weak71=1
done
if [ -z "$kex" ]; then sec_audit_report_fail 71 "sshd KexAlgorithms not readable"
elif [ $weak71 -eq 1 ]; then sec_audit_report_fail 71 "weak KexAlgorithms present"
else sec_audit_report_pass 71 "sshd KexAlgorithms OK"; fi

lgt=$(sec_audit_sshd_opt logingracetime)
if [ -n "$lgt" ] && [ "$lgt" -ge 1 ] 2>/dev/null && [ "$lgt" -le 60 ] 2>/dev/null; then
    sec_audit_report_pass 72 "LoginGraceTime=${lgt}"
else
    sec_audit_report_fail 72 "LoginGraceTime=${lgt:-?} (want 1-60)"
fi

ll=$(sec_audit_sshd_opt loglevel | tr '[:lower:]' '[:upper:]')
case "$ll" in
    VERBOSE|INFO) sec_audit_report_pass 73 "LogLevel=${ll}" ;;
    *) sec_audit_report_fail 73 "LogLevel=${ll:-?}, expected VERBOSE or INFO" ;;
esac

macs=$(sec_audit_sshd_opt macs)
weak74=0
for w in hmac-md5 hmac-md5-96 hmac-ripemd160 hmac-sha1-96 'umac-64@openssh.com' 'hmac-md5-etm@openssh.com' 'hmac-md5-96-etm@openssh.com' 'hmac-ripemd160-etm@openssh.com' 'hmac-sha1-96-etm@openssh.com' 'umac-64-etm@openssh.com'; do
    printf '%s' "$macs" | grep -Fqi "$w" && weak74=1
done
if [ -z "$macs" ]; then sec_audit_report_fail 74 "sshd MACs not readable"
elif [ $weak74 -eq 1 ]; then sec_audit_report_fail 74 "weak MACs present"
else sec_audit_report_pass 74 "sshd MACs OK"; fi

mat=$(sec_audit_sshd_opt maxauthtries)
if [ -n "$mat" ] && [ "$mat" -le 4 ] 2>/dev/null; then sec_audit_report_pass 75 "MaxAuthTries=${mat}"
else sec_audit_report_fail 75 "MaxAuthTries=${mat:-?} (want <=4)"; fi

ms=$(sec_audit_sshd_opt maxsessions)
if [ -n "$ms" ] && [ "$ms" -le 10 ] 2>/dev/null; then sec_audit_report_pass 76 "MaxSessions=${ms}"
else sec_audit_report_fail 76 "MaxSessions=${ms:-?} (want <=10)"; fi

mst=$(sec_audit_sshd_opt maxstartups)
if [ -n "$mst" ]; then
    IFS=: read -r a b c <<<"$mst"
    if [ "${a:-99}" -le 10 ] 2>/dev/null && [ "${b:-99}" -le 30 ] 2>/dev/null && [ "${c:-999}" -le 60 ] 2>/dev/null; then
        sec_audit_report_pass 77 "MaxStartups=${mst}"
    else
        sec_audit_report_fail 77 "MaxStartups=${mst} not <=10:30:60"
    fi
else
    sec_audit_report_fail 77 "MaxStartups not readable"
fi

sec_audit_check_sshd_eq 78 permitemptypasswords no
sec_audit_check_sshd_eq 79 permitrootlogin no
sec_audit_check_sshd_eq 80 permituserenvironment no
sec_audit_check_sshd_eq 81 usepam yes

if sec_audit_pkg_installed sudo || [ -x /usr/local/bin/sudo ]; then
    sec_audit_report_pass 82 "sudo is installed"
else
    sec_audit_report_fail 82 "sudo is not installed"
fi

if sec_audit_sudoers_grep -Esiq 'Defaults[[:space:]].*use_pty' 2>/dev/null; then
    sec_audit_report_pass 83 "Defaults use_pty configured"
else
    sec_audit_report_fail 83 "Defaults use_pty not found in sudoers"
fi

if sec_audit_sudoers_grep -Esiq 'Defaults[[:space:]].*logfile[[:space:]]*=' 2>/dev/null; then
    sec_audit_report_pass 84 "sudo logfile configured"
else
    sec_audit_report_fail 84 "sudo logfile not configured"
fi

if sec_audit_sudoers_grep -E '^[^#].*NOPASSWD' 2>/dev/null | grep -q .; then
    sec_audit_report_fail 85 "NOPASSWD found in sudoers"
else
    sec_audit_report_pass 85 "no NOPASSWD in sudoers"
fi

if sec_audit_sudoers_grep -E '^[^#].*!authenticate' 2>/dev/null | grep -q .; then
    sec_audit_report_fail 86 "!authenticate found in sudoers"
else
    sec_audit_report_pass 86 "re-authentication not disabled globally"
fi

tto=$(sec_audit_sudoers_grep -hoE 'timestamp_timeout=[-0-9]+' 2>/dev/null | head -n1 | cut -d= -f2)
if [ -z "$tto" ]; then
    sec_audit_report_review 87 "timestamp_timeout not set explicitly (confirm sudo default <=15)"
elif [ "$tto" -ge 0 ] 2>/dev/null && [ "$tto" -le 15 ] 2>/dev/null; then
    sec_audit_report_pass 87 "timestamp_timeout=${tto}"
else
    sec_audit_report_fail 87 "timestamp_timeout=${tto} (want 0-15)"
fi

if grep -Eqi '^auth[[:space:]]+(required|requisite)[[:space:]]+pam_group\.so' /etc/pam.d/su 2>/dev/null; then
    sec_audit_report_pass 88 "su restricted via pam_group"
else
    sec_audit_report_fail 88 "pam_group restriction not found in /etc/pam.d/su"
fi

_ml=$(grep -ERh -- 'pam_passwdqc\.so' /etc/pam.d 2>/dev/null | grep -Eo 'minlen=[0-9]+' | head -n1 | cut -d= -f2)
if [ -n "$_ml" ] && [ "$_ml" -ge 14 ] 2>/dev/null; then
    sec_audit_report_pass 89 "pam_passwdqc minlen=${_ml}"
else
    sec_audit_report_fail 89 "password minlen >=14 not found in pam (got ${_ml:-none})"
fi

if grep -ERiq -- 'pam_passwdqc\.so.*enforce=everyone' /etc/pam.d 2>/dev/null; then
    sec_audit_report_pass 90 "pam_passwdqc enforce=everyone"
else
    sec_audit_report_fail 90 "pam_passwdqc enforce=everyone not configured"
fi

if grep -E -- '^\s*(auth|account|password|session)\s+(requisite|required|sufficient)\s+pam_unix\.so\b' /etc/pam.d/passwd /etc/pam.d/system 2>/dev/null | grep -Eq -- '\bnullok\b'; then
    sec_audit_report_fail 91 "pam_unix includes nullok"
else
    sec_audit_report_pass 91 "pam_unix does not include nullok"
fi

if grep -Eq '^[[:space:]]*:passwd_format=sha512:' /etc/login.conf 2>/dev/null; then
    sec_audit_report_pass 92 "passwd_format=sha512"
else
    sec_audit_report_fail 92 "passwd_format=sha512 not set in /etc/login.conf"
fi

pt=$(grep -E '^[[:space:]]*:passwordtime=' /etc/login.conf 2>/dev/null | head -n1)
_ptdays=$(sec_audit_login_conf_days "$pt" 2>/dev/null || true)
if [ -z "$pt" ] || [ -z "$_ptdays" ]; then
    sec_audit_report_fail 93 "passwordtime not set or unparsable"
elif [ "$_ptdays" -le 365 ] 2>/dev/null; then
    sec_audit_report_pass 93 "passwordtime=${_ptdays}d (<=365)"
else
    sec_audit_report_fail 93 "passwordtime=${_ptdays}d (>365)"
fi

wp=$(grep -E '^[[:space:]]*:warnpassword=' /etc/login.conf 2>/dev/null | head -n1)
_wdays=$(sec_audit_login_conf_days "$wp" 2>/dev/null || true)
if [ -z "$wp" ] || [ -z "$_wdays" ]; then
    sec_audit_report_fail 94 "warnpassword not set or unparsable"
elif [ "$_wdays" -ge 7 ] 2>/dev/null; then
    sec_audit_report_pass 94 "warnpassword=${_wdays}d (>=7)"
else
    sec_audit_report_fail 94 "warnpassword=${_wdays}d (<7)"
fi

rg=$(awk -F: '$1=="root"{print $4; exit}' /etc/passwd 2>/dev/null)
if [ "$rg" = "0" ]; then sec_audit_report_pass 95 "root GID=0"
else sec_audit_report_fail 95 "root GID=${rg:-?}, expected 0"; fi

if grep -Esiq -- '^\s*umask\s+' /root/.profile /root/.cshrc /root/.login /etc/csh.cshrc /etc/profile 2>/dev/null; then
    sec_audit_report_pass 96 "root umask is configured"
else
    sec_audit_report_fail 96 "root umask not found"
fi

bad97=$(awk -F: '($1!~/^(root|toor|uucp)$/) && ($3+0 < 1000) && ($7!~/^(\/usr)?\/sbin\/nologin$/) && ($7!="/bin/false") {print $1}' /etc/passwd 2>/dev/null | tr '\n' ',' )
if [ -n "$bad97" ]; then sec_audit_report_fail 97 "system accounts with login shell: ${bad97}"
else sec_audit_report_pass 97 "system accounts are secured"; fi

if grep -Eq '/nologin\b' /etc/shells 2>/dev/null; then
    sec_audit_report_fail 98 "nologin is listed in /etc/shells"
else
    sec_audit_report_pass 98 "nologin is not listed in /etc/shells"
fi

if grep -Esiq 'umask' /etc/login.conf /etc/csh.cshrc /etc/profile 2>/dev/null; then
    sec_audit_report_pass 99 "default user umask is configured"
else
    sec_audit_report_fail 99 "default user umask not found"
fi

if sec_audit_sysrc_enabled_yes syslogd_enable; then sec_audit_report_pass 100 "syslogd_enable=YES"
else sec_audit_report_fail 100 "syslogd_enable is not YES"; fi

if sec_audit_sysrc_enabled_yes syslogd_enable; then sec_audit_report_pass 101 "syslogd service is enabled"
else sec_audit_report_fail 101 "syslogd service is not enabled"; fi

if [ -f /etc/newsyslog.conf ]; then
    bad102=$(grep -Eihv '^[[:space:]]*(#|$)' /etc/newsyslog.conf /etc/newsyslog.conf.d/* 2>/dev/null | awk '{print $2}' | grep -E '^[0-7]{3,4}$' | while read -r m; do
        sec_audit_mode_le "$m" 644 || echo "$m"
    done | head -n1)
    if [ -n "$bad102" ]; then sec_audit_report_fail 102 "newsyslog mode more permissive than 644 found"
    else sec_audit_report_pass 102 "newsyslog default permissions look restrictive"; fi
else
    sec_audit_report_fail 102 "/etc/newsyslog.conf missing"
fi

if [ -f /etc/syslog.conf ] || ls /etc/syslog.d/*.conf >/dev/null 2>&1; then
    if [ -d /var/log ] && ls /var/log >/dev/null 2>&1; then
        sec_audit_report_pass 103 "syslog configuration and /var/log present"
    else
        sec_audit_report_fail 103 "/var/log missing"
    fi
else
    sec_audit_report_fail 103 "syslog configuration not found"
fi

if grep -Eqs '^[^#]*@' /etc/syslog.conf /etc/syslog.d/*.conf /usr/local/etc/syslog.d/*.conf 2>/dev/null; then
    sec_audit_report_pass 104 "remote syslog host configured"
else
    sec_audit_report_fail 104 "remote syslog host not configured"
fi

sf=$(sec_audit_sysrc_n syslogd_flags)
if printf '%s' "$sf" | grep -Eq -- '(^|[[:space:]])-s(s)?([[:space:]]|$)'; then
    sec_audit_report_pass 105 "syslogd_flags include -s (no remote receive)"
else
    sec_audit_report_fail 105 "syslogd_flags='${sf}' missing -s"
fi

if [ -f /etc/newsyslog.conf ]; then
    sec_audit_report_pass 106 "newsyslog.conf is present (review site policy)"
else
    sec_audit_report_fail 106 "newsyslog.conf missing"
fi

ok107=1; detail107=""
for spec in \
    /var/log/messages:640:root:wheel \
    /var/log/cron:640:root:wheel \
    /var/log/auth.log:640:root:wheel \
    /var/log/maillog:640:root:wheel; do
    IFS=: read -r f maxm ow og <<<"$spec"
    [ -e "$f" ] || continue
    m=$(sec_audit_bsd_mode "$f"); o=$(sec_audit_bsd_owner "$f"); g=$(sec_audit_bsd_group "$f")
    if ! sec_audit_mode_le "${m:-777}" "$maxm" || [ "$o" != "$ow" ] || [ "$g" != "$og" ]; then
        ok107=0
        detail107="${detail107}${f} mode=${m:-?} owner=${o:-?}:${g:-?}; "
    fi
done
if [ $ok107 -eq 1 ]; then sec_audit_report_pass 107 "checked log files have appropriate access"
else sec_audit_report_fail 107 "${detail107}"; fi

if sec_audit_sysrc_enabled_yes auditd_enable; then sec_audit_report_pass 108 "auditd_enable=YES"
else sec_audit_report_fail 108 "auditd_enable is not YES"; fi

if grep -Eq '^filesz:' /etc/security/audit_control 2>/dev/null; then
    sec_audit_report_pass 109 "filesz configured: $(grep -E '^filesz:' /etc/security/audit_control | head -n1)"
else
    sec_audit_report_fail 109 "filesz not set in audit_control"
fi

if grep -Eq '^expire-after:' /etc/security/audit_control 2>/dev/null; then
    sec_audit_report_pass 110 "expire-after configured"
else
    sec_audit_report_fail 110 "expire-after not set in audit_control"
fi

sec_audit_check_audit_flag 111 aa "authentication and authorization"

ok112=1
for c in fa fc fd fm fr fw; do
    sec_audit_audit_flags_has "$c" || ok112=0
done
if [ $ok112 -eq 1 ]; then sec_audit_report_pass 112 "audit flags include fa,fc,fd,fm,fr,fw"
else sec_audit_report_fail 112 "audit flags missing file classes: $(sec_audit_audit_flags 2>/dev/null || echo none)"; fi

sec_audit_check_audit_flag 113 pc "process"

ok114=1
for c in fm fa; do sec_audit_audit_flags_has "$c" || ok114=0; done
if [ $ok114 -eq 1 ]; then sec_audit_report_pass 114 "audit flags include fm/fa for DAC changes"
else sec_audit_report_fail 114 "audit flags missing fm/fa: $(sec_audit_audit_flags 2>/dev/null || echo none)"; fi

sec_audit_check_audit_flag 115 ad "administrative"

sec_audit_check_audit_flag 116 lo "login_logout"

sec_audit_check_audit_flag 117 fd "file delete"

ok118=1
for c in aa ad; do sec_audit_audit_flags_has "$c" || ok118=0; done
if [ $ok118 -eq 1 ]; then sec_audit_report_pass 118 "audit flags include aa,ad (user modification)"
else sec_audit_report_fail 118 "audit flags missing aa/ad for usermod-equivalent events"; fi

adir=$(sec_audit_audit_dir)
if [ -n "$adir" ] && [ -d "$adir" ]; then
    m=$(sec_audit_bsd_mode "$adir")
    if sec_audit_mode_le "${m:-777}" 750; then sec_audit_report_pass 119 "audit dir ${adir} mode=${m}"
    else sec_audit_report_fail 119 "audit dir ${adir} mode=${m:-?}, want <=750"; fi
else
    sec_audit_report_fail 119 "audit dir not found in audit_control"
fi

adir=$(sec_audit_audit_dir)
ok120=1; ok121=1; ok122=1
detail120=""; detail121=""; detail122=""
if [ -n "$adir" ] && [ -d "$adir" ]; then
    while IFS= read -r f; do
        m=$(sec_audit_bsd_mode "$f"); o=$(sec_audit_bsd_owner "$f"); g=$(sec_audit_bsd_group "$f")
        if ! sec_audit_mode_le "${m:-777}" 640; then ok120=0; detail120="${detail120}${f} mode=${m}; "; fi
        if [ "$o" != root ]; then ok121=0; detail121="${detail121}${f} owner=${o}; "; fi
        if [ "$g" != wheel ] && [ "$g" != audit ]; then
            ok122=0
            detail122="${detail122}${f} group=${g}; "
        fi
    done < <(sec_audit_low_impact_find --timeout=30 "$adir" -xdev -type f 2>/dev/null | head -n 200)
    if [ $ok120 -eq 1 ]; then sec_audit_report_pass 120 "audit log files mode <=640"
    else sec_audit_report_fail 120 "${detail120}"; fi
    if [ $ok121 -eq 1 ]; then sec_audit_report_pass 121 "audit log files owned by root"
    else sec_audit_report_fail 121 "${detail121}"; fi
    if [ $ok122 -eq 1 ]; then sec_audit_report_pass 122 "audit log files group OK"
    else sec_audit_report_fail 122 "${detail122}"; fi
else
    sec_audit_report_fail 120 "audit dir not found"
    sec_audit_report_fail 121 "audit dir not found"
    sec_audit_report_fail 122 "audit dir not found"
fi

ok123=1; detail123=""
for f in /etc/security/audit_control /etc/security/audit_user; do
    [ -e "$f" ] || continue
    m=$(sec_audit_bsd_mode "$f")
    sec_audit_mode_le "${m:-777}" 600 || { ok123=0; detail123="${detail123}${f} mode=${m}; "; }
done
for f in /etc/security/audit_event /etc/security/audit_class; do
    [ -e "$f" ] || continue
    m=$(sec_audit_bsd_mode "$f")
    sec_audit_mode_le "${m:-777}" 444 || { ok123=0; detail123="${detail123}${f} mode=${m}; "; }
done
if [ $ok123 -eq 1 ]; then sec_audit_report_pass 123 "audit configuration file modes OK"
else sec_audit_report_fail 123 "${detail123}"; fi

if find /etc/security -type f -name 'audit*' ! -user root 2>/dev/null | grep -q .; then
    sec_audit_report_fail 124 "audit config files not owned by root"
else
    sec_audit_report_pass 124 "audit configuration files owned by root"
fi

if find /etc/security -type f -name 'audit*' ! -group wheel 2>/dev/null | grep -q .; then
    sec_audit_report_fail 125 "audit config files not group wheel"
else
    sec_audit_report_pass 125 "audit configuration files belong to wheel"
fi

ok126=1; detail126=""
for f in /usr/sbin/audit /usr/sbin/auditd /usr/sbin/auditreduce /usr/sbin/praudit; do
    [ -e "$f" ] || continue
    m=$(sec_audit_bsd_mode "$f")
    sec_audit_mode_le "${m:-777}" 555 || { ok126=0; detail126="${detail126}${f} mode=${m}; "; }
done
if [ $ok126 -eq 1 ]; then sec_audit_report_pass 126 "audit tools mode <=555"
else sec_audit_report_fail 126 "${detail126}"; fi

ok127=1; detail127=""
for f in /usr/sbin/audit /usr/sbin/auditd /usr/sbin/auditreduce /usr/sbin/praudit; do
    [ -e "$f" ] || continue
    o=$(sec_audit_bsd_owner "$f")
    [ "$o" = root ] || { ok127=0; detail127="${detail127}${f} owner=${o}; "; }
done
if [ $ok127 -eq 1 ]; then sec_audit_report_pass 127 "audit tools owned by root"
else sec_audit_report_fail 127 "${detail127}"; fi

ok128=1; detail128=""
for f in /usr/sbin/audit /usr/sbin/auditd /usr/sbin/auditreduce /usr/sbin/praudit; do
    [ -e "$f" ] || continue
    g=$(sec_audit_bsd_group "$f")
    [ "$g" = wheel ] || { ok128=0; detail128="${detail128}${f} group=${g}; "; }
done
if [ $ok128 -eq 1 ]; then sec_audit_report_pass 128 "audit tools belong to wheel"
else sec_audit_report_fail 128 "${detail128}"; fi

if sec_audit_pkg_query_glob 'aide*'; then sec_audit_report_pass 129 "AIDE is installed"
else sec_audit_report_fail 129 "AIDE is not installed"; fi

if crontab -l -u root 2>/dev/null | grep -Eqs 'aide' \
    || grep -Eqs 'aide' /var/cron/tabs/root /etc/crontab 2>/dev/null \
    || grep -Eqs 'aide' /etc/cron.d/* /usr/local/etc/cron.d/* 2>/dev/null \
    || grep -Eqs 'aide' /etc/periodic/*/* 2>/dev/null; then
    sec_audit_report_pass 130 "AIDE scheduled check present"
else
    sec_audit_report_fail 130 "no AIDE schedule in crontab/cron.d/periodic"
fi

sec_audit_check_file_mode_owner 131 /etc/passwd 644 root wheel
sec_audit_check_file_mode_owner 132 /etc/group 644 root wheel
if [ -e /etc/master.passwd ]; then
    m=$(sec_audit_bsd_mode /etc/master.passwd); o=$(sec_audit_bsd_owner /etc/master.passwd); g=$(sec_audit_bsd_group /etc/master.passwd)
    if sec_audit_mode_le "${m:-777}" 600 && [ "$o" = root ] && [ "$g" = wheel ]; then
        sec_audit_report_pass 133 "/etc/master.passwd mode=${m} owner=${o}:${g}"
    else
        sec_audit_report_fail 133 "/etc/master.passwd mode=${m:-?} owner=${o:-?}:${g:-?} (want <=600 root:wheel)"
    fi
else
    sec_audit_report_fail 133 "/etc/master.passwd missing"
fi
sec_audit_check_file_mode_owner 134 /etc/shells 644 root wheel

ww135=""
while IFS= read -r root; do
    [ -d "$root" ] || continue
    sample=$(sec_audit_low_impact_find --timeout=45 "$root" -xdev \
        \( -name .zfs -o -path /tmp -o -path '/tmp/*' -o -path /var/tmp -o -path '/var/tmp/*' \
           -o -path /dev -o -path '/dev/*' -o -path /proc -o -path '/proc/*' \
           -o -path /mnt -o -path '/mnt/*' -o -path /media -o -path '/media/*' \
           -o -path /compat -o -path '/compat/*' \) -prune -o \
        \( \( -type f -perm -0002 \) -o \( -type d -perm -0002 ! -perm -1000 \) \) -print 2>/dev/null \
        | head -n 20)
    [ -n "$sample" ] && ww135="${ww135}${sample}"$'\n'
    [ "$(printf '%s' "$ww135" | grep -c .)" -ge 20 ] 2>/dev/null && break
done < <(sec_audit_local_mount_roots)
ww135=$(printf '%s' "$ww135" | awk 'NF' | head -n 20)
if [ -n "$ww135" ]; then
    sec_audit_report_fail 135 "world-writable objects found (sample): $(printf '%s' "$ww135" | tr '\n' ' ' | cut -c1-160)"
else
    sec_audit_report_pass 135 "no insecure world-writable files/dirs found on local mounts (sampled)"
fi

uu136=""
while IFS= read -r root; do
    [ -d "$root" ] || continue
    sample=$(sec_audit_low_impact_find --timeout=45 "$root" -xdev \
        \( -name .zfs -o -path /dev -o -path '/dev/*' -o -path /proc -o -path '/proc/*' \) -prune -o \
        \( -nouser -o -nogroup \) -print 2>/dev/null | head -n 20)
    [ -n "$sample" ] && uu136="${uu136}${sample}"$'\n'
    [ "$(printf '%s' "$uu136" | grep -c .)" -ge 20 ] 2>/dev/null && break
done < <(sec_audit_local_mount_roots)
uu136=$(printf '%s' "$uu136" | awk 'NF' | head -n 20)
if [ -n "$uu136" ]; then
    sec_audit_report_fail 136 "unowned/ungrouped paths: $(printf '%s' "$uu136" | tr '\n' ' ' | cut -c1-160)"
else
    sec_audit_report_pass 136 "no unowned or ungrouped files/dirs on local mounts (sampled)"
fi

suid_n=0; sgid_n=0
while IFS= read -r root; do
    [ -d "$root" ] || continue
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        [ -u "$f" ] && suid_n=$((suid_n + 1))
        [ -g "$f" ] && sgid_n=$((sgid_n + 1))
    done < <(sec_audit_low_impact_find --timeout=45 "$root" -xdev -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null)
done < <(sec_audit_local_mount_roots)
sec_audit_report_review 137 "SUID=${suid_n} SGID=${sgid_n} — review against site policy"

if awk -F: '($2 != "*") { print $1 }' /etc/passwd 2>/dev/null | grep -q .; then
    sec_audit_report_fail 138 "accounts in /etc/passwd without shadowed '*' password field"
else
    sec_audit_report_pass 138 "accounts in /etc/passwd use shadowed passwords (*)"
fi

if awk -F: '($2 == "") { print $1 }' /etc/master.passwd 2>/dev/null | grep -q .; then
    sec_audit_report_fail 139 "empty password fields in /etc/master.passwd"
else
    sec_audit_report_pass 139 "/etc/master.passwd password fields are not empty"
fi

bad140=$(awk -F: 'NR==FNR { g[$3]=1; next } !($4 in g) { print $4 }' /etc/group /etc/passwd 2>/dev/null | sort -u | tr '\n' ',')
if [ -n "$bad140" ]; then sec_audit_report_fail 140 "GIDs missing from /etc/group: ${bad140}"
else sec_audit_report_pass 140 "all groups in /etc/passwd exist in /etc/group"; fi

if awk -F: '{print $3}' /etc/passwd 2>/dev/null | sort | uniq -c | awk '$1>1{f=1} END{exit f?0:1}'; then
    sec_audit_report_fail 141 "duplicate UIDs exist"
else
    sec_audit_report_pass 141 "no duplicate UIDs"
fi

if awk -F: '{print $3}' /etc/group 2>/dev/null | sort | uniq -c | awk '$1>1{f=1} END{exit f?0:1}'; then
    sec_audit_report_fail 142 "duplicate GIDs exist"
else
    sec_audit_report_pass 142 "no duplicate GIDs"
fi

if awk -F: '{print $1}' /etc/passwd 2>/dev/null | sort | uniq -c | awk '$1>1{f=1} END{exit f?0:1}'; then
    sec_audit_report_fail 143 "duplicate user names exist"
else
    sec_audit_report_pass 143 "no duplicate user names"
fi

if awk -F: '{print $1}' /etc/group 2>/dev/null | sort | uniq -c | awk '$1>1{f=1} END{exit f?0:1}'; then
    sec_audit_report_fail 144 "duplicate group names exist"
else
    sec_audit_report_pass 144 "no duplicate group names"
fi

rpath=$(su -m root -c 'printf %s "$PATH"' 2>/dev/null || printf '%s' "${PATH}")
ok145=1
IFS=':' read -ra _pp <<<"$rpath"
for p in "${_pp[@]}"; do
    if [ -z "$p" ] || [ "$p" = "." ]; then sec_audit_report_fail 145 "root PATH contains empty or '.'"; ok145=0; break; fi
    if [ ! -d "$p" ]; then sec_audit_report_fail 145 "root PATH entry missing: $p"; ok145=0; break; fi
    o=$(sec_audit_bsd_owner "$p"); m=$(sec_audit_bsd_mode "$p")
    if [ "$o" != root ] || ! sec_audit_mode_le "${m:-777}" 755 || ! sec_audit_mode_no_go_write "${m:-777}"; then
        sec_audit_report_fail 145 "insecure PATH dir $p owner=${o:-?} mode=${m:-?}"
        ok145=0
        break
    fi
done
[ $ok145 -eq 1 ] && sec_audit_report_pass 145 "root PATH integrity OK"

u0=$(awk -F: '($3==0){print $1}' /etc/passwd 2>/dev/null | sort | tr '\n' ' ')
u0=$(printf '%s' "$u0" | sed 's/[[:space:]]*$//')
case "$u0" in
    root) sec_audit_report_pass 146 "only root has UID 0" ;;
    "root toor"|"toor root") sec_audit_report_review 146 "UID 0 accounts: ${u0} (FreeBSD toor present)" ;;
    *) sec_audit_report_fail 146 "UID 0 accounts: ${u0}" ;;
esac

ok147=1; detail147=""
while IFS=: read -r user _ uid gid _ home shell; do
    [ -n "$uid" ] || continue
    [ "$uid" -ge 1000 ] 2>/dev/null || continue
    [ "$uid" -lt 65534 ] 2>/dev/null || continue
    case "$shell" in */nologin|/bin/false) continue ;; esac
    if [ ! -d "$home" ]; then
        ok147=0
        detail147="${detail147}home missing for ${user} (${home}); "
        continue
    fi
    o=$(sec_audit_bsd_owner "$home"); g=$(sec_audit_bsd_group "$home"); m=$(sec_audit_bsd_mode "$home")
    if [ "$o" != "$user" ] || ! sec_audit_mode_le "${m:-777}" 755; then
        ok147=0
        detail147="${detail147}${user} home ${home} owner=${o:-?} mode=${m:-?}; "
    fi
done < /etc/passwd
if [ $ok147 -eq 1 ]; then sec_audit_report_pass 147 "local interactive user home directories configured"
else sec_audit_report_fail 147 "${detail147}"; fi

ok148=1; detail148=""
while IFS=: read -r user _ uid gid _ home shell; do
    [ -n "$uid" ] || continue
    [ "$uid" -ge 1000 ] 2>/dev/null || continue
    [ "$uid" -lt 65534 ] 2>/dev/null || continue
    case "$shell" in */nologin|/bin/false) continue ;; esac
    [ -d "$home" ] || continue
    for bad in .forward .rhost .rhosts .netrc; do
        if [ -e "$home/$bad" ]; then
            ok148=0
            detail148="${detail148}${user} has ${home}/${bad}; "
        fi
    done
    for f in "$home"/.[!.]*; do
        [ -f "$f" ] || continue
        base=$(basename "$f")
        m=$(sec_audit_bsd_mode "$f"); o=$(sec_audit_bsd_owner "$f")
        if [ "$o" != "$user" ]; then
            ok148=0
            detail148="${detail148}${f} owner=${o}; "
            continue
        fi
        case "$base" in
            .sh_history|.history|.bash_history)
                sec_audit_mode_le "${m:-777}" 600 || { ok148=0; detail148="${detail148}${f} mode=${m}; "; }
                ;;
            *)
                sec_audit_mode_le "${m:-777}" 644 || { ok148=0; detail148="${detail148}${f} mode=${m}; "; }
                ;;
        esac
    done
done < /etc/passwd
if [ $ok148 -eq 1 ]; then sec_audit_report_pass 148 "local interactive user dot files access configured"
else sec_audit_report_fail 148 "${detail148}"; fi

exit 0
