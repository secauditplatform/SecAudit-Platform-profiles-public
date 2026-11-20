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

export LC_ALL=C

if [ -z "${BASH_VERSION:-}" ]; then
    if command -v bash >/dev/null 2>&1; then
        exec bash "$0" "$@"
    fi
    printf '%s\n' "ERROR: bash is required." >&2
    exit 1
fi

set +e

sec_audit_have_bin() { command -v "$1" >/dev/null 2>&1; }
sec_audit_log() { printf '[remediation] %s\n' "$*"; }

sec_audit_pkg_install() {
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" >/dev/null 2>&1 || true
}

sec_audit_pkg_remove() {
    local p
    for p in "$@"; do
        dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q "install ok installed" || continue
        DEBIAN_FRONTEND=noninteractive apt-get remove -y "$p" >/dev/null 2>&1 || true
    done
}

sec_audit_start_svc() {
    local u="$1"
    sec_audit_have_bin systemctl || return 0
    systemctl enable "$u" >/dev/null 2>&1 || true
    systemctl start "$u" >/dev/null 2>&1 || true
}

sec_audit_disable_svc() {
    local u="$1"
    sec_audit_have_bin systemctl || return 0
    systemctl disable --now "$u" >/dev/null 2>&1 || true
}

sec_audit_disable_kmod() {
    local mod="$1" f="/etc/modprobe.d/-${mod}.conf"
    [[ -f "$f" ]] && grep -q "blacklist ${mod}" "$f" 2>/dev/null && return 0
    { echo "install ${mod} /bin/false"; echo "blacklist ${mod}"; } >"$f"
    if lsmod 2>/dev/null | awk '{print $1}' | grep -qx "$mod"; then
        modprobe -r "$mod" >/dev/null 2>&1 || rmmod "$mod" >/dev/null 2>&1 || true
    fi
}

sec_audit_ensure_fstab_mount() {
    local mp="$1" opts="$2"
    if grep -qE "^[^#[:space:]]+[[:space:]]+${mp}[[:space:]]+" /etc/fstab 2>/dev/null; then
        if ! grep -E "^[^#[:space:]]+[[:space:]]+${mp}[[:space:]]+" /etc/fstab | grep -q "$opts"; then
            sed -i "s|^\([^#].*[[:space:]]${mp}[[:space:]].*\)$|\1,${opts}|" /etc/fstab 2>/dev/null || true
        fi
    else
        echo "tmpfs ${mp} tmpfs defaults,${opts} 0 0" >>/etc/fstab
    fi
    mountpoint -q "$mp" 2>/dev/null && mount -o remount,${opts} "$mp" >/dev/null 2>&1 || mount "$mp" >/dev/null 2>&1 || true
}

ensure_mount_option() {
    local mp="$1" opt="$2"
    if grep -qE "^[^#[:space:]]+[[:space:]]+${mp}[[:space:]]+" /etc/fstab 2>/dev/null; then
        if ! grep -E "^[^#[:space:]]+[[:space:]]+${mp}[[:space:]]+" /etc/fstab | grep -qE "(^|,)${opt}(,|$)"; then
            sed -i "s|^\([^#].*[[:space:]]${mp}[[:space:]]+.*\)$|\1,${opt}|" /etc/fstab 2>/dev/null || true
        fi
        mountpoint -q "$mp" 2>/dev/null && mount -o remount,${opt} "$mp" >/dev/null 2>&1 || true
    fi
}

set_sysctl() {
    local key="$1" val="$2" f="/etc/sysctl.d/99-debian10-cre-sec.conf"
    mkdir -p /etc/sysctl.d
    if [[ -f "$f" ]] && grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$f"; then
        sed -i "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${val}|" "$f"
    else
        echo "${key} = ${val}" >>"$f"
    fi
    sysctl -w "${key}=${val}" >/dev/null 2>&1 || true
}

set_sshd_kv() {
    local key="$1" val="$2" f=/etc/ssh/sshd_config
    [[ -f $f ]] || return 0
    if grep -qE "^[[:space:]]*#?[[:space:]]*${key}[[:space:]]" "$f"; then
        sed -i "s/^[[:space:]]*#\?[[:space:]]*${key}.*/${key} ${val}/" "$f"
    else
        echo "${key} ${val}" >>"$f"
    fi
}

set_login_defs_kv() {
    local key="$1" val="$2" f=/etc/login.defs
    [[ -f $f ]] || return 0
    if grep -qE "^${key}[[:space:]]" "$f"; then
        sed -i "s/^${key}[[:space:]].*/${key}   ${val}/" "$f"
    else
        echo "${key}   ${val}" >>"$f"
    fi
}

harden_file() {
    local path="$1" mode="$2" owner="${3:-root:root}"
    [[ -e "$path" ]] || return 0
    chmod "$mode" "$path" 2>/dev/null || true
    chown "$owner" "$path" 2>/dev/null || true
}

pam_faillock_debian() {
    local f=/etc/pam.d/common-auth
    [[ -f $f ]] || return 0
    grep -q pam_faillock "$f" 2>/dev/null || {
        sed -i '1i auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900' "$f" 2>/dev/null || true
        sed -i '1i auth required pam_faillock.so authfail audit deny=5 unlock_time=900' "$f" 2>/dev/null || true
    }
    mkdir -p /etc/security
    cat >/etc/security/faillock.conf <<'EOF'
deny = 5
unlock_time = 900
fail_interval = 900
EOF
}

rem_skip() { sec_audit_log "REMEDIATE RULE${1}= SKIP: manual step required - ${2}"; }
rem_done() { sec_audit_log "REMEDIATE RULE${1}= applied: ${2}"; }

sec_audit_log "starting remediation (sec_Debian_Linux_10_v2.0.0)"

# RULE1:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 1; then
rem_skip 1 "review remediation: The squashfs kernel module is not available"

fi
# RULE2:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 2; then
rem_skip 2 "review remediation: The squashfs kernel module is not available"

fi
# RULE3:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 3; then
rem_skip 3 "review remediation: The jffs2 kernel module is not available"

fi
# RULE4:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 4; then
rem_skip 4 "review remediation: The hfs kernel module is not available"

fi
# RULE5:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 5; then
rem_skip 5 "review remediation: The hfsplus kernel module is not available"

fi
# RULE6:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 6; then
rem_skip 6 "review remediation: The squashfs kernel module is not available"

fi
# RULE7:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 7; then
rem_skip 7 "review remediation: The udf kernel module is not available"

fi
# RULE8:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 8; then
rem_skip 8 "review remediation: A separate partition exists for /tmp is configured"

fi
# RULE9:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 9; then
rem_skip 9 "review remediation: The nodev option is set on the /tmp partition is configured"

fi
# RULE10:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 10; then
rem_skip 10 "review remediation: The nosuid option is set on the /tmp partition is configured"

fi
# RULE11:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 11; then
rem_skip 11 "review remediation: The noexec option is set on the /tmp partition is configured"

fi
# RULE12:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 12; then
rem_skip 12 "review remediation: The nodev option is set on the /dev/shm partition is configured"

fi
# RULE13:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 13; then
rem_skip 13 "review remediation: The nosuid option is set on the /dev/shm partition is configured"

fi
# RULE14:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 14; then
rem_skip 14 "review remediation: The noexec option is set on the /dev/shm partition is configured"

fi
# RULE15:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 15; then
rem_skip 15 "review remediation: A separate partition exists for /var is configured"

fi
# RULE16:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 16; then
rem_skip 16 "review remediation: A separate partition exists for /var /tmp is configured"

fi
# RULE17:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 17; then
sec_audit_pkg_install auditd audispd-plugins
sec_audit_start_svc auditd
rem_done 17 "auditd running"

fi
# RULE18:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 18; then
rem_skip 18 "review remediation: The nosuid option is set on the /var/tmp partition is configured"

fi
# RULE19:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 19; then
rem_skip 19 "review remediation: The noexec parameter is set on the /var/tmp partition is configured"

fi
# RULE20:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 20; then
ensure_mount_option /dev/shm noexec
rem_done 20 "set noexec on /dev/shm"

fi
# RULE21:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 21; then
ensure_mount_option /dev/shm nodev
rem_done 21 "set nodev on /dev/shm"

fi
# RULE22:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 22; then
rem_skip 22 "Ensure nosuid option set on /dev/shm partition"

fi
# RULE23:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 23; then
rem_skip 23 "review remediation: The nodev mount option is set on /var"

fi
# RULE24:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 24; then
rem_skip 24 "review remediation: The sticky bit is set on all world-writable directories is configured"

fi
# RULE25:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 25; then
rem_skip 25 "review remediation: GPG keys are configured"

fi
# RULE26:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 26; then
rem_skip 26 "review remediation: GPG keys are configured"

fi
# RULE27:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 27; then
rem_skip 27 "review remediation: AIDE is installed is configured"

fi
# RULE28:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 28; then
rem_skip 28 "review remediation: File system integrity is checked regularly is configured"

fi
# RULE29:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 29; then
harden_file /boot/grub2/grub.cfg 600 root:root
harden_file /boot/grub2/user.cfg 600 root:root
rem_done 29 "hardened grub permissions"

fi
# RULE30:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 30; then
rem_skip 30 "review remediation: Bootloader configuration permissions are configured"

fi
# RULE31:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 31; then
rem_skip 31 "review remediation: The bootloader password is set is configured"

fi
# RULE32:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 32; then
rem_skip 32 "review remediation: The bootloader password is set is configured"

fi
# RULE33:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 33; then
rem_skip 33 "review remediation: XD/NX support is enabled"

fi
# RULE34:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 34; then
rem_skip 34 "review remediation: XD/NX support is enabled"

fi
# RULE35:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 35; then
rem_skip 35 "review remediation: Address space layout randomization (ASLR) is enabled"

fi
# RULE36:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 36; then
rem_skip 36 "review remediation: XD/NX support is enabled"

fi
# RULE37:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 37; then
rem_skip 37 "review remediation: Single-user mode requires authentication is configured"

fi
# RULE38:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 38; then
rem_skip 38 "review remediation: Prelinking is disabled"

fi
# RULE39:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 39; then
rem_skip 39 "review remediation: Core dumps are restricted is configured"

fi
# RULE40:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 40; then
rem_skip 40 "review remediation: SELinux is not disabled in the bootloader configuration is configured"

fi
# RULE41:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 41; then
rem_skip 41 "review remediation: The SELinux state is enforcing is configured"

fi
# RULE42:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 42; then
rem_skip 42 "review remediation: The SELinux state is enforcing is configured"

fi
# RULE43:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 43; then
rem_skip 43 "review remediation: The message of the day is configured correctly"

fi
# RULE44:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 44; then
rem_skip 44 "review remediation: The local login warning banner is configured correctly"

fi
# RULE45:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 45; then
rem_skip 45 "review remediation: The remote login warning banner is configured correctly"

fi
# RULE46:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 46; then
rem_skip 46 "review remediation: Permissions for /etc/motd are configured"

fi
# RULE47:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 47; then
rem_skip 47 "review remediation: Permissions for /etc/issue are configured"

fi
# RULE48:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 48; then
rem_skip 48 "review remediation: Updates, patches, and additional security software are installed is configured"

fi
# RULE49:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 49; then
rem_skip 49 "review remediation: Updates, patches, and additional security software are installed is configured"

fi
# RULE50:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 50; then
rem_skip 50 "review remediation: Time synchronization is used is configured"

fi
# RULE51:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 51; then
rem_skip 51 "review remediation: Time synchronization is used is configured"

fi
# RULE52:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 52; then
rem_skip 52 "review remediation: Chrony is configured"

fi
# RULE53:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 53; then
rem_skip 53 "review remediation: NTP is configured"

fi
# RULE54:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 54; then
rem_skip 54 "review remediation: The X Window System is not installed is configured"

fi
# RULE55:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 55; then
rem_skip 55 "review remediation: The Avahi server is not enabled is configured"

fi
# RULE56:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 56; then
rem_skip 56 "review remediation: CUPS is not enabled is configured"

fi
# RULE57:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 57; then
rem_skip 57 "review remediation: The DHCP server is not enabled is configured"

fi
# RULE58:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 58; then
rem_skip 58 "review remediation: The LDAP server is not enabled is configured"

fi
# RULE59:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 59; then
rem_skip 59 "review remediation: NFS and RPC are not enabled is configured"

fi
# RULE60:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 60; then
rem_skip 60 "review remediation: The FTP server is not enabled is configured"

fi
# RULE61:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 61; then
rem_skip 61 "review remediation: The HTTP server is not enabled is configured"

fi
# RULE62:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 62; then
rem_skip 62 "review remediation: Unused IMAP and POP3 server is not disabled is configured"

fi
# RULE63:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 63; then
rem_skip 63 "review remediation: Samba is not enabled is configured"

fi
# RULE64:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 64; then
rem_skip 64 "review remediation: The HTTP proxy server is not enabled is configured"

fi
# RULE65:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 65; then
rem_skip 65 "review remediation: The SNMP server is not enabled is configured"

fi
# RULE66:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 66; then
rem_skip 66 "review remediation: The mail transfer agent is configured for local-only mode"

fi
# RULE67:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 67; then
rem_skip 67 "review remediation: The rsync service is not enabled is configured"

fi
# RULE68:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 68; then
rem_skip 68 "review remediation: Unless the system is specifically intended to operate as a DNS server, it is recommended to remove the package to reduce the potential attack surface"

fi
# RULE69:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 69; then
rem_skip 69 "review remediation: The NIS client is not installed is configured"

fi
# RULE70:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 70; then
rem_skip 70 "review remediation: The rsh client is not installed is configured"

fi
# RULE71:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 71; then
rem_skip 71 "review remediation: The talk client is not installed is configured"

fi
# RULE72:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 72; then
rem_skip 72 "review remediation: The telnet client is not installed is configured"

fi
# RULE73:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 73; then
rem_skip 73 "review remediation: The LDAP client is not installed is configured"

fi
# RULE74:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 74; then
set_sysctl net.ipv4.ip_forward 0
rem_done 74 "set net.ipv4.ip_forward=0"

fi
# RULE75:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 75; then
rem_skip 75 "review remediation: Packet forwarding is disabled"

fi
# RULE76:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 76; then
rem_skip 76 "review remediation: Source routed packets are not accepted is configured"

fi
# RULE77:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 77; then
set_sysctl net.ipv4.conf.all.accept_redirects 0
rem_done 77 "set net.ipv4.conf.all.accept_redirects=0"

fi
# RULE78:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 78; then
rem_skip 78 "review remediation: Secure ICMP redirects are not accepted is configured"

fi
# RULE79:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 79; then
rem_skip 79 "review remediation: Suspicious packets are logged is configured"

fi
# RULE80:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 80; then
rem_skip 80 "review remediation: ICMP broadcast requests are ignored is configured"

fi
# RULE81:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 81; then
set_sysctl net.ipv4.icmp_ignore_bogus_error_responses 1
rem_done 81 "set net.ipv4.icmp_ignore_bogus_error_responses=1"

fi
# RULE82:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 82; then
set_sysctl net.ipv4.conf.all.rp_filter 1
rem_done 82 "set net.ipv4.conf.all.rp_filter=1"

fi
# RULE83:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 83; then
set_sysctl net.ipv4.tcp_syncookies 1
rem_done 83 "set net.ipv4.tcp_syncookies=1"

fi
# RULE84:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 84; then
rem_skip 84 "review remediation: IPv6 router advertisements are not accepted is configured"

fi
# RULE85:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 85; then
rem_skip 85 "review remediation: DCCP is disabled"

fi
# RULE86:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 86; then
rem_skip 86 "review remediation: SCTP is disabled"

fi
# RULE87:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 87; then
rem_skip 87 "review remediation: RDS is disabled"

fi
# RULE88:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 88; then
rem_skip 88 "review remediation: TIPC is disabled"

fi
# RULE89:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 89; then
sec_audit_pkg_install nftables
systemctl enable --now nftables >/dev/null 2>&1 || true
rem_done 89 "nftables baseline"

fi
# RULE90:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 90; then
rem_skip 90 "review remediation: The Audit service is enabled"

fi
# RULE91:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 91; then
rem_skip 91 "review remediation: The audit log storage size is configured"

fi
# RULE92:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 92; then
sec_audit_pkg_install auditd audispd-plugins
sec_audit_start_svc auditd
rem_done 92 "auditd running"

fi
# RULE93:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 93; then
sec_audit_pkg_install auditd audispd-plugins
sec_audit_start_svc auditd
rem_done 93 "auditd running"

fi
# RULE94:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 94; then
sec_audit_pkg_install auditd audispd-plugins
sec_audit_start_svc auditd
rem_done 94 "auditd running"

fi
# RULE95:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 95; then
sec_audit_pkg_install auditd audispd-plugins
sec_audit_start_svc auditd
rem_done 95 "auditd running"

fi
# RULE96:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 96; then
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
rem_done 96 "rsyslog installed"

fi
# RULE97:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 97; then
rem_skip 97 "review remediation: Default rsyslog file permissions are configured"

fi
# RULE98:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 98; then
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
rem_done 98 "rsyslog installed"

fi
# RULE99:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 99; then
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
rem_done 99 "rsyslog installed"

fi
# RULE100:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 100; then
rem_skip 100 "review remediation: Cron daemon is enabled"

fi
# RULE101:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 101; then
chmod 600 /etc/crontab 2>/dev/null || true
chown root:root /etc/crontab 2>/dev/null || true
rem_done 101 "restricted /etc/crontab"

fi
# RULE102:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 102; then
rem_skip 102 "review remediation: Permissions for /etc/cron.hourly is configured"

fi
# RULE103:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 103; then
rem_skip 103 "review remediation: Permissions for /etc/cron.daily is configured"

fi
# RULE104:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 104; then
rem_skip 104 "review remediation: Permissions for /etc/cron.weekly is configured"

fi
# RULE105:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 105; then
rem_skip 105 "review remediation: Permissions for /etc/cron.monthly is configured"

fi
# RULE106:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 106; then
chmod 600 /etc/crontab 2>/dev/null || true
chown root:root /etc/crontab 2>/dev/null || true
rem_done 106 "restricted /etc/crontab"

fi
# RULE107:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 107; then
rem_skip 107 "review remediation: Access to /cron is permitted only for authorized users"

fi
# RULE108:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 108; then
rem_skip 108 "review remediation: Permissions for /etc/ssh/sshd_config is configured"

fi
# RULE109:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 109; then
rem_skip 109 "review remediation: SSH version 2 is used is configured"

fi
# RULE110:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 110; then
rem_skip 110 "review remediation: SSH LogLevel is set to INFO is configured"

fi
# RULE111:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 111; then
rem_skip 111 "review remediation: Disable unused filesystems"

fi
# RULE112:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 112; then
sec_audit_ensure_fstab_mount /tmp "nodev,nosuid,noexec"
rem_done 112 "configured mount /tmp"

fi
# RULE113:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 113; then
rem_skip 113 "review remediation: Configure /var"

fi
# RULE114:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 114; then
rem_skip 114 "review remediation: Configure /var/tmp"

fi
# RULE115:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 115; then
rem_skip 115 "review remediation: Configure /var/sec_audit_log"

fi
# RULE116:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 116; then
rem_skip 116 "create separate partition for /var during provisioning; then set mount options"

fi
# RULE117:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 117; then
rem_skip 117 "create separate partition for /var/tmp during provisioning; then set mount options"

fi
# RULE118:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 118; then
rem_skip 118 "create separate partition for /var/sec_audit_log during provisioning; then set mount options"

fi
# RULE119:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 119; then
rem_skip 119 "create separate partition for /var/sec_audit_log/audit during provisioning; then set mount options"

fi
# RULE120:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 120; then
set_sshd_kv ClientAliveInterval 300
rem_done 120 "sshd ClientAliveInterval"

fi
# RULE121:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 121; then
rem_skip 121 "review remediation: SSH warning banner is configured"

fi
# RULE122:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 122; then
sec_audit_pkg_install aide
rem_done 122 "installed AIDE"

fi
# RULE123:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 123; then
sec_audit_pkg_install aide afick
rem_done 123 "integrity tooling"

fi
# RULE124:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 124; then
rem_skip 124 "review remediation: Password reuse restrictions"

fi
# RULE125:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 125; then
set_login_defs_kv ENCRYPT_METHOD SHA512
rem_done 125 "ENCRYPT_METHOD SHA512"

fi
# RULE126:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 126; then
rem_skip 126 "review remediation: Password expiration warning period"

fi
# RULE127:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 127; then
rem_skip 127 "review remediation: Password lifetime does not exceed 365 days"

fi
# RULE128:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 128; then
set_login_defs_kv PASS_WARN_AGE 7
rem_done 128 "PASS_WARN_AGE 7"

fi
# RULE129:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 129; then
rem_skip 129 "review remediation: Lock inactive passwords"

fi
# RULE130:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 130; then
rem_skip 130 "review remediation: Lock inactive passwords"

fi
# RULE131:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 131; then
rem_skip 131 "review remediation: Default group for the root account GID 0"

fi
# RULE132:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 132; then
rem_skip 132 "review remediation: Ensure updates, patches, and additional security software are installed"

fi
# RULE133:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 133; then
rem_skip 133 "Ensure package manager repositories are configured"

fi
# RULE134:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 134; then
rem_skip 134 "Ensure GPG keys are configured"

fi
# RULE135:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 135; then
rem_skip 135 "review remediation: Permissions for /etc/passwd- is configured"

fi
# RULE136:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 136; then
rem_skip 136 "review remediation: Permissions for /etc/group is configured"

fi
# RULE137:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 137; then
rem_skip 137 "review remediation: Permissions for /etc/shadow- is configured"

fi
# RULE138:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 138; then
rem_skip 138 "review remediation: Permissions for /etc/shadow is configured"

fi
# RULE139:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 139; then
rem_skip 139 "review remediation: Permissions for /etc/passwd- is configured"

fi
# RULE140:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 140; then
rem_skip 140 "review remediation: Permissions for /etc/gshadow is configured"

fi
# RULE141:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 141; then
rem_skip 141 "review remediation: Permissions for /etc/gshadow- is configured"

fi
# RULE142:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 142; then
rem_skip 142 "review remediation: There are no world-writable files"

fi
# RULE143:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 143; then
rem_skip 143 "review remediation: No unused files or directories exist"

fi
# RULE144:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 144; then
rem_skip 144 "review remediation: No unused files or directories exist"

fi
# RULE145:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 145; then
rem_skip 145 "review remediation: Audit SUID executable files"

fi
# RULE146:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 146; then
rem_skip 146 "review remediation: Audit SGID executable files"

fi
# RULE147:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 147; then
rem_skip 147 "review remediation: Password fields are not empty"

fi
# RULE148:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 148; then
rem_skip 148 "review remediation: Root is the only UID 0 account"

fi
# RULE149:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 149; then
rem_skip 149 "Ensure bootloader password is set"

fi
# RULE150:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 150; then
rem_skip 150 "review remediation: Permissions on /etc/gshadow are configured correctly"

fi
# RULE151:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 151; then
harden_file /boot/grub2/grub.cfg 600 root:root
harden_file /boot/grub2/user.cfg 600 root:root
rem_done 151 "hardened grub permissions"

fi
# RULE152:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 152; then
rem_skip 152 "review remediation: Ensure authentication required for single user mode"

fi
# RULE153:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 153; then
rem_skip 153 "review remediation: Time synchronization is used is configured"

fi
# RULE154:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 154; then
rem_skip 154 "review remediation: The password hashing algorithm is SHA-512 is configured"

fi
# RULE155:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 155; then
rem_skip 155 "review remediation: Remove all obsolete \"+\" files"

fi
# RULE156:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 156; then
rem_skip 156 "review remediation: Remove all obsolete \"+\" files"

fi
# RULE157:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 157; then
rem_skip 157 "review remediation: Remove all obsolete \"+\" files"

fi
# RULE158:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 158; then
rem_skip 158 "review remediation: OSSEC is installed is configured"

fi
# RULE159:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 159; then
rem_skip 159 "review remediation: Ensure Automatic Error Reporting is not enabled"

fi
# RULE160:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 160; then
rem_skip 160 "review remediation: Ensure address space layout randomization (ASLR) is enabled"

fi
# RULE161:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 161; then
set_sysctl kernel.yama.ptrace_scope 1
rem_done 161 "set kernel.yama.ptrace_scope=1"

fi
# RULE162:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 162; then
rem_skip 162 "review remediation: Ensure prelink is not installed"

fi
# RULE163:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 163; then
grep -q "hard core" /etc/security/limits.conf 2>/dev/null || echo "* hard core 0" >>/etc/security/limits.conf
mkdir -p /etc/systemd/coredump.conf.d
cat >/etc/systemd/coredump.conf.d/99-cre-sec.conf <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
sec_audit_have_bin systemctl && systemctl daemon-reload >/dev/null 2>&1 || true
rem_done 163 "disabled core dumps"

fi
# RULE164:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 164; then
rem_skip 164 "review remediation: Remove all obsolete "+" files"

fi
# RULE165:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 165; then
rem_skip 165 "review remediation: Remove all obsolete "+" files"

fi
# RULE166:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 166; then
rem_skip 166 "review remediation: Xinetd is not enabled is configured"

fi
# RULE167:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 167; then
rem_skip 167 "review remediation: NFS and RPC are not enabled is configured"

fi
# RULE168:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 168; then
sec_audit_pkg_install aide afick
rem_done 168 "integrity tooling"

fi
# RULE169:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 169; then
sec_audit_pkg_install aide afick
rem_done 169 "integrity tooling"

fi
# RULE170:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 170; then
sec_audit_pkg_install aide afick
rem_done 170 "integrity tooling"

fi
# RULE171:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 171; then
sec_audit_pkg_install aide afick
rem_done 171 "integrity tooling"

fi
# RULE172:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 172; then
pam_faillock_debian >/dev/null 2>&1 || true
rem_done 172 "pam faillock"

fi
# RULE173:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 173; then
sec_audit_pkg_install libpam-pwquality
cat >/etc/security/pwquality.conf <<'EOF'
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF
rem_done 173 "password quality"

fi
# RULE174:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 174; then
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
rem_done 174 "rsyslog installed"

fi
# RULE175:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 175; then
rem_skip 175 "review remediation: NTP is configured"

fi
# RULE176:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 176; then
rem_skip 176 "review remediation: Ensure password creation requirements are configured"

fi
# RULE177:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 177; then
pam_faillock_debian >/dev/null 2>&1 || true
rem_done 177 "pam faillock"

fi
# RULE178:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 178; then
rem_skip 178 "review remediation: Ensure password reuse is limited"

fi
# RULE179:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 179; then
set_login_defs_kv ENCRYPT_METHOD SHA512
rem_done 179 "ENCRYPT_METHOD SHA512"

fi
# RULE180:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 180; then
sec_audit_pkg_install sudo
rem_done 180 "sudo installed"

fi
# RULE181:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 181; then
rem_skip 181 "review remediation: Ensure sudo commands use pty"

fi
# RULE182:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 182; then
rem_skip 182 "review remediation: Ensure sudo sec_audit_log file exists"

fi
# RULE183:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 183; then
rem_skip 183 "review remediation: Ensure users must provide password for privilege escalation"

fi
# RULE184:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 184; then
rem_skip 184 "review remediation: Set Shadow Password Suite Parameters"

fi
# RULE185:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 185; then
rem_skip 185 "Ensure system accounts are secured"

fi
# RULE186:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 186; then
rem_skip 186 "Ensure default group for the root account is GID 0"

fi
# RULE187:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 187; then
set_login_defs_kv UMASK 027
cat >/etc/profile.d/99-cre-umask.sh <<'EOF'
umask 027
EOF
rem_done 187 "default umask 027"

fi
# RULE188:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 188; then
rem_skip 188 "review remediation: Disable USB Storage"

fi
# RULE189:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 189; then
sec_audit_pkg_install auditd audispd-plugins
sec_audit_start_svc auditd
rem_done 189 "auditd running"

fi
# RULE190:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 190; then
sec_audit_pkg_install auditd audispd-plugins
sec_audit_start_svc auditd
rem_done 190 "auditd running"

fi
# RULE191:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 191; then
rem_skip 191 "review remediation: Ensure audit_backlog_limit is sufficient"

fi
# RULE192:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 192; then
rem_skip 192 "review remediation: Ensure events that modify date and time information are collected"

fi
# RULE193:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 193; then
rem_skip 193 "Ensure events that modify user/group information are collected"

fi
# RULE194:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 194; then
rem_skip 194 "review remediation: Ensure login and logout events are collected"

fi
# RULE195:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 195; then
rem_skip 195 "review remediation: Ensure session initiation information is collected"

fi
# RULE196:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 196; then
rem_skip 196 "review remediation: Ensure use of privileged commands are collected"

fi
# RULE197:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 197; then
rem_skip 197 "review remediation: Ensure file deletion events by users are collected"

fi
# RULE198:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 198; then
rem_skip 198 "review remediation: Ensure changes to system administration scope (sudoers) is collected"

fi
# RULE199:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 199; then
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
rem_done 199 "rsyslog installed"

fi
# RULE200:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 200; then
rem_skip 200 "review remediation: Ensure permissions on SSH private host key files are configured"

fi
# RULE201:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 201; then
rem_skip 201 "review remediation: Ensure permissions on SSH public host key files are configured"

fi
# RULE202:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 202; then
rem_skip 202 "Ensure system accounts are secured"

fi
# RULE203:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 203; then
rem_skip 203 "review remediation: Ensure access to the su command is restricted"

fi
# RULE204:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 204; then
rem_skip 204 "Ensure root PATH Integrity"

fi
# RULE205:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 205; then
rem_skip 205 "Ensure users' dot files are not group or world writable"

fi
# RULE206:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 206; then
rem_skip 206 "Ensure no duplicate UIDs exist"

fi
# RULE207:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 207; then
rem_skip 207 "Ensure no duplicate GIDs exist"

fi
# RULE208:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 208; then
rem_skip 208 "Ensure no duplicate user names exist"

fi
# RULE209:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 209; then
rem_skip 209 "Ensure no duplicate group names exist"

fi
# RULE210:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 210; then
rem_skip 210 "Ensure shadow group is empty"

fi
# RULE211:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 211; then
sec_audit_disable_kmod bluetooth
rem_done 211 "disabled wireless interfaces"

fi
# RULE212:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 212; then
rem_skip 212 "review remediation: Ensure SSH PAM is enabled"

fi
# RULE213:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 213; then
rem_skip 213 "review remediation: Prohibit mounting of cramfs filesystems"

fi
# RULE214:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 214; then
rem_skip 214 "review remediation: /tmp is a separate partition is configured"

fi
# RULE215:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 215; then
rem_skip 215 "review remediation: The nodev option is set for the /var partition is configured"

fi
# RULE216:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 216; then
rem_skip 216 "review remediation: The nosuid option is set for the /var partition is configured"

fi
# RULE217:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 217; then
rem_skip 217 "review remediation: The nodev option is set for the /var/log partition is configured"

fi
# RULE218:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 218; then
rem_skip 218 "review remediation: The noexec option is set for the /var/log partition is configured"

fi
# RULE219:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 219; then
rem_skip 219 "review remediation: The nosuid option is set for the /var/log partition is configured"

fi
# RULE220:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 220; then
rem_skip 220 "review remediation: The nodev option is set on the /var/log/audit partition is configured"

fi
# RULE221:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 221; then
rem_skip 221 "review remediation: The noexec option is set on the /var/log/audit partition is configured"

fi
# RULE222:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 222; then
rem_skip 222 "review remediation: The nosuid option is set on the /var/log/audit partition is configured"

fi
# RULE223:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 223; then
rem_skip 223 "review remediation: The nosuid option is set for the /home partition is configured"

fi
# RULE224:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 224; then
rem_skip 224 "review remediation: The nodev option is set on the /var/log/audit partition is configured"

fi
# RULE225:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 225; then
rem_skip 225 "review remediation: The noexec option is set on the /var/log/audit partition is configured"

fi
# RULE226:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 226; then
rem_skip 226 "review remediation: The nosuid option is set on the /var/log/audit partition is configured"

fi
# RULE227:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 227; then
rem_skip 227 "review remediation: The nosuid option is set for the /home partition is configured"

fi
# RULE228:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 228; then
mkdir -p /etc/dconf/db/gdm.d
sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
rem_done 228 "configured GDM hardening"

fi
# RULE229:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 229; then
rem_skip 229 "review remediation: GPG keys are configured"

fi
# RULE230:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 230; then
rem_skip 230 "review remediation: Ptrace_scope is restricted"

fi
# RULE231:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 231; then
rem_skip 231 "review remediation: Prohibit automatic sending of error reports"

fi
# RULE232:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 232; then
rem_skip 232 "review remediation: Remove GNOME Display Manager (GDM)"

fi
# RULE233:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 233; then
rem_skip 233 "review remediation: The disable-user-list option in GDM is enabled"

fi
# RULE234:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 234; then
rem_skip 234 "review remediation: GDM screen lock on idle is configured"

fi
# RULE235:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 235; then
rem_skip 235 "review remediation: Prohibit canceling GDM screen lock"

fi
# RULE236:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 236; then
rem_skip 236 "review remediation: Automatic mounting of removable media in GDM is disabled"

fi
# RULE237:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 237; then
rem_skip 237 "review remediation: Prohibit overriding the disablement of automount in GDM"

fi
# RULE238:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 238; then
rem_skip 238 "review remediation: The autorun-never option in GDM is enabled"

fi
# RULE239:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 239; then
rem_skip 239 "review remediation: Prohibit overriding autorun-never in GDM"

fi
# RULE240:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 240; then
rem_skip 240 "review remediation: XDMCP is disabled"

fi
# RULE241:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 241; then
rem_skip 241 "review remediation: Only one time synchronization daemon is used is configured"

fi
# RULE242:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 242; then
rem_skip 242 "review remediation: Chrony is configured with an authorized time server"

fi
# RULE243:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 243; then
rem_skip 243 "review remediation: Chrony is run as the _chrony user is configured"

fi
# RULE244:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 244; then
rem_skip 244 "review remediation: Systemd-timesyncd is configured with an authorized time server"

fi
# RULE245:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 245; then
rem_skip 245 "review remediation: NTP access control is configured"

fi
# RULE246:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 246; then
rem_skip 246 "review remediation: NTP is configured with an authorized time server"

fi
# RULE247:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 247; then
rem_skip 247 "review remediation: NTP runs as the ntp user is configured"

fi
# RULE248:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 248; then
rem_skip 248 "review remediation: Avahi server is not installed is configured"

fi
# RULE249:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 249; then
rem_skip 249 "review remediation: CUPS is not installed is configured"

fi
# RULE250:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 250; then
rem_skip 250 "review remediation: DHCP server is not installed is configured"

fi
# RULE251:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 251; then
rem_skip 251 "review remediation: LDAP server is not installed is configured"

fi
# RULE252:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 252; then
rem_skip 252 "review remediation: NFS is not installed is configured"

fi
# RULE253:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 253; then
rem_skip 253 "review remediation: The absence of IMAP and POP3 servers is configured"

fi
# RULE254:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 254; then
rem_skip 254 "review remediation: Dnsmasq is not installed is configured"

fi
# RULE255:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 255; then
sec_audit_disable_kmod bluetooth
sec_audit_pkg_remove bluez
sec_audit_disable_svc bluetooth.service
rem_done 255 "disabled bluetooth"

fi
# RULE256:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 256; then
sec_audit_pkg_install nftables
systemctl enable --now nftables >/dev/null 2>&1 || true
rem_done 256 "nftables baseline"

fi
# RULE257:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 257; then
sec_audit_pkg_install nftables
systemctl enable --now nftables >/dev/null 2>&1 || true
rem_done 257 "nftables baseline"

fi
# RULE258:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 258; then
sec_audit_pkg_install nftables
systemctl enable --now nftables >/dev/null 2>&1 || true
rem_done 258 "nftables baseline"

fi
# RULE259:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 259; then
sec_audit_pkg_install nftables
systemctl enable --now nftables >/dev/null 2>&1 || true
rem_done 259 "nftables baseline"

fi
# RULE260:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 260; then
rem_skip 260 "review remediation: Iptables-persistent is not installed together with ufw is configured"

fi
# RULE261:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 261; then
rem_skip 261 "review remediation: Ufw is removed or disabled when using nftables is configured"

fi
# RULE262:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 262; then
echo "Defaults timestamp_timeout=5" >/etc/sudoers.d/99-cre-timeout
chmod 440 /etc/sudoers.d/99-cre-timeout
rem_done 262 "sudo timestamp_timeout=5"

fi
# RULE263:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 263; then
rem_skip 263 "review remediation: Ufw is removed or disabled when using iptables is configured"

fi
# RULE264:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 264; then
rem_skip 264 "review remediation: Users must provide a password to elevate privileges is configured"

fi
# RULE265:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 265; then
rem_skip 265 "review remediation: Re-authentication for privilege elevation is not disabled globally is configured"

fi
# RULE266:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 266; then
rem_skip 266 "review remediation: The sudo authentication timeout is configured correctly"

fi
# RULE267:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 267; then
rem_skip 267 "review remediation: All current passwords use the configured hashing algorithm is configured"

fi
# RULE268:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 268; then
rem_skip 268 "review remediation: The minimum number of changed characters in a new password is configured"

fi
# RULE269:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 269; then
rem_skip 269 "review remediation: Dictionary words are prohibited in passwords is configured"

fi
# RULE270:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 270; then
rem_skip 270 "review remediation: Nologin is not listed in /etc/shells is configured"

fi
# RULE271:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 271; then
rem_skip 271 "review remediation: The maximum number of identical consecutive characters in a password is configured"

fi
# RULE272:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 272; then
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
rem_done 272 "rsyslog installed"

fi
# RULE273:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 273; then
rem_skip 273 "review remediation: Systemd-journal-remote is configured"

fi
# RULE274:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 274; then
rem_skip 274 "review remediation: Systemd-journal-remote is enabled"

fi
# RULE275:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 275; then
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
rem_done 275 "rsyslog installed"

fi
# RULE276:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 276; then
rem_skip 276 "review remediation: Journald is not configured to send logs to rsyslog is configured"

fi
# RULE277:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 277; then
rem_skip 277 "review remediation: Journald log rotation is configured according to site policy"

fi
# RULE278:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 278; then
rem_skip 278 "review remediation: Permissions on journald log files are configured correctly"

fi
# RULE279:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 279; then
rem_skip 279 "review remediation: Rsyslog is not configured to receive logs from remote clients is configured"

fi
# RULE280:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 280; then
rem_skip 280 "review remediation: Successful and unsuccessful attempts to use the chcon command are recorded is configured"

fi
# RULE281:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 281; then
rem_skip 281 "review remediation: Successful and unsuccessful attempts to use the setfacl command are recorded is configured"

fi
# RULE282:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 282; then
rem_skip 282 "review remediation: Successful and unsuccessful attempts to use the chacl command are recorded is configured"

fi
# RULE283:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 283; then
rem_skip 283 "review remediation: Successful and unsuccessful attempts to use the usermod command are recorded is configured"

fi
# RULE284:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 284; then
rem_skip 284 "review remediation: The current and saved audit configurations match is configured"

fi
# RULE285:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 285; then
rem_skip 285 "review remediation: Audit configuration files have permissions of 640 or more restrictive is configured"

fi
# RULE286:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 286; then
rem_skip 286 "review remediation: Audit configuration files are owned by root is configured"

fi
# RULE287:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 287; then
rem_skip 287 "review remediation: Audit configuration files are owned by the root group is configured"

fi
# RULE288:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 288; then
rem_skip 288 "review remediation: Audit tools have permissions of 755 or more restrictive is configured"

fi
# RULE289:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 289; then
rem_skip 289 "review remediation: Audit tools are owned by the root user is configured"

fi
# RULE290:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 290; then
rem_skip 290 "review remediation: Audit tools are owned by the root group is configured"

fi
# RULE291:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 291; then
rem_skip 291 "review remediation: Cryptographic mechanisms are used to protect the integrity of audit tools is configured"

DEBIAN_FRONTEND=noninteractive apt-get update >/dev/null 2>&1 || true
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y >/dev/null 2>&1 || true

sec_audit_log " remediation complete (Debian10_remediation.sh)"
exit 0

fi
