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
    sec_audit_have_bin dnf || return 0
    dnf install -y "$@" >/dev/null 2>&1 || true
}

sec_audit_pkg_remove() {
    local p
    sec_audit_have_bin dnf || return 0
    for p in "$@"; do
        rpm -q "$p" &>/dev/null || continue
        dnf remove -y "$p" >/dev/null 2>&1 || true
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

sec_audit_disable_kernel_module() {
    local mod="$1"
    local f="/etc/modprobe.d/sec-audit-disable-${mod}.conf"
    [[ -d /etc/modprobe.d ]] || mkdir -p /etc/modprobe.d
    [[ -f "$f" ]] && grep -q "blacklist ${mod}" "$f" 2>/dev/null && return 0
    {
        echo "install ${mod} /bin/false"
        echo "blacklist ${mod}"
    } >"$f"
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

sec_audit_ensure_mount_option() {
    local mp="$1" opt="$2"
    if grep -qE "^[^#[:space:]]+[[:space:]]+${mp}[[:space:]]+" /etc/fstab 2>/dev/null; then
        if ! grep -E "^[^#[:space:]]+[[:space:]]+${mp}[[:space:]]+" /etc/fstab | grep -qE "(^|,)${opt}(,|$)"; then
            sed -i "s|^\([^#].*[[:space:]]${mp}[[:space:]].*\)$|\1,${opt}|" /etc/fstab 2>/dev/null || true
        fi
        mountpoint -q "$mp" 2>/dev/null && mount -o remount,${opt} "$mp" >/dev/null 2>&1 || true
    fi
}

sec_audit_set_sysctl() {
    local key="$1" val="$2" f="/etc/sysctl.d/99-secaudit-azure-sec.conf"
    mkdir -p /etc/sysctl.d
    if [[ -f "$f" ]] && grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$f"; then
        sed -i "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${val}|" "$f"
    else
        echo "${key} = ${val}" >>"$f"
    fi
    sysctl -w "${key}=${val}" >/dev/null 2>&1 || true
}

sec_audit_set_dnf_main_kv() {
    local key="$1" val="$2" f=/etc/dnf/dnf.conf
    [[ -f $f ]] || return 0
    if grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$f"; then
        sed -i "s/^[[:space:]]*${key}[[:space:]]*=.*/${key}=${val}/" "$f"
    elif grep -qE '^\[main\]' "$f"; then
        sed -i "/^\[main\]/a ${key}=${val}" "$f"
    else
        printf '%s\n%s=%s\n' '[main]' "$key" "$val" >>"$f"
    fi
}

sec_audit_set_sshd_kv() {
    local key="$1" val="$2" f=/etc/ssh/sshd_config
    [[ -f $f ]] || return 0
    if grep -qE "^[[:space:]]*#?[[:space:]]*${key}[[:space:]]" "$f"; then
        sed -i "s/^[[:space:]]*#\?[[:space:]]*${key}.*/${key} ${val}/" "$f"
    else
        echo "${key} ${val}" >>"$f"
    fi
}

sec_audit_set_login_defs_kv() {
    local key="$1" val="$2" f=/etc/login.defs
    [[ -f $f ]] || return 0
    if grep -qE "^${key}[[:space:]]" "$f"; then
        sed -i "s/^${key}[[:space:]].*/${key}   ${val}/" "$f"
    else
        echo "${key}   ${val}" >>"$f"
    fi
}

sec_audit_set_pwquality_kv() {
    local key="$1" val="$2" f=/etc/security/pwquality.conf
    mkdir -p /etc/security/pwquality.conf.d
    if grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$f" 2>/dev/null; then
        sed -i "s/^[[:space:]]*${key}[[:space:]]*=.*/${key} = ${val}/" "$f"
    else
        echo "${key} = ${val}" >>"$f"
    fi
}

sec_audit_set_faillock_kv() {
    local key="$1" val="$2" f=/etc/security/faillock.conf
    mkdir -p /etc/security
    if [[ -f $f ]] && grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$f"; then
        sed -i "s/^[[:space:]]*${key}[[:space:]]*=.*/${key} = ${val}/" "$f"
    else
        echo "${key} = ${val}" >>"$f"
    fi
}

sec_audit_harden_file() {
    local path="$1" mode="$2" owner="${3:-root:root}"
    [[ -e "$path" ]] || return 0
    chmod "$mode" "$path" 2>/dev/null || true
    chown "$owner" "$path" 2>/dev/null || true
}

sec_audit_authselect_enable() {
    local feat="$1" profile
    sec_audit_have_bin authselect || return 0
    profile=$(head -1 /etc/authselect/authselect.conf 2>/dev/null)
    [[ -n $profile ]] || profile=sssd
    if ! authselect current 2>/dev/null | grep -q "$feat"; then
        authselect select "$profile" "$feat" --force >/dev/null 2>&1 || true
    fi
    authselect apply-changes >/dev/null 2>&1 || true
}

sec_audit_remediate_skip() { sec_audit_log "REMEDIATE RULE${1}= SKIP: manual step required - ${2}"; }
sec_audit_remediate_done() { sec_audit_log "REMEDIATE RULE${1}= applied: ${2}"; }

sec_audit_log "starting remediation (sec_AKS_Optimized_Azure_Linux_2_v1.1.0)"

sec_audit_remediate_kernel_modules() {
# RULE1-6
# RULE1:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 1; then
sec_audit_disable_kernel_module cramfs
sec_audit_remediate_done 1 "blacklisted kernel module cramfs"

fi
# RULE2:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 2; then
sec_audit_disable_kernel_module freevxfs
sec_audit_remediate_done 2 "blacklisted kernel module freevxfs"

fi
# RULE3:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 3; then
sec_audit_disable_kernel_module hfs
sec_audit_remediate_done 3 "blacklisted kernel module hfs"

fi
# RULE4:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 4; then
sec_audit_disable_kernel_module hfsplus
sec_audit_remediate_done 4 "blacklisted kernel module hfsplus"

fi
# RULE5:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 5; then
sec_audit_disable_kernel_module jffs2
sec_audit_remediate_done 5 "blacklisted kernel module jffs2"

fi
# RULE6:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 6; then
sec_audit_remediate_skip 6 "unused filesystems kernel modules are not available"

fi
}

sec_audit_remediate_filesystem_partitions() {
# RULE7-12
# RULE7:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 7; then
sec_audit_remediate_skip 7 "/tmp is a separate partition"

fi
# RULE8:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 8; then
sec_audit_ensure_mount_option /tmp nodev
sec_audit_remediate_done 8 "set nodev on /tmp"

fi
# RULE9:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 9; then
sec_audit_remediate_skip 9 "nosuid option set on /tmp partition"

fi
# RULE10:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 10; then
sec_audit_remediate_skip 10 "/dev/shm is a separate partition"

fi
# RULE11:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 11; then
sec_audit_ensure_mount_option /dev/shm nodev
sec_audit_remediate_done 11 "set nodev on /dev/shm"

fi
# RULE12:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 12; then
sec_audit_remediate_skip 12 "nosuid option set on /dev/shm partition"

fi
}

sec_audit_remediate_package_security() {
# RULE13-16
# RULE13:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 13; then
sec_audit_remediate_skip 13 "GPG keys are configured"

fi
# RULE14:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 14; then
sec_audit_set_dnf_main_kv gpgcheck 1
sec_audit_set_dnf_main_kv localpkg_gpgcheck 1
sec_audit_remediate_done 14 "enabled gpgcheck"

fi
# RULE15:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 15; then
sec_audit_remediate_skip 15 "review remediation: TDNF gpgcheck is globally activated"

fi
# RULE16:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 16; then
sec_audit_remediate_skip 16 "package manager repositories are configured"

fi
}

sec_audit_remediate_process_hardening() {
# RULE17-19
# RULE17:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 17; then
sec_audit_remediate_skip 17 "review remediation: address space layout randomization is enabled"

fi
# RULE18:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 18; then
sec_audit_remediate_skip 18 "review remediation: core dump backtraces are disabled"

fi
# RULE19:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 19; then
sec_audit_remediate_skip 19 "review remediation: core dump storage is disabled"

fi
}

sec_audit_remediate_bootloader() {
# RULE20-21
# RULE20:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 20; then
sec_audit_set_sshd_kv Banner /etc/issue.net
sec_audit_remediate_done 20 "sshd Banner"

fi
# RULE21:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 21; then
sec_audit_remediate_skip 21 "remote login warning banner is configured properly"

fi
}

sec_audit_remediate_banners() {
# RULE22-24
# RULE22:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 22; then
sec_audit_harden_file /etc/motd 644 root:root
sec_audit_remediate_done 22 "permissions /etc/motd"

fi
# RULE23:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 23; then
sec_audit_harden_file /etc/issue 644 root:root
sec_audit_remediate_done 23 "permissions /etc/issue"

fi
# RULE24:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 24; then
sec_audit_harden_file /etc/issue.net 644 root:root
sec_audit_remediate_done 24 "permissions /etc/issue.net"

fi
}

sec_audit_remediate_chrony() {
# RULE25-26
# RULE25:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 25; then
sec_audit_pkg_install chrony
sec_audit_start_svc chronyd
sec_audit_remediate_done 25 "installed chrony"

fi
# RULE26:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 26; then
sec_audit_pkg_install chrony
grep -q "^pool \|^server " /etc/chrony.conf 2>/dev/null || echo "pool 2.pool.ntp.org iburst" >>/etc/chrony.conf
sec_audit_start_svc chronyd
sec_audit_remediate_done 26 "configured chrony"

fi
}

sec_audit_remediate_unused_services() {
# RULE27-32
# RULE27:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 27; then
sec_audit_remediate_skip 27 "review remediation: xinetd is not installed"

fi
# RULE28:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 28; then
sec_audit_disable_svc gdm
sec_audit_disable_svc gdm3
sec_audit_pkg_remove xorg-x11-server-Xorg
sec_audit_remediate_done 28 "disabled xorg-x11-server-Xorg"

fi
# RULE29:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 29; then
sec_audit_disable_svc avahi-daemon.socket
sec_audit_disable_svc avahi-daemon.service
sec_audit_pkg_remove avahi
sec_audit_remediate_done 29 "disabled avahi"

fi
# RULE30:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 30; then
sec_audit_remediate_skip 30 "review remediation: a print server is not installed"

fi
# RULE31:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 31; then
sec_audit_disable_svc dhcpd.service
sec_audit_disable_svc dhcpd6.service
sec_audit_pkg_remove dhcp-server
sec_audit_remediate_done 31 "disabled dhcp-server"

fi
# RULE32:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 32; then
sec_audit_disable_svc named.service
sec_audit_pkg_remove bind
sec_audit_remediate_done 32 "disabled bind"

fi
}

sec_audit_remediate_client_tools() {
# RULE33-39
# RULE33:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 33; then
sec_audit_pkg_remove ftp
sec_audit_remediate_done 33 "removed ftp"

fi
# RULE34:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 34; then
sec_audit_disable_svc vsftpd.service
sec_audit_pkg_remove vsftpd
sec_audit_remediate_done 34 "disabled vsftpd"

fi
# RULE35:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 35; then
sec_audit_disable_svc vsftpd.service
sec_audit_pkg_remove vsftpd
sec_audit_remediate_done 35 "disabled vsftpd"

fi
# RULE36:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 36; then
sec_audit_remediate_skip 36 "review remediation: a web server is not installed"

fi
# RULE37:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 37; then
sec_audit_disable_svc dovecot.socket
sec_audit_disable_svc dovecot.service
sec_audit_pkg_remove dovecot
sec_audit_remediate_done 37 "disabled dovecot"

fi
# RULE38:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 38; then
sec_audit_disable_svc smb.service
sec_audit_disable_svc smbd.service
sec_audit_pkg_remove samba
sec_audit_remediate_done 38 "disabled samba"

fi
# RULE39:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 39; then
sec_audit_remediate_skip 39 "review remediation: HTTP Proxy Server is not installed"

fi
}

sec_audit_remediate_unused_services_2() {
# RULE40-45
# RULE40:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 40; then
sec_audit_disable_svc snmpd.service
sec_audit_pkg_remove net-snmp
sec_audit_remediate_done 40 "disabled net-snmp"

fi
# RULE41:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 41; then
sec_audit_pkg_remove nis
sec_audit_remediate_done 41 "removed nis"

fi
# RULE42:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 42; then
sec_audit_disable_svc telnet.socket
sec_audit_pkg_remove telnet-server
sec_audit_remediate_done 42 "disabled telnet-server"

fi
# RULE43:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 43; then
sec_audit_remediate_skip 43 "review remediation: mail transfer agent is configured for local-only mode"

fi
# RULE44:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 44; then
sec_audit_disable_svc nfs-server.service
sec_audit_disable_svc nfs.service
sec_audit_pkg_remove nfs-utils
sec_audit_remediate_done 44 "disabled nfs-utils"

fi
# RULE45:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 45; then
sec_audit_disable_svc rsyncd.socket
sec_audit_disable_svc rsyncd.service
sec_audit_pkg_remove rsync-daemon
sec_audit_remediate_done 45 "disabled rsync-daemon"

fi
}

sec_audit_remediate_chrony_2() {
# RULE46-48
# RULE46:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 46; then
sec_audit_pkg_remove nis
sec_audit_remediate_done 46 "removed nis"

fi
# RULE47:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 47; then
sec_audit_pkg_remove rsh-client
sec_audit_remediate_done 47 "removed rsh-client"

fi
# RULE48:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 48; then
sec_audit_pkg_remove talk
sec_audit_remediate_done 48 "removed talk"

fi
}

sec_audit_remediate_client_tools_2() {
# RULE49-51
# RULE49:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 49; then
sec_audit_pkg_remove telnet
sec_audit_remediate_done 49 "removed telnet"

fi
# RULE50:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 50; then
sec_audit_pkg_remove ldap-utils
sec_audit_remediate_done 50 "removed ldap-utils"

fi
# RULE51:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 51; then
sec_audit_pkg_remove tftp
sec_audit_remediate_done 51 "removed tftp"

fi
}

sec_audit_remediate_network_stack() {
# RULE52-61
# RULE52:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 52; then
sec_audit_remediate_skip 52 "review remediation: packet redirect sending is disabled"

fi
# RULE53:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 53; then
sec_audit_remediate_skip 53 "review remediation: bogus icmp responses are ignored"

fi
# RULE54:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 54; then
sec_audit_remediate_skip 54 "review remediation: broadcast icmp requests are ignored"

fi
# RULE55:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 55; then
sec_audit_remediate_skip 55 "review remediation: icmp redirects are not accepted"

fi
# RULE56:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 56; then
sec_audit_remediate_skip 56 "review remediation: secure icmp redirects are not accepted"

fi
# RULE57:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 57; then
sec_audit_remediate_skip 57 "review remediation: reverse path filtering is enabled"

fi
# RULE58:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 58; then
sec_audit_remediate_skip 58 "review remediation: source routed packets are not accepted"

fi
# RULE59:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 59; then
sec_audit_remediate_skip 59 "review remediation: suspicious packets are logged"

fi
# RULE60:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 60; then
sec_audit_remediate_skip 60 "review remediation: tcp syn cookies is enabled"

fi
# RULE61:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 61; then
sec_audit_remediate_skip 61 "ipv6 router advertisements are not accepted"

fi
}

sec_audit_remediate_firewalld() {
# RULE62-64
# RULE62:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 62; then
sec_audit_remediate_skip 62 "review remediation: iptables is installed"

fi
# RULE63:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 63; then
sec_audit_pkg_install nftables
mkdir -p /etc/nftables
cat >/etc/nftables/secaudit-azure-sec.nft <<'EOF'
table inet filter {
  chain input { type filter hook input priority 0; policy drop;
    iif "lo" accept
    ct state established,related accept
    tcp dport 22 accept
  }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output { type filter hook output priority 0; policy accept; }
}
EOF
systemctl enable --now nftables >/dev/null 2>&1 || true
nft -f /etc/nftables/secaudit-azure-sec.nft >/dev/null 2>&1 || true
sec_audit_remediate_done 63 "nftables baseline chains"

fi
# RULE64:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 64; then
sec_audit_remediate_skip 64 "review remediation: firewalld is not in use"

fi
}

sec_audit_remediate_sshd() {
# RULE65-73
# RULE65:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 65; then
sec_audit_pkg_install cronie
sec_audit_start_svc crond
sec_audit_remediate_done 65 "enabled crond"

fi
# RULE66:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 66; then
chmod 600 /etc/crontab 2>/dev/null || true
chown root:root /etc/crontab 2>/dev/null || true
sec_audit_remediate_done 66 "restricted /etc/crontab"

fi
# RULE67:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 67; then
sec_audit_remediate_skip 67 "review remediation: permissions on /etc/cron.hourly are configured"

fi
# RULE68:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 68; then
sec_audit_remediate_skip 68 "review remediation: permissions on /etc/cron.daily are configured"

fi
# RULE69:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 69; then
sec_audit_remediate_skip 69 "review remediation: permissions on /etc/cron.weekly are configured"

fi
# RULE70:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 70; then
sec_audit_remediate_skip 70 "review remediation: permissions on /etc/cron.monthly are configured"

fi
# RULE71:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 71; then
sec_audit_remediate_skip 71 "review remediation: permissions on /etc/cron.d are configured"

fi
# RULE72:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 72; then
sec_audit_remediate_skip 72 "review remediation: cron is restricted to authorized users"

fi
# RULE73:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 73; then
sec_audit_remediate_skip 73 "review remediation: at is restricted to authorized users"

fi
}

sec_audit_remediate_sudo_su() {
# RULE74-80
# RULE74:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 74; then
sec_audit_remediate_skip 74 "review remediation: access to /etc/ssh/sshd_config is configured"

fi
# RULE75:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 75; then
sec_audit_remediate_skip 75 "review remediation: access to SSH private host key files is configured"

fi
# RULE76:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 76; then
sec_audit_remediate_skip 76 "review remediation: access to SSH public host key files is configured"

fi
# RULE77:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 77; then
sec_audit_remediate_skip 77 "review remediation: sshd Ciphers are configured"

fi
# RULE78:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 78; then
sec_audit_remediate_skip 78 "review remediation: sshd KexAlgorithms is configured"

fi
# RULE79:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 79; then
sec_audit_remediate_skip 79 "review remediation: sshd MACs are configured"

fi
# RULE80:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 80; then
sec_audit_remediate_skip 80 "review remediation: sshd access is configured"

fi
}

sec_audit_remediate_banners_2() {
# RULE81-81
# RULE81:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 81; then
sec_audit_set_sshd_kv Banner /etc/issue.net
sec_audit_remediate_done 81 "sshd Banner"

fi
}

sec_audit_remediate_sshd_2() {
# RULE82-93
# RULE82:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 82; then
sec_audit_set_sshd_kv ClientAliveInterval 300
sec_audit_remediate_done 82 "sshd ClientAliveInterval"

fi
# RULE83:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 83; then
sec_audit_set_sshd_kv HostbasedAuthentication no
sec_audit_remediate_done 83 "sshd HostbasedAuthentication"

fi
# RULE84:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 84; then
sec_audit_set_sshd_kv IgnoreRhosts yes
sec_audit_remediate_done 84 "sshd IgnoreRhosts"

fi
# RULE85:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 85; then
sec_audit_set_sshd_kv LoginGraceTime 60
sec_audit_remediate_done 85 "sshd LoginGraceTime"

fi
# RULE86:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 86; then
sec_audit_set_sshd_kv LogLevel VERBOSE
sec_audit_remediate_done 86 "sshd LogLevel"

fi
# RULE87:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 87; then
sec_audit_set_sshd_kv MaxAuthTries 4
sec_audit_remediate_done 87 "sshd MaxAuthTries"

fi
# RULE88:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 88; then
sec_audit_set_sshd_kv MaxStartups 10:30:60
sec_audit_remediate_done 88 "sshd MaxStartups"

fi
# RULE89:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 89; then
sec_audit_set_sshd_kv MaxSessions 10
sec_audit_remediate_done 89 "sshd MaxSessions"

fi
# RULE90:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 90; then
sec_audit_set_sshd_kv PermitEmptyPasswords no
sec_audit_remediate_done 90 "sshd PermitEmptyPasswords"

fi
# RULE91:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 91; then
sec_audit_set_sshd_kv PermitRootLogin no
sec_audit_remediate_done 91 "sshd PermitRootLogin"

fi
# RULE92:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 92; then
sec_audit_set_sshd_kv PermitUserEnvironment no
sec_audit_remediate_done 92 "sshd PermitUserEnvironment"

fi
# RULE93:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 93; then
sec_audit_set_sshd_kv UsePAM yes
sec_audit_remediate_done 93 "sshd UsePAM"

fi
}

sec_audit_remediate_sudo_su_2() {
# RULE94-100
# RULE94:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 94; then
sec_audit_pkg_install sudo
sec_audit_remediate_done 94 "sudo installed"

fi
# RULE95:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 95; then
sec_audit_remediate_skip 95 "review remediation: re-authentication for privilege escalation is not disabled globally"

fi
# RULE96:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 96; then
sec_audit_remediate_skip 96 "review remediation: sudo authentication timeout is configured correctly"

fi
# RULE97:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 97; then
sec_audit_remediate_skip 97 "review remediation: password creation requirements are configured"

fi
# RULE98:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 98; then
sec_audit_authselect_enable with-faillock
authselect apply-changes >/dev/null 2>&1 || true
sec_audit_remediate_done 98 "pam faillock"

fi
# RULE99:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 99; then
sec_audit_set_login_defs_kv ENCRYPT_METHOD SHA512
sec_audit_remediate_done 99 "ENCRYPT_METHOD SHA512"

fi
# RULE100:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 100; then
sec_audit_remediate_skip 100 "review remediation: password reuse is limited"

fi
}

sec_audit_remediate_accounts() {
# RULE101-108
# RULE101:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 101; then
sec_audit_remediate_skip 101 "review remediation: password expiration is 365 days or less"

fi
# RULE102:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 102; then
sec_audit_remediate_skip 102 "minimum days between password changes is configured"

fi
# RULE103:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 103; then
sec_audit_remediate_skip 103 "review remediation: password expiration warning days is 7 or more"

fi
# RULE104:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 104; then
sec_audit_remediate_skip 104 "inactive password lock is 30 days or less"

fi
# RULE105:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 105; then
sec_audit_remediate_skip 105 "all users last password change date is in the past"

fi
# RULE106:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 106; then
sec_audit_remediate_skip 106 "system accounts are secured"

fi
# RULE107:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 107; then
sec_audit_remediate_skip 107 "default group for the root account is GID 0"

fi
# RULE108:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 108; then
sec_audit_set_login_defs_kv UMASK 027
cat >/etc/profile.d/99-secaudit-umask.sh <<'EOF'
umask 027
EOF
sec_audit_remediate_done 108 "default umask 027"

fi
}

sec_audit_remediate_logging() {
# RULE109-114
# RULE109:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 109; then
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
sec_audit_remediate_done 109 "rsyslog installed"

fi
# RULE110:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 110; then
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
sec_audit_remediate_done 110 "rsyslog installed"

fi
# RULE111:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 111; then
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
sec_audit_remediate_done 111 "rsyslog installed"

fi
# RULE112:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 112; then
sec_audit_remediate_skip 112 "rsyslog is not configured to receive logs from a remote client"

fi
# RULE113:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 113; then
sec_audit_remediate_skip 113 "review remediation: access to all logfiles has been configured"

fi
# RULE114:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 114; then
sec_audit_remediate_skip 114 "logrotate is configured"

fi
}

sec_audit_remediate_identity_files() {
# RULE115-124
# RULE115:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 115; then
sec_audit_remediate_skip 115 "review remediation: access to /etc/passwd is configured"

fi
# RULE116:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 116; then
sec_audit_remediate_skip 116 "review remediation: access to /etc/passwd- is configured"

fi
# RULE117:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 117; then
sec_audit_remediate_skip 117 "access to /etc/group is configured"

fi
# RULE118:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 118; then
sec_audit_remediate_skip 118 "access to /etc/group- is configured"

fi
# RULE119:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 119; then
sec_audit_remediate_skip 119 "review remediation: access to /etc/shadow is configured"

fi
# RULE120:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 120; then
sec_audit_remediate_skip 120 "review remediation: access to /etc/shadow- is configured"

fi
# RULE121:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 121; then
sec_audit_remediate_skip 121 "review remediation: access to /etc/gshadow is configured"

fi
# RULE122:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 122; then
sec_audit_remediate_skip 122 "review remediation: access to /etc/gshadow- is configured"

fi
# RULE123:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 123; then
sec_audit_remediate_skip 123 "review remediation: access to /etc/shells is configured"

fi
# RULE124:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 124; then
sec_audit_remediate_skip 124 "review remediation: access to /etc/security/opasswd is configured"

fi
}

sec_audit_remediate_filesystem_integrity() {
# RULE125-126
# RULE125:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 125; then
sec_audit_remediate_skip 125 "review remediation: world writable files and directories are secured"

fi
# RULE126:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 126; then
sec_audit_remediate_skip 126 "no files or directories without an owner and a group exist"

fi
}

sec_audit_remediate_identity_files_2() {
# RULE127-129
# RULE127:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 127; then
sec_audit_remediate_skip 127 "accounts in /etc/passwd use shadowed passwords"

fi
# RULE128:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 128; then
sec_audit_remediate_skip 128 "review remediation: /etc/shadow password fields are not empty"

fi
# RULE129:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 129; then
sec_audit_remediate_skip 129 "all groups in /etc/passwd exist in /etc/group"

fi
}

sec_audit_remediate_filesystem_integrity_2() {
# RULE130-135
# RULE130:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 130; then
sec_audit_remediate_skip 130 "no duplicate UIDs exist"

fi
# RULE131:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 131; then
sec_audit_remediate_skip 131 "no duplicate GIDs exist"

fi
# RULE132:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 132; then
sec_audit_remediate_skip 132 "no duplicate user names exist"

fi
# RULE133:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 133; then
sec_audit_remediate_skip 133 "no duplicate group names exist"

fi
# RULE134:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 134; then
sec_audit_remediate_skip 134 "local interactive user home directories are configured"

fi
# RULE135:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 135; then
sec_audit_remediate_skip 135 "local interactive user dot files access is configured"

fi

if sec_audit_have_bin dnf; then
    timeout 300 dnf upgrade --security -y >/dev/null 2>&1 || true
elif sec_audit_have_bin yum; then
    timeout 300 yum update --security -y >/dev/null 2>&1 || true
fi

sec_audit_log " remediation complete (Azure_linux_remediation.sh)"
}

sec_audit_main() {
    sec_audit_remediate_kernel_modules
    sec_audit_remediate_filesystem_partitions
    sec_audit_remediate_package_security
    sec_audit_remediate_process_hardening
    sec_audit_remediate_bootloader
    sec_audit_remediate_banners
    sec_audit_remediate_chrony
    sec_audit_remediate_unused_services
    sec_audit_remediate_client_tools
    sec_audit_remediate_unused_services_2
    sec_audit_remediate_chrony_2
    sec_audit_remediate_client_tools_2
    sec_audit_remediate_network_stack
    sec_audit_remediate_firewalld
    sec_audit_remediate_sshd
    sec_audit_remediate_sudo_su
    sec_audit_remediate_banners_2
    sec_audit_remediate_sshd_2
    sec_audit_remediate_sudo_su_2
    sec_audit_remediate_accounts
    sec_audit_remediate_logging
    sec_audit_remediate_identity_files
    sec_audit_remediate_filesystem_integrity
    sec_audit_remediate_identity_files_2
    sec_audit_remediate_filesystem_integrity_2
    exit 0
}

# secaudit-restore-journal: paired with Azure_linux_remediation.sh
SECAUDIT_JOURNAL="${SECAUDIT_JOURNAL:-/var/backups/secaudit-azure_linux.journal}"
SECAUDIT_PKG="${SECAUDIT_PKG:-dnf}"

sec_audit_journal_once() {
	local kind="$1" id="$2"
	shift 2
	mkdir -p "$(dirname "$SECAUDIT_JOURNAL")" 2>/dev/null || return 0
	touch "$SECAUDIT_JOURNAL" 2>/dev/null || return 0
	grep -q "^${kind} ${id} " "$SECAUDIT_JOURNAL" 2>/dev/null && return 0
	grep -qxF "${kind} ${id}" "$SECAUDIT_JOURNAL" 2>/dev/null && return 0
	if [ $# -eq 0 ]; then
		printf '%s %s\n' "$kind" "$id" >>"$SECAUDIT_JOURNAL"
	else
		printf '%s %s %s\n' "$kind" "$id" "$*" >>"$SECAUDIT_JOURNAL"
	fi
}

sec_audit_guard_file() {
	local f="$1"
	[ -n "$f" ] || return 0
	case "$f" in *.secaudit.bak) return 0 ;; esac
	if [ -e "$f" ]; then
		[ -e "${f}.secaudit.bak" ] && return 0
		cp -p "$f" "${f}.secaudit.bak" 2>/dev/null || true
	else
		sec_audit_journal_once created "$f"
	fi
}

sec_audit_pkg_table() {
	case "$SECAUDIT_PKG" in
		apt) dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null | sort -u ;;
		zypper|dnf|yum) rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' 2>/dev/null | sort -u ;;
	esac
}

sec_audit_journal_pkg_diff() {
	local kind="$1" before="$2" after="$3" name ver
	comm -13 "$before" "$after" | while read -r name ver; do
		[ -n "${name:-}" ] || continue
		sec_audit_journal_once "$kind" "$name" "$ver"
	done
}

sec_audit_remember_unit() {
	local u="$1" state
	command -v systemctl >/dev/null 2>&1 || return 0
	[ -n "$u" ] || return 0
	state=$(systemctl is-enabled "$u" 2>/dev/null || true)
	case "$state" in
		enabled|enabled-runtime) state=enabled ;;
		disabled|masked|static|indirect|absent) ;;
		*) state=absent ;;
	esac
	sec_audit_journal_once unit "$u" "$state"
}

sec_audit_remember_mount() {
	local mp="$1" opts
	[ -n "$mp" ] || return 0
	mountpoint -q "$mp" 2>/dev/null || return 0
	opts=$(findmnt -kn -T "$mp" -o OPTIONS -n 2>/dev/null | head -n1)
	[ -n "$opts" ] && sec_audit_journal_once mount "$mp" "$opts"
}

sec_audit_rename_fn() {
	local src="$1" dst="${1}_raw" body
	declare -f "$src" >/dev/null 2>&1 || return 1
	declare -f "$dst" >/dev/null 2>&1 && return 0
	body=$(declare -f "$src") || return 1
	eval "${body/#"$src"/"$dst"}"
}

sed() {
	local arg
	for arg in "$@"; do
		case "$arg" in
			/etc/*|/boot/*|/usr/*|/var/*) sec_audit_guard_file "$arg" ;;
		esac
	done
	command sed "$@"
}

chmod() {
	local path="${!#}" mode owner
	if [ -n "${path:-}" ] && [ -e "$path" ]; then
		mode=$(stat -c '%a' "$path" 2>/dev/null || true)
		owner=$(stat -c '%U:%G' "$path" 2>/dev/null || true)
		[ -n "$mode" ] && sec_audit_journal_once mode "$path" "$mode ${owner:-root:root}"
	fi
	command chmod "$@"
}

chown() {
	local path="${!#}" mode owner
	if [ -n "${path:-}" ] && [ -e "$path" ]; then
		mode=$(stat -c '%a' "$path" 2>/dev/null || true)
		owner=$(stat -c '%U:%G' "$path" 2>/dev/null || true)
		[ -n "$mode" ] && sec_audit_journal_once mode "$path" "$mode ${owner:-root:root}"
	fi
	command chown "$@"
}


if sec_audit_rename_fn sec_audit_pkg_install; then
sec_audit_pkg_install() {
	local before after
	before=$(mktemp)
	after=$(mktemp)
	sec_audit_pkg_table >"$before"
	sec_audit_pkg_install_raw "$@"
	sec_audit_pkg_table >"$after"
	sec_audit_journal_pkg_diff pkg_add "$before" "$after"
	rm -f "$before" "$after"
}
fi


if sec_audit_rename_fn sec_audit_pkg_remove; then
sec_audit_pkg_remove() {
	local before after
	before=$(mktemp)
	after=$(mktemp)
	sec_audit_pkg_table >"$before"
	sec_audit_pkg_remove_raw "$@"
	sec_audit_pkg_table >"$after"
	sec_audit_journal_pkg_diff pkg_del "$before" "$after"
	rm -f "$before" "$after"
}
fi


if sec_audit_rename_fn sec_audit_start_svc; then
sec_audit_start_svc() {
	local u
	for u in "$@"; do
		sec_audit_remember_unit "$u"
	done
	sec_audit_start_svc_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_disable_svc; then
sec_audit_disable_svc() {
	local u
	for u in "$@"; do
		sec_audit_remember_unit "$u"
	done
	sec_audit_disable_svc_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_disable_kernel_module; then
sec_audit_disable_kernel_module() {
	local mod="$1" before after name
	if awk '{print $1}' /proc/modules 2>/dev/null | grep -qx "$mod"; then
		sec_audit_journal_once kmod "$mod"
	fi
	before=$(mktemp)
	after=$(mktemp)
	find /etc/modprobe.d -type f -printf '%f\n' 2>/dev/null | sort >"$before"
	sec_audit_disable_kernel_module_raw "$@"
	find /etc/modprobe.d -type f -printf '%f\n' 2>/dev/null | sort >"$after"
	comm -13 "$before" "$after" | while read -r name; do
		[ -n "${name:-}" ] || continue
		sec_audit_journal_once created "/etc/modprobe.d/$name"
	done
	rm -f "$before" "$after"
}
fi


if sec_audit_rename_fn sec_audit_ensure_fstab_mount; then
sec_audit_ensure_fstab_mount() {
		sec_audit_guard_file /etc/fstab
	sec_audit_remember_mount "$1"
	sec_audit_ensure_fstab_mount_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_ensure_mount_option; then
sec_audit_ensure_mount_option() {
		sec_audit_guard_file /etc/fstab
	sec_audit_remember_mount "$1"
	sec_audit_ensure_mount_option_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_set_sysctl; then
sec_audit_set_sysctl() {
	local key="$1" old
		sec_audit_guard_file /etc/sysctl.d/99-secaudit-azure-sec.conf
	sec_audit_guard_file /etc/sysctl.d
	old=$(sysctl -n "$key" 2>/dev/null || true)
	[ -n "$old" ] && sec_audit_journal_once sysctl "$key" "$old"
	sec_audit_set_sysctl_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_set_dnf_main_kv; then
sec_audit_set_dnf_main_kv() {
		sec_audit_guard_file /etc/dnf/dnf.conf
	sec_audit_set_dnf_main_kv_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_set_sshd_kv; then
sec_audit_set_sshd_kv() {
		sec_audit_guard_file /etc/ssh/sshd_config
	sec_audit_set_sshd_kv_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_set_login_defs_kv; then
sec_audit_set_login_defs_kv() {
		sec_audit_guard_file /etc/login.defs
	sec_audit_set_login_defs_kv_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_set_pwquality_kv; then
sec_audit_set_pwquality_kv() {
		sec_audit_guard_file /etc/security/pwquality.conf
	sec_audit_guard_file /etc/security/pwquality.conf.d
	sec_audit_set_pwquality_kv_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_set_faillock_kv; then
sec_audit_set_faillock_kv() {
		sec_audit_guard_file /etc/security/faillock.conf
	sec_audit_guard_file /etc/security
	sec_audit_set_faillock_kv_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_authselect_enable; then
sec_audit_authselect_enable() {
		sec_audit_guard_file /etc/authselect/authselect.conf
	sec_audit_guard_file /etc/pam.d/system-auth
	sec_audit_guard_file /etc/pam.d/password-auth
	sec_audit_guard_file /etc/pam.d/common-auth
	sec_audit_guard_file /etc/pam.d/common-password
	sec_audit_authselect_enable_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_remediate_chrony; then
sec_audit_remediate_chrony() {
		sec_audit_guard_file /etc/chrony.conf
	sec_audit_remediate_chrony_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_remediate_firewalld; then
sec_audit_remediate_firewalld() {
		sec_audit_guard_file /etc/nftables
	sec_audit_guard_file /etc/nftables/secaudit-azure-sec.nft
	sec_audit_remediate_firewalld_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_remediate_sshd; then
sec_audit_remediate_sshd() {
		sec_audit_guard_file /etc/crontab
	sec_audit_guard_file /etc/cron.hourly
	sec_audit_guard_file /etc/cron.daily
	sec_audit_guard_file /etc/cron.weekly
	sec_audit_guard_file /etc/cron.monthly
	sec_audit_guard_file /etc/cron.d
	sec_audit_remediate_sshd_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_remediate_accounts; then
sec_audit_remediate_accounts() {
		sec_audit_guard_file /etc/profile.d/99-secaudit-umask.sh
	sec_audit_remediate_accounts_raw "$@"
}
fi

sec_audit_main "$@"

