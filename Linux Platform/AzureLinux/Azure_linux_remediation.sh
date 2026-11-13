#!/bin/bash

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

# RULE1:
sec_audit_disable_kernel_module cramfs
sec_audit_remediate_done 1 "blacklisted kernel module cramfs"

# RULE2:
sec_audit_disable_kernel_module freevxfs
sec_audit_remediate_done 2 "blacklisted kernel module freevxfs"

# RULE3:
sec_audit_disable_kernel_module hfs
sec_audit_remediate_done 3 "blacklisted kernel module hfs"

# RULE4:
sec_audit_disable_kernel_module hfsplus
sec_audit_remediate_done 4 "blacklisted kernel module hfsplus"

# RULE5:
sec_audit_disable_kernel_module jffs2
sec_audit_remediate_done 5 "blacklisted kernel module jffs2"

# RULE6:
sec_audit_remediate_skip 6 "unused filesystems kernel modules are not available"

# RULE7:
sec_audit_remediate_skip 7 "/tmp is a separate partition"

# RULE8:
sec_audit_ensure_mount_option /tmp nodev
sec_audit_remediate_done 8 "set nodev on /tmp"

# RULE9:
sec_audit_remediate_skip 9 "nosuid option set on /tmp partition"

# RULE10:
sec_audit_remediate_skip 10 "/dev/shm is a separate partition"

# RULE11:
sec_audit_ensure_mount_option /dev/shm nodev
sec_audit_remediate_done 11 "set nodev on /dev/shm"

# RULE12:
sec_audit_remediate_skip 12 "nosuid option set on /dev/shm partition"

# RULE13:
sec_audit_remediate_skip 13 "GPG keys are configured"

# RULE14:
sec_audit_set_dnf_main_kv gpgcheck 1
sec_audit_set_dnf_main_kv localpkg_gpgcheck 1
sec_audit_remediate_done 14 "enabled gpgcheck"

# RULE15:
sec_audit_remediate_skip 15 "review remediation: TDNF gpgcheck is globally activated"

# RULE16:
sec_audit_remediate_skip 16 "package manager repositories are configured"

# RULE17:
sec_audit_remediate_skip 17 "review remediation: address space layout randomization is enabled"

# RULE18:
sec_audit_remediate_skip 18 "review remediation: core dump backtraces are disabled"

# RULE19:
sec_audit_remediate_skip 19 "review remediation: core dump storage is disabled"

# RULE20:
sec_audit_set_sshd_kv Banner /etc/issue.net
sec_audit_remediate_done 20 "sshd Banner"

# RULE21:
sec_audit_remediate_skip 21 "remote login warning banner is configured properly"

# RULE22:
sec_audit_harden_file /etc/motd 644 root:root
sec_audit_remediate_done 22 "permissions /etc/motd"

# RULE23:
sec_audit_harden_file /etc/issue 644 root:root
sec_audit_remediate_done 23 "permissions /etc/issue"

# RULE24:
sec_audit_harden_file /etc/issue.net 644 root:root
sec_audit_remediate_done 24 "permissions /etc/issue.net"

# RULE25:
sec_audit_pkg_install chrony
sec_audit_start_svc chronyd
sec_audit_remediate_done 25 "installed chrony"

# RULE26:
sec_audit_pkg_install chrony
grep -q "^pool \|^server " /etc/chrony.conf 2>/dev/null || echo "pool 2.pool.ntp.org iburst" >>/etc/chrony.conf
sec_audit_start_svc chronyd
sec_audit_remediate_done 26 "configured chrony"

# RULE27:
sec_audit_remediate_skip 27 "review remediation: xinetd is not installed"

# RULE28:
sec_audit_disable_svc gdm
sec_audit_disable_svc gdm3
sec_audit_pkg_remove xorg-x11-server-Xorg
sec_audit_remediate_done 28 "disabled xorg-x11-server-Xorg"

# RULE29:
sec_audit_disable_svc avahi-daemon.socket
sec_audit_disable_svc avahi-daemon.service
sec_audit_pkg_remove avahi
sec_audit_remediate_done 29 "disabled avahi"

# RULE30:
sec_audit_remediate_skip 30 "review remediation: a print server is not installed"

# RULE31:
sec_audit_disable_svc dhcpd.service
sec_audit_disable_svc dhcpd6.service
sec_audit_pkg_remove dhcp-server
sec_audit_remediate_done 31 "disabled dhcp-server"

# RULE32:
sec_audit_disable_svc named.service
sec_audit_pkg_remove bind
sec_audit_remediate_done 32 "disabled bind"

# RULE33:
sec_audit_pkg_remove ftp
sec_audit_remediate_done 33 "removed ftp"

# RULE34:
sec_audit_disable_svc vsftpd.service
sec_audit_pkg_remove vsftpd
sec_audit_remediate_done 34 "disabled vsftpd"

# RULE35:
sec_audit_disable_svc vsftpd.service
sec_audit_pkg_remove vsftpd
sec_audit_remediate_done 35 "disabled vsftpd"

# RULE36:
sec_audit_remediate_skip 36 "review remediation: a web server is not installed"

# RULE37:
sec_audit_disable_svc dovecot.socket
sec_audit_disable_svc dovecot.service
sec_audit_pkg_remove dovecot
sec_audit_remediate_done 37 "disabled dovecot"

# RULE38:
sec_audit_disable_svc smb.service
sec_audit_disable_svc smbd.service
sec_audit_pkg_remove samba
sec_audit_remediate_done 38 "disabled samba"

# RULE39:
sec_audit_remediate_skip 39 "review remediation: HTTP Proxy Server is not installed"

# RULE40:
sec_audit_disable_svc snmpd.service
sec_audit_pkg_remove net-snmp
sec_audit_remediate_done 40 "disabled net-snmp"

# RULE41:
sec_audit_pkg_remove nis
sec_audit_remediate_done 41 "removed nis"

# RULE42:
sec_audit_disable_svc telnet.socket
sec_audit_pkg_remove telnet-server
sec_audit_remediate_done 42 "disabled telnet-server"

# RULE43:
sec_audit_remediate_skip 43 "review remediation: mail transfer agent is configured for local-only mode"

# RULE44:
sec_audit_disable_svc nfs-server.service
sec_audit_disable_svc nfs.service
sec_audit_pkg_remove nfs-utils
sec_audit_remediate_done 44 "disabled nfs-utils"

# RULE45:
sec_audit_disable_svc rsyncd.socket
sec_audit_disable_svc rsyncd.service
sec_audit_pkg_remove rsync-daemon
sec_audit_remediate_done 45 "disabled rsync-daemon"

# RULE46:
sec_audit_pkg_remove nis
sec_audit_remediate_done 46 "removed nis"

# RULE47:
sec_audit_pkg_remove rsh-client
sec_audit_remediate_done 47 "removed rsh-client"

# RULE48:
sec_audit_pkg_remove talk
sec_audit_remediate_done 48 "removed talk"

# RULE49:
sec_audit_pkg_remove telnet
sec_audit_remediate_done 49 "removed telnet"

# RULE50:
sec_audit_pkg_remove ldap-utils
sec_audit_remediate_done 50 "removed ldap-utils"

# RULE51:
sec_audit_pkg_remove tftp
sec_audit_remediate_done 51 "removed tftp"

# RULE52:
sec_audit_remediate_skip 52 "review remediation: packet redirect sending is disabled"

# RULE53:
sec_audit_remediate_skip 53 "review remediation: bogus icmp responses are ignored"

# RULE54:
sec_audit_remediate_skip 54 "review remediation: broadcast icmp requests are ignored"

# RULE55:
sec_audit_remediate_skip 55 "review remediation: icmp redirects are not accepted"

# RULE56:
sec_audit_remediate_skip 56 "review remediation: secure icmp redirects are not accepted"

# RULE57:
sec_audit_remediate_skip 57 "review remediation: reverse path filtering is enabled"

# RULE58:
sec_audit_remediate_skip 58 "review remediation: source routed packets are not accepted"

# RULE59:
sec_audit_remediate_skip 59 "review remediation: suspicious packets are logged"

# RULE60:
sec_audit_remediate_skip 60 "review remediation: tcp syn cookies is enabled"

# RULE61:
sec_audit_remediate_skip 61 "ipv6 router advertisements are not accepted"

# RULE62:
sec_audit_remediate_skip 62 "review remediation: iptables is installed"

# RULE63:
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

# RULE64:
sec_audit_remediate_skip 64 "review remediation: firewalld is not in use"

# RULE65:
sec_audit_pkg_install cronie
sec_audit_start_svc crond
sec_audit_remediate_done 65 "enabled crond"

# RULE66:
chmod 600 /etc/crontab 2>/dev/null || true
chown root:root /etc/crontab 2>/dev/null || true
sec_audit_remediate_done 66 "restricted /etc/crontab"

# RULE67:
sec_audit_remediate_skip 67 "review remediation: permissions on /etc/cron.hourly are configured"

# RULE68:
sec_audit_remediate_skip 68 "review remediation: permissions on /etc/cron.daily are configured"

# RULE69:
sec_audit_remediate_skip 69 "review remediation: permissions on /etc/cron.weekly are configured"

# RULE70:
sec_audit_remediate_skip 70 "review remediation: permissions on /etc/cron.monthly are configured"

# RULE71:
sec_audit_remediate_skip 71 "review remediation: permissions on /etc/cron.d are configured"

# RULE72:
sec_audit_remediate_skip 72 "review remediation: cron is restricted to authorized users"

# RULE73:
sec_audit_remediate_skip 73 "review remediation: at is restricted to authorized users"

# RULE74:
sec_audit_remediate_skip 74 "review remediation: access to /etc/ssh/sshd_config is configured"

# RULE75:
sec_audit_remediate_skip 75 "review remediation: access to SSH private host key files is configured"

# RULE76:
sec_audit_remediate_skip 76 "review remediation: access to SSH public host key files is configured"

# RULE77:
sec_audit_remediate_skip 77 "review remediation: sshd Ciphers are configured"

# RULE78:
sec_audit_remediate_skip 78 "review remediation: sshd KexAlgorithms is configured"

# RULE79:
sec_audit_remediate_skip 79 "review remediation: sshd MACs are configured"

# RULE80:
sec_audit_remediate_skip 80 "review remediation: sshd access is configured"

# RULE81:
sec_audit_set_sshd_kv Banner /etc/issue.net
sec_audit_remediate_done 81 "sshd Banner"

# RULE82:
sec_audit_set_sshd_kv ClientAliveInterval 300
sec_audit_remediate_done 82 "sshd ClientAliveInterval"

# RULE83:
sec_audit_set_sshd_kv HostbasedAuthentication no
sec_audit_remediate_done 83 "sshd HostbasedAuthentication"

# RULE84:
sec_audit_set_sshd_kv IgnoreRhosts yes
sec_audit_remediate_done 84 "sshd IgnoreRhosts"

# RULE85:
sec_audit_set_sshd_kv LoginGraceTime 60
sec_audit_remediate_done 85 "sshd LoginGraceTime"

# RULE86:
sec_audit_set_sshd_kv LogLevel VERBOSE
sec_audit_remediate_done 86 "sshd LogLevel"

# RULE87:
sec_audit_set_sshd_kv MaxAuthTries 4
sec_audit_remediate_done 87 "sshd MaxAuthTries"

# RULE88:
sec_audit_set_sshd_kv MaxStartups 10:30:60
sec_audit_remediate_done 88 "sshd MaxStartups"

# RULE89:
sec_audit_set_sshd_kv MaxSessions 10
sec_audit_remediate_done 89 "sshd MaxSessions"

# RULE90:
sec_audit_set_sshd_kv PermitEmptyPasswords no
sec_audit_remediate_done 90 "sshd PermitEmptyPasswords"

# RULE91:
sec_audit_set_sshd_kv PermitRootLogin no
sec_audit_remediate_done 91 "sshd PermitRootLogin"

# RULE92:
sec_audit_set_sshd_kv PermitUserEnvironment no
sec_audit_remediate_done 92 "sshd PermitUserEnvironment"

# RULE93:
sec_audit_set_sshd_kv UsePAM yes
sec_audit_remediate_done 93 "sshd UsePAM"

# RULE94:
sec_audit_pkg_install sudo
sec_audit_remediate_done 94 "sudo installed"

# RULE95:
sec_audit_remediate_skip 95 "review remediation: re-authentication for privilege escalation is not disabled globally"

# RULE96:
sec_audit_remediate_skip 96 "review remediation: sudo authentication timeout is configured correctly"

# RULE97:
sec_audit_remediate_skip 97 "review remediation: password creation requirements are configured"

# RULE98:
sec_audit_authselect_enable with-faillock
authselect apply-changes >/dev/null 2>&1 || true
sec_audit_remediate_done 98 "pam faillock"

# RULE99:
sec_audit_set_login_defs_kv ENCRYPT_METHOD SHA512
sec_audit_remediate_done 99 "ENCRYPT_METHOD SHA512"

# RULE100:
sec_audit_remediate_skip 100 "review remediation: password reuse is limited"

# RULE101:
sec_audit_remediate_skip 101 "review remediation: password expiration is 365 days or less"

# RULE102:
sec_audit_remediate_skip 102 "minimum days between password changes is configured"

# RULE103:
sec_audit_remediate_skip 103 "review remediation: password expiration warning days is 7 or more"

# RULE104:
sec_audit_remediate_skip 104 "inactive password lock is 30 days or less"

# RULE105:
sec_audit_remediate_skip 105 "all users last password change date is in the past"

# RULE106:
sec_audit_remediate_skip 106 "system accounts are secured"

# RULE107:
sec_audit_remediate_skip 107 "default group for the root account is GID 0"

# RULE108:
sec_audit_set_login_defs_kv UMASK 027
cat >/etc/profile.d/99-secaudit-umask.sh <<'EOF'
umask 027
EOF
sec_audit_remediate_done 108 "default umask 027"

# RULE109:
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
sec_audit_remediate_done 109 "rsyslog installed"

# RULE110:
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
sec_audit_remediate_done 110 "rsyslog installed"

# RULE111:
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
sec_audit_remediate_done 111 "rsyslog installed"

# RULE112:
sec_audit_remediate_skip 112 "rsyslog is not configured to receive logs from a remote client"

# RULE113:
sec_audit_remediate_skip 113 "review remediation: access to all logfiles has been configured"

# RULE114:
sec_audit_remediate_skip 114 "logrotate is configured"

# RULE115:
sec_audit_remediate_skip 115 "review remediation: access to /etc/passwd is configured"

# RULE116:
sec_audit_remediate_skip 116 "review remediation: access to /etc/passwd- is configured"

# RULE117:
sec_audit_remediate_skip 117 "access to /etc/group is configured"

# RULE118:
sec_audit_remediate_skip 118 "access to /etc/group- is configured"

# RULE119:
sec_audit_remediate_skip 119 "review remediation: access to /etc/shadow is configured"

# RULE120:
sec_audit_remediate_skip 120 "review remediation: access to /etc/shadow- is configured"

# RULE121:
sec_audit_remediate_skip 121 "review remediation: access to /etc/gshadow is configured"

# RULE122:
sec_audit_remediate_skip 122 "review remediation: access to /etc/gshadow- is configured"

# RULE123:
sec_audit_remediate_skip 123 "review remediation: access to /etc/shells is configured"

# RULE124:
sec_audit_remediate_skip 124 "review remediation: access to /etc/security/opasswd is configured"

# RULE125:
sec_audit_remediate_skip 125 "review remediation: world writable files and directories are secured"

# RULE126:
sec_audit_remediate_skip 126 "no files or directories without an owner and a group exist"

# RULE127:
sec_audit_remediate_skip 127 "accounts in /etc/passwd use shadowed passwords"

# RULE128:
sec_audit_remediate_skip 128 "review remediation: /etc/shadow password fields are not empty"

# RULE129:
sec_audit_remediate_skip 129 "all groups in /etc/passwd exist in /etc/group"

# RULE130:
sec_audit_remediate_skip 130 "no duplicate UIDs exist"

# RULE131:
sec_audit_remediate_skip 131 "no duplicate GIDs exist"

# RULE132:
sec_audit_remediate_skip 132 "no duplicate user names exist"

# RULE133:
sec_audit_remediate_skip 133 "no duplicate group names exist"

# RULE134:
sec_audit_remediate_skip 134 "local interactive user home directories are configured"

# RULE135:
sec_audit_remediate_skip 135 "local interactive user dot files access is configured"

if sec_audit_have_bin dnf; then
    timeout 300 dnf upgrade --security -y >/dev/null 2>&1 || true
elif sec_audit_have_bin yum; then
    timeout 300 yum update --security -y >/dev/null 2>&1 || true
fi

sec_audit_log " remediation complete (Azure_linux_remediation.sh)"
exit 0

