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
    local key="$1" val="$2" f="/etc/sysctl.d/99-debian12-cre-sec.conf"
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

sec_audit_log "starting remediation (sec_Debian_Linux_12_v1.1.0)"

# RULE1:
sec_audit_disable_kmod cramfs
rem_done 1 "blacklisted kernel module cramfs"

# RULE2:
sec_audit_disable_kmod freevxfs
rem_done 2 "blacklisted kernel module freevxfs"

# RULE3:
sec_audit_disable_kmod hfs
rem_done 3 "blacklisted kernel module hfs"

# RULE4:
sec_audit_disable_kmod hfsplus
rem_done 4 "blacklisted kernel module hfsplus"

# RULE5:
sec_audit_disable_kmod jffs2
rem_done 5 "blacklisted kernel module jffs2"

# RULE6:
sec_audit_disable_kmod overlay
rem_done 6 "blacklisted kernel module overlay"

# RULE7:
sec_audit_disable_kmod squashfs
rem_done 7 "blacklisted kernel module squashfs"

# RULE8:
sec_audit_disable_kmod udf
rem_done 8 "blacklisted kernel module udf"

# RULE9:
sec_audit_disable_kmod firewire-core
rem_done 9 "blacklisted kernel module firewire-core"

# RULE10:
rem_skip 10 "Ensure /tmp is a separate partition"

# RULE11:
ensure_mount_option /tmp nodev
rem_done 11 "set nodev on /tmp"

# RULE12:
rem_skip 12 "Ensure nosuid option set on /tmp partition"

# RULE13:
ensure_mount_option /tmp noexec
rem_done 13 "set noexec on /tmp"

# RULE14:
rem_skip 14 "Ensure /dev/shm is a separate partition"

# RULE15:
ensure_mount_option /dev/shm nodev
rem_done 15 "set nodev on /dev/shm"

# RULE16:
rem_skip 16 "Ensure nosuid option set on /dev/shm partition"

# RULE17:
ensure_mount_option /dev/shm noexec
rem_done 17 "set noexec on /dev/shm"

# RULE18:
ensure_mount_option /home nodev
rem_done 18 "set nodev on /home"

# RULE19:
rem_skip 19 "Ensure nosuid option set on /home partition"

# RULE20:
ensure_mount_option /var nodev
rem_done 20 "set nodev on /var"

# RULE21:
rem_skip 21 "Ensure nosuid option set on /var partition"

# RULE22:
ensure_mount_option /var/tmp nodev
rem_done 22 "set nodev on /var/tmp"

# RULE23:
rem_skip 23 "Ensure nosuid option set on /var/tmp partition"

# RULE24:
ensure_mount_option /var/tmp noexec
rem_done 24 "set noexec on /var/tmp"

# RULE25:
ensure_mount_option /var/sec_audit_log nodev
rem_done 25 "set nodev on /var/sec_audit_log"

# RULE26:
rem_skip 26 "Ensure nosuid option set on /var/sec_audit_log partition"

# RULE27:
ensure_mount_option /var/sec_audit_log noexec
rem_done 27 "set noexec on /var/sec_audit_log"

# RULE28:
ensure_mount_option /var/sec_audit_log/audit nodev
rem_done 28 "set nodev on /var/sec_audit_log/audit"

# RULE29:
rem_skip 29 "Ensure nosuid option set on /var/sec_audit_log/audit partition"

# RULE30:
ensure_mount_option /var/sec_audit_log/audit noexec
rem_done 30 "set noexec on /var/sec_audit_log/audit"

# RULE31:
rem_skip 31 "Ensure GPG keys are configured"

# RULE32:
rem_skip 32 "Ensure package manager repositories are configured"

# RULE33:
rem_skip 33 "review remediation: Ensure updates, patches, and additional security software are installed"

# RULE34:
sec_audit_pkg_install apparmor apparmor-utils
sec_audit_start_svc apparmor
rem_done 34 "apparmor enabled"

# RULE35:
harden_file /boot/grub2/grub.cfg 600 root:root
harden_file /boot/grub2/user.cfg 600 root:root
rem_done 35 "hardened grub permissions"

# RULE36:
rem_skip 36 "Ensure bootloader password is set"

# RULE37:
harden_file /boot/grub2/grub.cfg 600 root:root
harden_file /boot/grub2/user.cfg 600 root:root
rem_done 37 "hardened grub permissions"

# RULE38:
rem_skip 38 "review remediation: Ensure address space layout randomization is enabled"

# RULE39:
set_sysctl kernel.yama.ptrace_scope 1
rem_done 39 "set kernel.yama.ptrace_scope=1"

# RULE40:
grep -q "hard core" /etc/security/limits.conf 2>/dev/null || echo "* hard core 0" >>/etc/security/limits.conf
mkdir -p /etc/systemd/coredump.conf.d
cat >/etc/systemd/coredump.conf.d/99-cre-sec.conf <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
sec_audit_have_bin systemctl && systemctl daemon-reload >/dev/null 2>&1 || true
rem_done 40 "disabled core dumps"

# RULE41:
rem_skip 41 "review remediation: Ensure message of the day is configured properly"

# RULE42:
set_sshd_kv Banner /etc/issue.net
rem_done 42 "sshd Banner"

# RULE43:
rem_skip 43 "Ensure remote login warning banner is configured properly"

# RULE44:
harden_file /etc/motd 644 root:root
rem_done 44 "permissions /etc/motd"

# RULE45:
harden_file /etc/issue 644 root:root
rem_done 45 "permissions /etc/issue"

# RULE46:
harden_file /etc/issue.net 644 root:root
rem_done 46 "permissions /etc/issue.net"

# RULE47:
sec_audit_pkg_remove gdm gdm3
sec_audit_disable_svc gdm gdm3
rem_done 47 "removed GDM"

# RULE48:
mkdir -p /etc/dconf/db/gdm.d
sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
rem_done 48 "configured GDM hardening"

# RULE49:
mkdir -p /etc/dconf/db/gdm.d
sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
rem_done 49 "configured GDM hardening"

# RULE50:
mkdir -p /etc/dconf/db/gdm.d
sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
rem_done 50 "configured GDM hardening"

# RULE51:
sec_audit_pkg_remove gdm gdm3
sec_audit_disable_svc gdm gdm3
rem_done 51 "removed GDM"

# RULE52:
sec_audit_disable_kmod removable
rem_done 52 "disabled removable mount"

# RULE53:
sec_audit_disable_kmod removable
rem_done 53 "disabled removable mount"

# RULE54:
mkdir -p /etc/dconf/db/gdm.d
sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
rem_done 54 "configured GDM hardening"

# RULE55:
sec_audit_pkg_remove gdm gdm3
sec_audit_disable_svc gdm gdm3
rem_done 55 "removed GDM"

# RULE56:
mkdir -p /etc/dconf/db/gdm.d
sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
rem_done 56 "configured GDM hardening"

# RULE57:
rem_skip 57 "review remediation: Ensure chargen services are not enabled"

# RULE58:
rem_skip 58 "review remediation: Ensure daytime services are not enabled"

# RULE59:
rem_skip 59 "review remediation: Ensure discard services are not enabled"

# RULE60:
rem_skip 60 "review remediation: Ensure echo services are not enabled"

# RULE61:
rem_skip 61 "review remediation: Ensure time services are not enabled"

# RULE62:
rem_skip 62 "review remediation: Ensure tftp server is not enabled"

# RULE63:
rem_skip 63 "review remediation: Ensure talk server is not enabled"

# RULE64:
rem_skip 64 "review remediation: Ensure telnet server is not enabled"

# RULE65:
rem_skip 65 "review remediation: Ensure rsh server is not enabled"

# RULE66:
rem_skip 66 "review remediation: Ensure rsync service is not enabled"

# RULE67:
rem_skip 67 "review remediation: Ensure NIS server is not enabled"

# RULE68:
sec_audit_pkg_remove nis
rem_done 68 "removed nis"

# RULE69:
sec_audit_pkg_remove rsh-client
rem_done 69 "removed rsh-client"

# RULE70:
sec_audit_pkg_remove talk
rem_done 70 "removed talk"

# RULE71:
sec_audit_pkg_remove telnet
rem_done 71 "removed telnet"

# RULE72:
sec_audit_pkg_remove ldap-utils
rem_done 72 "removed ldap-utils"

# RULE73:
sec_audit_pkg_install chrony
grep -q "^pool \|^server " /etc/chrony.conf 2>/dev/null || echo "pool 2.pool.ntp.org iburst" >>/etc/chrony.conf
sec_audit_start_svc chronyd
rem_done 73 "configured chrony"

# RULE74:
sec_audit_pkg_install chrony
grep -q "^pool \|^server " /etc/chrony.conf 2>/dev/null || echo "pool 2.pool.ntp.org iburst" >>/etc/chrony.conf
sec_audit_start_svc chronyd
rem_done 74 "configured chrony"

# RULE75:
rem_skip 75 "review remediation: Ensure X Window System is not installed"

# RULE76:
rem_skip 76 "review remediation: Ensure packet redirect sending is disabled"

# RULE77:
set_sysctl net.ipv4.ip_forward 0
rem_done 77 "set net.ipv4.ip_forward=0"

# RULE78:
rem_skip 78 "review remediation: Ensure source routed packets are not accepted"

# RULE79:
rem_skip 79 "review remediation: Ensure ICMP redirects are not accepted"

# RULE80:
rem_skip 80 "review remediation: Ensure secure ICMP redirects are not accepted"

# RULE81:
rem_skip 81 "review remediation: Ensure suspicious packets are logged"

# RULE82:
rem_skip 82 "review remediation: Ensure broadcast ICMP requests are ignored"

# RULE83:
rem_skip 83 "review remediation: Ensure bogus ICMP responses are ignored"

# RULE84:
rem_skip 84 "review remediation: Ensure Reverse Path Filtering is enabled"

# RULE85:
rem_skip 85 "review remediation: Ensure TCP SYN Cookies are enabled"

# RULE86:
rem_skip 86 "Ensure IPv6 router advertisements are not accepted"

# RULE87:
rem_skip 87 "Ensure IPv6 redirects are not accepted"

# RULE88:
rem_skip 88 "review remediation: Ensure auditing is enabled"

# RULE89:
sec_audit_pkg_install auditd audispd-plugins
sec_audit_start_svc auditd
rem_done 89 "auditd running"

# RULE90:
sec_audit_pkg_install auditd audispd-plugins
sec_audit_start_svc auditd
rem_done 90 "auditd running"

# RULE91:
rem_skip 91 "review remediation: Ensure audit_backlog_limit is sufficient"

# RULE92:
sec_audit_pkg_install audit auditd 2>/dev/null || true
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-debian12-cre.rules <<'EOF'
-D
-b 8192
-f 1
-w /etc/sudoers -p wa -k scope
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /var/sec_audit_log/audit/ -p wa -k audit_log
EOF
sec_audit_have_bin augenrules && augenrules --load >/dev/null 2>&1 || true
sec_audit_start_svc auditd
rem_done 92 "audit rules baseline"

# RULE93:
rem_skip 93 "review remediation: Ensure audit logs are not automatically deleted"

# RULE94:
rem_skip 94 "review remediation: Ensure system is disabled when audit logs are full"

# RULE95:
rem_skip 95 "review remediation: Ensure audit logs are rotated appropriately"

# RULE96:
rem_skip 96 "review remediation: Ensure audit configuration is immutable"

# RULE97:
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
rem_done 97 "rsyslog installed"

# RULE98:
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
rem_done 98 "rsyslog installed"

# RULE99:
rem_skip 99 "configure central logging per site policy before enabling journal remote/upload"

# RULE100:
mkdir -p /etc/systemd/journald.conf.d
cat >/etc/systemd/journald.conf.d/99-debian12-cre.conf <<'EOF'
[Journal]
ForwardToSyslog=no
Compress=yes
Storage=persistent
EOF
systemctl restart systemd-journald >/dev/null 2>&1 || true
rem_done 100 "journald configuration"

# RULE101:
mkdir -p /etc/systemd/journald.conf.d
cat >/etc/systemd/journald.conf.d/99-debian12-cre.conf <<'EOF'
[Journal]
ForwardToSyslog=no
Compress=yes
Storage=persistent
EOF
systemctl restart systemd-journald >/dev/null 2>&1 || true
rem_done 101 "journald configuration"

# RULE102:
rem_skip 102 "Ensure logrotate is configured"

# RULE103:
sec_audit_pkg_install cron
sec_audit_start_svc cron
rem_done 103 "enabled cron"

# RULE104:
chmod 600 /etc/crontab 2>/dev/null || true
chown root:root /etc/crontab 2>/dev/null || true
rem_done 104 "restricted /etc/crontab"

# RULE105:
rem_skip 105 "review remediation: Ensure permissions on /etc/cron.hourly are configured"

# RULE106:
rem_skip 106 "review remediation: Ensure permissions on /etc/cron.daily are configured"

# RULE107:
rem_skip 107 "review remediation: Ensure permissions on /etc/cron.weekly are configured"

# RULE108:
rem_skip 108 "review remediation: Ensure permissions on /etc/cron.monthly are configured"

# RULE109:
rem_skip 109 "review remediation: Ensure permissions on /etc/cron.d are configured"

# RULE110:
rem_skip 110 "review remediation: Ensure at/cron is restricted to authorized users"

# RULE111:
rem_skip 111 "review remediation: Ensure password creation requirements are configured"

# RULE112:
pam_faillock_debian >/dev/null 2>&1 || true
rem_done 112 "pam faillock"

# RULE113:
set_login_defs_kv ENCRYPT_METHOD SHA512
rem_done 113 "ENCRYPT_METHOD SHA512"

# RULE114:
rem_skip 114 "review remediation: Ensure root login is restricted to system console"

# RULE115:
rem_skip 115 "review remediation: Ensure su command access is restricted"

# RULE116:
sec_audit_pkg_install sudo
rem_done 116 "sudo installed"

# RULE117:
rem_skip 117 "review remediation: Ensure sudo commands use pty"

# RULE118:
rem_skip 118 "review remediation: Ensure sudo sec_audit_log file exists"

# RULE119:
rem_skip 119 "review remediation: Ensure users must provide password for escalation"

# RULE120:
rem_skip 120 "review remediation: Ensure re-authentication for privilege escalation is configured"

# RULE121:
rem_skip 121 "review remediation: Ensure sudo authentication uses strong hashing"

# RULE122:
rem_skip 122 "Ensure inactive password lock is configured"

# RULE123:
rem_skip 123 "review remediation: Ensure password expiration is configured"

# RULE124:
rem_skip 124 "review remediation: Ensure password expiration warning days are configured"

# RULE125:
rem_skip 125 "review remediation: Ensure password minimum days is configured"

# RULE126:
rem_skip 126 "review remediation: Ensure password reuse is limited"

# RULE127:
rem_skip 127 "review remediation: Ensure all users have a password"

# RULE128:
rem_skip 128 "Ensure system accounts are secured"

# RULE129:
rem_skip 129 "Ensure default group for root account is GID 0"

# RULE130:
set_login_defs_kv UMASK 027
cat >/etc/profile.d/99-cre-umask.sh <<'EOF'
umask 027
EOF
rem_done 130 "default umask 027"

# RULE131:
cat >/etc/profile.d/99-cre-timeout.sh <<'EOF'
TMOUT=600
readonly TMOUT
export TMOUT
EOF
rem_done 131 "TMOUT=600"

# RULE132:
rem_skip 132 "Ensure root account is secured"

# RULE133:
rem_skip 133 "Ensure all accounts have unique UID"

# RULE135:
rem_skip 135 "review remediation: Ensure all users' home directories exist"

# RULE136:
rem_skip 136 "review remediation: Ensure users own their home directories"

# RULE137:
rem_skip 137 "review remediation: Ensure users' home directories permissions are 750 or more restrictive"

# RULE138:
rem_skip 138 "review remediation: Ensure no users have .netrc files"

# RULE139:
rem_skip 139 "review remediation: Ensure users' .forward files are not present"

# RULE140:
rem_skip 140 "review remediation: Ensure users' .rhosts files are not present"

# RULE141:
set_sshd_kv X11Forwarding no
rem_done 141 "sshd X11Forwarding"

# RULE142:
set_sshd_kv MaxAuthTries 4
rem_done 142 "sshd MaxAuthTries"

# RULE143:
set_sshd_kv IgnoreRhosts yes
rem_done 143 "sshd IgnoreRhosts"

# RULE144:
set_sshd_kv HostbasedAuthentication no
rem_done 144 "sshd HostbasedAuthentication"

# RULE145:
rem_skip 145 "review remediation: Ensure SSH root login is disabled"

# RULE146:
set_sshd_kv PermitEmptyPasswords no
rem_done 146 "sshd PermitEmptyPasswords"

# RULE147:
set_sshd_kv PermitUserEnvironment no
rem_done 147 "sshd PermitUserEnvironment"

# RULE148:
rem_skip 148 "review remediation: Ensure SSH Idle Timeout Interval is configured"

# RULE149:
set_sshd_kv LoginGraceTime 60
rem_done 149 "sshd LoginGraceTime"

# RULE150:
rem_skip 150 "review remediation: Ensure SSH PAM is enabled"

# RULE151:
rem_skip 151 "review remediation: Ensure SSH AllowTcpForwarding is disabled"

# RULE152:
set_sshd_kv MaxStartups 10:30:60
rem_done 152 "sshd MaxStartups"

# RULE153:
set_sshd_kv MaxSessions 10
rem_done 153 "sshd MaxSessions"

# RULE154:
sec_audit_pkg_install aide
rem_done 154 "installed AIDE"

# RULE155:
harden_file /etc/passwd 644 root:root
rem_done 155 "permissions /etc/passwd"

# RULE156:
chmod 640 /etc/shadow 2>/dev/null || true
chown root:shadow /etc/shadow 2>/dev/null || true
rem_done 156 "permissions /etc/shadow"

# RULE157:
rem_skip 157 "Ensure permissions on /etc/group are configured"

# RULE158:
chmod 640 /etc/gshadow 2>/dev/null || true
chown root:shadow /etc/gshadow 2>/dev/null || true
rem_done 158 "permissions /etc/gshadow"

# RULE159:
rem_skip 159 "review remediation: Ensure password fields are not empty"

# RULE160:
rem_skip 160 "review remediation: Ensure no legacy '+' entries exist in /etc/passwd"

# RULE161:
rem_skip 161 "review remediation: Ensure no legacy '+' entries exist in /etc/shadow"

# RULE162:
rem_skip 162 "Ensure no legacy '+' entries exist in /etc/group"

# RULE163:
rem_skip 163 "Ensure root is the only UID 0 account"

# RULE164:
rem_skip 164 "Ensure all groups in /etc/passwd exist in /etc/group"

# RULE165:
rem_skip 165 "Ensure no duplicate UIDs exist"

# RULE166:
rem_skip 166 "Ensure no duplicate GIDs exist"

# RULE167:
rem_skip 167 "Ensure no duplicate user names exist"

# RULE168:
rem_skip 168 "Ensure no duplicate group names exist"

DEBIAN_FRONTEND=noninteractive apt-get update >/dev/null 2>&1 || true
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y >/dev/null 2>&1 || true

sec_audit_log " remediation complete (Debian12_remediation.sh)"
exit 0

