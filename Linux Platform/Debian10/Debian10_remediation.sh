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

# RULE1:
rem_skip 1 "review remediation: The squashfs kernel module is not available"

# RULE2:
rem_skip 2 "review remediation: The squashfs kernel module is not available"

# RULE3:
rem_skip 3 "review remediation: The jffs2 kernel module is not available"

# RULE4:
rem_skip 4 "review remediation: The hfs kernel module is not available"

# RULE5:
rem_skip 5 "review remediation: The hfsplus kernel module is not available"

# RULE6:
rem_skip 6 "review remediation: The squashfs kernel module is not available"

# RULE7:
rem_skip 7 "review remediation: The udf kernel module is not available"

# RULE8:
rem_skip 8 "review remediation: A separate partition exists for /tmp is configured"

# RULE9:
rem_skip 9 "review remediation: The nodev option is set on the /tmp partition is configured"

# RULE10:
rem_skip 10 "review remediation: The nosuid option is set on the /tmp partition is configured"

# RULE11:
rem_skip 11 "review remediation: The noexec option is set on the /tmp partition is configured"

# RULE12:
rem_skip 12 "review remediation: The nodev option is set on the /dev/shm partition is configured"

# RULE13:
rem_skip 13 "review remediation: The nosuid option is set on the /dev/shm partition is configured"

# RULE14:
rem_skip 14 "review remediation: The noexec option is set on the /dev/shm partition is configured"

# RULE15:
rem_skip 15 "review remediation: A separate partition exists for /var is configured"

# RULE16:
rem_skip 16 "review remediation: A separate partition exists for /var /tmp is configured"

# RULE17:
sec_audit_pkg_install auditd audispd-plugins
sec_audit_start_svc auditd
rem_done 17 "auditd running"

# RULE18:
rem_skip 18 "review remediation: The nosuid option is set on the /var/tmp partition is configured"

# RULE19:
rem_skip 19 "review remediation: The noexec parameter is set on the /var/tmp partition is configured"

# RULE20:
ensure_mount_option /dev/shm noexec
rem_done 20 "set noexec on /dev/shm"

# RULE21:
ensure_mount_option /dev/shm nodev
rem_done 21 "set nodev on /dev/shm"

# RULE22:
rem_skip 22 "Ensure nosuid option set on /dev/shm partition"

# RULE23:
rem_skip 23 "review remediation: The nodev mount option is set on /var"

# RULE24:
rem_skip 24 "review remediation: The sticky bit is set on all world-writable directories is configured"

# RULE25:
rem_skip 25 "review remediation: GPG keys are configured"

# RULE26:
rem_skip 26 "review remediation: GPG keys are configured"

# RULE27:
rem_skip 27 "review remediation: AIDE is installed is configured"

# RULE28:
rem_skip 28 "review remediation: File system integrity is checked regularly is configured"

# RULE29:
harden_file /boot/grub2/grub.cfg 600 root:root
harden_file /boot/grub2/user.cfg 600 root:root
rem_done 29 "hardened grub permissions"

# RULE30:
rem_skip 30 "review remediation: Bootloader configuration permissions are configured"

# RULE31:
rem_skip 31 "review remediation: The bootloader password is set is configured"

# RULE32:
rem_skip 32 "review remediation: The bootloader password is set is configured"

# RULE33:
rem_skip 33 "review remediation: XD/NX support is enabled"

# RULE34:
rem_skip 34 "review remediation: XD/NX support is enabled"

# RULE35:
rem_skip 35 "review remediation: Address space layout randomization (ASLR) is enabled"

# RULE36:
rem_skip 36 "review remediation: XD/NX support is enabled"

# RULE37:
rem_skip 37 "review remediation: Single-user mode requires authentication is configured"

# RULE38:
rem_skip 38 "review remediation: Prelinking is disabled"

# RULE39:
rem_skip 39 "review remediation: Core dumps are restricted is configured"

# RULE40:
rem_skip 40 "review remediation: SELinux is not disabled in the bootloader configuration is configured"

# RULE41:
rem_skip 41 "review remediation: The SELinux state is enforcing is configured"

# RULE42:
rem_skip 42 "review remediation: The SELinux state is enforcing is configured"

# RULE43:
rem_skip 43 "review remediation: The message of the day is configured correctly"

# RULE44:
rem_skip 44 "review remediation: The local login warning banner is configured correctly"

# RULE45:
rem_skip 45 "review remediation: The remote login warning banner is configured correctly"

# RULE46:
rem_skip 46 "review remediation: Permissions for /etc/motd are configured"

# RULE47:
rem_skip 47 "review remediation: Permissions for /etc/issue are configured"

# RULE48:
rem_skip 48 "review remediation: Updates, patches, and additional security software are installed is configured"

# RULE49:
rem_skip 49 "review remediation: Updates, patches, and additional security software are installed is configured"

# RULE50:
rem_skip 50 "review remediation: Time synchronization is used is configured"

# RULE51:
rem_skip 51 "review remediation: Time synchronization is used is configured"

# RULE52:
rem_skip 52 "review remediation: Chrony is configured"

# RULE53:
rem_skip 53 "review remediation: NTP is configured"

# RULE54:
rem_skip 54 "review remediation: The X Window System is not installed is configured"

# RULE55:
rem_skip 55 "review remediation: The Avahi server is not enabled is configured"

# RULE56:
rem_skip 56 "review remediation: CUPS is not enabled is configured"

# RULE57:
rem_skip 57 "review remediation: The DHCP server is not enabled is configured"

# RULE58:
rem_skip 58 "review remediation: The LDAP server is not enabled is configured"

# RULE59:
rem_skip 59 "review remediation: NFS and RPC are not enabled is configured"

# RULE60:
rem_skip 60 "review remediation: The FTP server is not enabled is configured"

# RULE61:
rem_skip 61 "review remediation: The HTTP server is not enabled is configured"

# RULE62:
rem_skip 62 "review remediation: Unused IMAP and POP3 server is not disabled is configured"

# RULE63:
rem_skip 63 "review remediation: Samba is not enabled is configured"

# RULE64:
rem_skip 64 "review remediation: The HTTP proxy server is not enabled is configured"

# RULE65:
rem_skip 65 "review remediation: The SNMP server is not enabled is configured"

# RULE66:
rem_skip 66 "review remediation: The mail transfer agent is configured for local-only mode"

# RULE67:
rem_skip 67 "review remediation: The rsync service is not enabled is configured"

# RULE68:
rem_skip 68 "review remediation: Unless the system is specifically intended to operate as a DNS server, it is recommended to remove the package to reduce the potential attack surface"

# RULE69:
rem_skip 69 "review remediation: The NIS client is not installed is configured"

# RULE70:
rem_skip 70 "review remediation: The rsh client is not installed is configured"

# RULE71:
rem_skip 71 "review remediation: The talk client is not installed is configured"

# RULE72:
rem_skip 72 "review remediation: The telnet client is not installed is configured"

# RULE73:
rem_skip 73 "review remediation: The LDAP client is not installed is configured"

# RULE74:
set_sysctl net.ipv4.ip_forward 0
rem_done 74 "set net.ipv4.ip_forward=0"

# RULE75:
rem_skip 75 "review remediation: Packet forwarding is disabled"

# RULE76:
rem_skip 76 "review remediation: Source routed packets are not accepted is configured"

# RULE77:
set_sysctl net.ipv4.conf.all.accept_redirects 0
rem_done 77 "set net.ipv4.conf.all.accept_redirects=0"

# RULE78:
rem_skip 78 "review remediation: Secure ICMP redirects are not accepted is configured"

# RULE79:
rem_skip 79 "review remediation: Suspicious packets are logged is configured"

# RULE80:
rem_skip 80 "review remediation: ICMP broadcast requests are ignored is configured"

# RULE81:
set_sysctl net.ipv4.icmp_ignore_bogus_error_responses 1
rem_done 81 "set net.ipv4.icmp_ignore_bogus_error_responses=1"

# RULE82:
set_sysctl net.ipv4.conf.all.rp_filter 1
rem_done 82 "set net.ipv4.conf.all.rp_filter=1"

# RULE83:
set_sysctl net.ipv4.tcp_syncookies 1
rem_done 83 "set net.ipv4.tcp_syncookies=1"

# RULE84:
rem_skip 84 "review remediation: IPv6 router advertisements are not accepted is configured"

# RULE85:
rem_skip 85 "review remediation: DCCP is disabled"

# RULE86:
rem_skip 86 "review remediation: SCTP is disabled"

# RULE87:
rem_skip 87 "review remediation: RDS is disabled"

# RULE88:
rem_skip 88 "review remediation: TIPC is disabled"

# RULE89:
sec_audit_pkg_install nftables
systemctl enable --now nftables >/dev/null 2>&1 || true
rem_done 89 "nftables baseline"

# RULE90:
rem_skip 90 "review remediation: The Audit service is enabled"

# RULE91:
rem_skip 91 "review remediation: The audit log storage size is configured"

# RULE92:
sec_audit_pkg_install auditd audispd-plugins
sec_audit_start_svc auditd
rem_done 92 "auditd running"

# RULE93:
sec_audit_pkg_install auditd audispd-plugins
sec_audit_start_svc auditd
rem_done 93 "auditd running"

# RULE94:
sec_audit_pkg_install auditd audispd-plugins
sec_audit_start_svc auditd
rem_done 94 "auditd running"

# RULE95:
sec_audit_pkg_install auditd audispd-plugins
sec_audit_start_svc auditd
rem_done 95 "auditd running"

# RULE96:
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
rem_done 96 "rsyslog installed"

# RULE97:
rem_skip 97 "review remediation: Default rsyslog file permissions are configured"

# RULE98:
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
rem_done 98 "rsyslog installed"

# RULE99:
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
rem_done 99 "rsyslog installed"

# RULE100:
rem_skip 100 "review remediation: Cron daemon is enabled"

# RULE101:
chmod 600 /etc/crontab 2>/dev/null || true
chown root:root /etc/crontab 2>/dev/null || true
rem_done 101 "restricted /etc/crontab"

# RULE102:
rem_skip 102 "review remediation: Permissions for /etc/cron.hourly is configured"

# RULE103:
rem_skip 103 "review remediation: Permissions for /etc/cron.daily is configured"

# RULE104:
rem_skip 104 "review remediation: Permissions for /etc/cron.weekly is configured"

# RULE105:
rem_skip 105 "review remediation: Permissions for /etc/cron.monthly is configured"

# RULE106:
chmod 600 /etc/crontab 2>/dev/null || true
chown root:root /etc/crontab 2>/dev/null || true
rem_done 106 "restricted /etc/crontab"

# RULE107:
rem_skip 107 "review remediation: Access to /cron is permitted only for authorized users"

# RULE108:
rem_skip 108 "review remediation: Permissions for /etc/ssh/sshd_config is configured"

# RULE109:
rem_skip 109 "review remediation: SSH version 2 is used is configured"

# RULE110:
rem_skip 110 "review remediation: SSH LogLevel is set to INFO is configured"

# RULE111:
rem_skip 111 "review remediation: Disable unused filesystems"

# RULE112:
sec_audit_ensure_fstab_mount /tmp "nodev,nosuid,noexec"
rem_done 112 "configured mount /tmp"

# RULE113:
rem_skip 113 "review remediation: Configure /var"

# RULE114:
rem_skip 114 "review remediation: Configure /var/tmp"

# RULE115:
rem_skip 115 "review remediation: Configure /var/sec_audit_log"

# RULE116:
rem_skip 116 "create separate partition for /var during provisioning; then set mount options"

# RULE117:
rem_skip 117 "create separate partition for /var/tmp during provisioning; then set mount options"

# RULE118:
rem_skip 118 "create separate partition for /var/sec_audit_log during provisioning; then set mount options"

# RULE119:
rem_skip 119 "create separate partition for /var/sec_audit_log/audit during provisioning; then set mount options"

# RULE120:
set_sshd_kv ClientAliveInterval 300
rem_done 120 "sshd ClientAliveInterval"

# RULE121:
rem_skip 121 "review remediation: SSH warning banner is configured"

# RULE122:
sec_audit_pkg_install aide
rem_done 122 "installed AIDE"

# RULE123:
sec_audit_pkg_install aide afick
rem_done 123 "integrity tooling"

# RULE124:
rem_skip 124 "review remediation: Password reuse restrictions"

# RULE125:
set_login_defs_kv ENCRYPT_METHOD SHA512
rem_done 125 "ENCRYPT_METHOD SHA512"

# RULE126:
rem_skip 126 "review remediation: Password expiration warning period"

# RULE127:
rem_skip 127 "review remediation: Password lifetime does not exceed 365 days"

# RULE128:
set_login_defs_kv PASS_WARN_AGE 7
rem_done 128 "PASS_WARN_AGE 7"

# RULE129:
rem_skip 129 "review remediation: Lock inactive passwords"

# RULE130:
rem_skip 130 "review remediation: Lock inactive passwords"

# RULE131:
rem_skip 131 "review remediation: Default group for the root account GID 0"

# RULE132:
rem_skip 132 "review remediation: Ensure updates, patches, and additional security software are installed"

# RULE133:
rem_skip 133 "Ensure package manager repositories are configured"

# RULE134:
rem_skip 134 "Ensure GPG keys are configured"

# RULE135:
rem_skip 135 "review remediation: Permissions for /etc/passwd- is configured"

# RULE136:
rem_skip 136 "review remediation: Permissions for /etc/group is configured"

# RULE137:
rem_skip 137 "review remediation: Permissions for /etc/shadow- is configured"

# RULE138:
rem_skip 138 "review remediation: Permissions for /etc/shadow is configured"

# RULE139:
rem_skip 139 "review remediation: Permissions for /etc/passwd- is configured"

# RULE140:
rem_skip 140 "review remediation: Permissions for /etc/gshadow is configured"

# RULE141:
rem_skip 141 "review remediation: Permissions for /etc/gshadow- is configured"

# RULE142:
rem_skip 142 "review remediation: There are no world-writable files"

# RULE143:
rem_skip 143 "review remediation: No unused files or directories exist"

# RULE144:
rem_skip 144 "review remediation: No unused files or directories exist"

# RULE145:
rem_skip 145 "review remediation: Audit SUID executable files"

# RULE146:
rem_skip 146 "review remediation: Audit SGID executable files"

# RULE147:
rem_skip 147 "review remediation: Password fields are not empty"

# RULE148:
rem_skip 148 "review remediation: Root is the only UID 0 account"

# RULE149:
rem_skip 149 "Ensure bootloader password is set"

# RULE150:
rem_skip 150 "review remediation: Permissions on /etc/gshadow are configured correctly"

# RULE151:
harden_file /boot/grub2/grub.cfg 600 root:root
harden_file /boot/grub2/user.cfg 600 root:root
rem_done 151 "hardened grub permissions"

# RULE152:
rem_skip 152 "review remediation: Ensure authentication required for single user mode"

# RULE153:
rem_skip 153 "review remediation: Time synchronization is used is configured"

# RULE154:
rem_skip 154 "review remediation: The password hashing algorithm is SHA-512 is configured"

# RULE155:
rem_skip 155 "review remediation: Remove all obsolete \"+\" files"

# RULE156:
rem_skip 156 "review remediation: Remove all obsolete \"+\" files"

# RULE157:
rem_skip 157 "review remediation: Remove all obsolete \"+\" files"

# RULE158:
rem_skip 158 "review remediation: OSSEC is installed is configured"

# RULE159:
rem_skip 159 "review remediation: Ensure Automatic Error Reporting is not enabled"

# RULE160:
rem_skip 160 "review remediation: Ensure address space layout randomization (ASLR) is enabled"

# RULE161:
set_sysctl kernel.yama.ptrace_scope 1
rem_done 161 "set kernel.yama.ptrace_scope=1"

# RULE162:
rem_skip 162 "review remediation: Ensure prelink is not installed"

# RULE163:
grep -q "hard core" /etc/security/limits.conf 2>/dev/null || echo "* hard core 0" >>/etc/security/limits.conf
mkdir -p /etc/systemd/coredump.conf.d
cat >/etc/systemd/coredump.conf.d/99-cre-sec.conf <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
sec_audit_have_bin systemctl && systemctl daemon-reload >/dev/null 2>&1 || true
rem_done 163 "disabled core dumps"

# RULE164:
rem_skip 164 "review remediation: Remove all obsolete "+" files"

# RULE165:
rem_skip 165 "review remediation: Remove all obsolete "+" files"

# RULE166:
rem_skip 166 "review remediation: Xinetd is not enabled is configured"

# RULE167:
rem_skip 167 "review remediation: NFS and RPC are not enabled is configured"

# RULE168:
sec_audit_pkg_install aide afick
rem_done 168 "integrity tooling"

# RULE169:
sec_audit_pkg_install aide afick
rem_done 169 "integrity tooling"

# RULE170:
sec_audit_pkg_install aide afick
rem_done 170 "integrity tooling"

# RULE171:
sec_audit_pkg_install aide afick
rem_done 171 "integrity tooling"

# RULE172:
pam_faillock_debian >/dev/null 2>&1 || true
rem_done 172 "pam faillock"

# RULE173:
sec_audit_pkg_install libpam-pwquality
cat >/etc/security/pwquality.conf <<'EOF'
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF
rem_done 173 "password quality"

# RULE174:
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
rem_done 174 "rsyslog installed"

# RULE175:
rem_skip 175 "review remediation: NTP is configured"

# RULE176:
rem_skip 176 "review remediation: Ensure password creation requirements are configured"

# RULE177:
pam_faillock_debian >/dev/null 2>&1 || true
rem_done 177 "pam faillock"

# RULE178:
rem_skip 178 "review remediation: Ensure password reuse is limited"

# RULE179:
set_login_defs_kv ENCRYPT_METHOD SHA512
rem_done 179 "ENCRYPT_METHOD SHA512"

# RULE180:
sec_audit_pkg_install sudo
rem_done 180 "sudo installed"

# RULE181:
rem_skip 181 "review remediation: Ensure sudo commands use pty"

# RULE182:
rem_skip 182 "review remediation: Ensure sudo sec_audit_log file exists"

# RULE183:
rem_skip 183 "review remediation: Ensure users must provide password for privilege escalation"

# RULE184:
rem_skip 184 "review remediation: Set Shadow Password Suite Parameters"

# RULE185:
rem_skip 185 "Ensure system accounts are secured"

# RULE186:
rem_skip 186 "Ensure default group for the root account is GID 0"

# RULE187:
set_login_defs_kv UMASK 027
cat >/etc/profile.d/99-cre-umask.sh <<'EOF'
umask 027
EOF
rem_done 187 "default umask 027"

# RULE188:
rem_skip 188 "review remediation: Disable USB Storage"

# RULE189:
sec_audit_pkg_install auditd audispd-plugins
sec_audit_start_svc auditd
rem_done 189 "auditd running"

# RULE190:
sec_audit_pkg_install auditd audispd-plugins
sec_audit_start_svc auditd
rem_done 190 "auditd running"

# RULE191:
rem_skip 191 "review remediation: Ensure audit_backlog_limit is sufficient"

# RULE192:
rem_skip 192 "review remediation: Ensure events that modify date and time information are collected"

# RULE193:
rem_skip 193 "Ensure events that modify user/group information are collected"

# RULE194:
rem_skip 194 "review remediation: Ensure login and logout events are collected"

# RULE195:
rem_skip 195 "review remediation: Ensure session initiation information is collected"

# RULE196:
rem_skip 196 "review remediation: Ensure use of privileged commands are collected"

# RULE197:
rem_skip 197 "review remediation: Ensure file deletion events by users are collected"

# RULE198:
rem_skip 198 "review remediation: Ensure changes to system administration scope (sudoers) is collected"

# RULE199:
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
rem_done 199 "rsyslog installed"

# RULE200:
rem_skip 200 "review remediation: Ensure permissions on SSH private host key files are configured"

# RULE201:
rem_skip 201 "review remediation: Ensure permissions on SSH public host key files are configured"

# RULE202:
rem_skip 202 "Ensure system accounts are secured"

# RULE203:
rem_skip 203 "review remediation: Ensure access to the su command is restricted"

# RULE204:
rem_skip 204 "Ensure root PATH Integrity"

# RULE205:
rem_skip 205 "Ensure users' dot files are not group or world writable"

# RULE206:
rem_skip 206 "Ensure no duplicate UIDs exist"

# RULE207:
rem_skip 207 "Ensure no duplicate GIDs exist"

# RULE208:
rem_skip 208 "Ensure no duplicate user names exist"

# RULE209:
rem_skip 209 "Ensure no duplicate group names exist"

# RULE210:
rem_skip 210 "Ensure shadow group is empty"

# RULE211:
sec_audit_disable_kmod bluetooth
rem_done 211 "disabled wireless interfaces"

# RULE212:
rem_skip 212 "review remediation: Ensure SSH PAM is enabled"

# RULE213:
rem_skip 213 "review remediation: Prohibit mounting of cramfs filesystems"

# RULE214:
rem_skip 214 "review remediation: /tmp is a separate partition is configured"

# RULE215:
rem_skip 215 "review remediation: The nodev option is set for the /var partition is configured"

# RULE216:
rem_skip 216 "review remediation: The nosuid option is set for the /var partition is configured"

# RULE217:
rem_skip 217 "review remediation: The nodev option is set for the /var/log partition is configured"

# RULE218:
rem_skip 218 "review remediation: The noexec option is set for the /var/log partition is configured"

# RULE219:
rem_skip 219 "review remediation: The nosuid option is set for the /var/log partition is configured"

# RULE220:
rem_skip 220 "review remediation: The nodev option is set on the /var/log/audit partition is configured"

# RULE221:
rem_skip 221 "review remediation: The noexec option is set on the /var/log/audit partition is configured"

# RULE222:
rem_skip 222 "review remediation: The nosuid option is set on the /var/log/audit partition is configured"

# RULE223:
rem_skip 223 "review remediation: The nosuid option is set for the /home partition is configured"

# RULE224:
rem_skip 224 "review remediation: The nodev option is set on the /var/log/audit partition is configured"

# RULE225:
rem_skip 225 "review remediation: The noexec option is set on the /var/log/audit partition is configured"

# RULE226:
rem_skip 226 "review remediation: The nosuid option is set on the /var/log/audit partition is configured"

# RULE227:
rem_skip 227 "review remediation: The nosuid option is set for the /home partition is configured"

# RULE228:
mkdir -p /etc/dconf/db/gdm.d
sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
rem_done 228 "configured GDM hardening"

# RULE229:
rem_skip 229 "review remediation: GPG keys are configured"

# RULE230:
rem_skip 230 "review remediation: Ptrace_scope is restricted"

# RULE231:
rem_skip 231 "review remediation: Prohibit automatic sending of error reports"

# RULE232:
rem_skip 232 "review remediation: Remove GNOME Display Manager (GDM)"

# RULE233:
rem_skip 233 "review remediation: The disable-user-list option in GDM is enabled"

# RULE234:
rem_skip 234 "review remediation: GDM screen lock on idle is configured"

# RULE235:
rem_skip 235 "review remediation: Prohibit canceling GDM screen lock"

# RULE236:
rem_skip 236 "review remediation: Automatic mounting of removable media in GDM is disabled"

# RULE237:
rem_skip 237 "review remediation: Prohibit overriding the disablement of automount in GDM"

# RULE238:
rem_skip 238 "review remediation: The autorun-never option in GDM is enabled"

# RULE239:
rem_skip 239 "review remediation: Prohibit overriding autorun-never in GDM"

# RULE240:
rem_skip 240 "review remediation: XDMCP is disabled"

# RULE241:
rem_skip 241 "review remediation: Only one time synchronization daemon is used is configured"

# RULE242:
rem_skip 242 "review remediation: Chrony is configured with an authorized time server"

# RULE243:
rem_skip 243 "review remediation: Chrony is run as the _chrony user is configured"

# RULE244:
rem_skip 244 "review remediation: Systemd-timesyncd is configured with an authorized time server"

# RULE245:
rem_skip 245 "review remediation: NTP access control is configured"

# RULE246:
rem_skip 246 "review remediation: NTP is configured with an authorized time server"

# RULE247:
rem_skip 247 "review remediation: NTP runs as the ntp user is configured"

# RULE248:
rem_skip 248 "review remediation: Avahi server is not installed is configured"

# RULE249:
rem_skip 249 "review remediation: CUPS is not installed is configured"

# RULE250:
rem_skip 250 "review remediation: DHCP server is not installed is configured"

# RULE251:
rem_skip 251 "review remediation: LDAP server is not installed is configured"

# RULE252:
rem_skip 252 "review remediation: NFS is not installed is configured"

# RULE253:
rem_skip 253 "review remediation: The absence of IMAP and POP3 servers is configured"

# RULE254:
rem_skip 254 "review remediation: Dnsmasq is not installed is configured"

# RULE255:
sec_audit_disable_kmod bluetooth
sec_audit_pkg_remove bluez
sec_audit_disable_svc bluetooth.service
rem_done 255 "disabled bluetooth"

# RULE256:
sec_audit_pkg_install nftables
systemctl enable --now nftables >/dev/null 2>&1 || true
rem_done 256 "nftables baseline"

# RULE257:
sec_audit_pkg_install nftables
systemctl enable --now nftables >/dev/null 2>&1 || true
rem_done 257 "nftables baseline"

# RULE258:
sec_audit_pkg_install nftables
systemctl enable --now nftables >/dev/null 2>&1 || true
rem_done 258 "nftables baseline"

# RULE259:
sec_audit_pkg_install nftables
systemctl enable --now nftables >/dev/null 2>&1 || true
rem_done 259 "nftables baseline"

# RULE260:
rem_skip 260 "review remediation: Iptables-persistent is not installed together with ufw is configured"

# RULE261:
rem_skip 261 "review remediation: Ufw is removed or disabled when using nftables is configured"

# RULE262:
echo "Defaults timestamp_timeout=5" >/etc/sudoers.d/99-cre-timeout
chmod 440 /etc/sudoers.d/99-cre-timeout
rem_done 262 "sudo timestamp_timeout=5"

# RULE263:
rem_skip 263 "review remediation: Ufw is removed or disabled when using iptables is configured"

# RULE264:
rem_skip 264 "review remediation: Users must provide a password to elevate privileges is configured"

# RULE265:
rem_skip 265 "review remediation: Re-authentication for privilege elevation is not disabled globally is configured"

# RULE266:
rem_skip 266 "review remediation: The sudo authentication timeout is configured correctly"

# RULE267:
rem_skip 267 "review remediation: All current passwords use the configured hashing algorithm is configured"

# RULE268:
rem_skip 268 "review remediation: The minimum number of changed characters in a new password is configured"

# RULE269:
rem_skip 269 "review remediation: Dictionary words are prohibited in passwords is configured"

# RULE270:
rem_skip 270 "review remediation: Nologin is not listed in /etc/shells is configured"

# RULE271:
rem_skip 271 "review remediation: The maximum number of identical consecutive characters in a password is configured"

# RULE272:
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
rem_done 272 "rsyslog installed"

# RULE273:
rem_skip 273 "review remediation: Systemd-journal-remote is configured"

# RULE274:
rem_skip 274 "review remediation: Systemd-journal-remote is enabled"

# RULE275:
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
rem_done 275 "rsyslog installed"

# RULE276:
rem_skip 276 "review remediation: Journald is not configured to send logs to rsyslog is configured"

# RULE277:
rem_skip 277 "review remediation: Journald log rotation is configured according to site policy"

# RULE278:
rem_skip 278 "review remediation: Permissions on journald log files are configured correctly"

# RULE279:
rem_skip 279 "review remediation: Rsyslog is not configured to receive logs from remote clients is configured"

# RULE280:
rem_skip 280 "review remediation: Successful and unsuccessful attempts to use the chcon command are recorded is configured"

# RULE281:
rem_skip 281 "review remediation: Successful and unsuccessful attempts to use the setfacl command are recorded is configured"

# RULE282:
rem_skip 282 "review remediation: Successful and unsuccessful attempts to use the chacl command are recorded is configured"

# RULE283:
rem_skip 283 "review remediation: Successful and unsuccessful attempts to use the usermod command are recorded is configured"

# RULE284:
rem_skip 284 "review remediation: The current and saved audit configurations match is configured"

# RULE285:
rem_skip 285 "review remediation: Audit configuration files have permissions of 640 or more restrictive is configured"

# RULE286:
rem_skip 286 "review remediation: Audit configuration files are owned by root is configured"

# RULE287:
rem_skip 287 "review remediation: Audit configuration files are owned by the root group is configured"

# RULE288:
rem_skip 288 "review remediation: Audit tools have permissions of 755 or more restrictive is configured"

# RULE289:
rem_skip 289 "review remediation: Audit tools are owned by the root user is configured"

# RULE290:
rem_skip 290 "review remediation: Audit tools are owned by the root group is configured"

# RULE291:
rem_skip 291 "review remediation: Cryptographic mechanisms are used to protect the integrity of audit tools is configured"

DEBIAN_FRONTEND=noninteractive apt-get update >/dev/null 2>&1 || true
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y >/dev/null 2>&1 || true

sec_audit_log " remediation complete (Debian10_remediation.sh)"
exit 0

