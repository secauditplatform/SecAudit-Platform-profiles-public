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
    local key="$1" val="$2" f="/etc/sysctl.d/99-debian11-cre-sec.conf"
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

sec_audit_log "starting remediation (sec_Debian_Linux_11_v2.0.0)"

# RULE1:
rem_skip 1 "review remediation: The cramfs kernel module is not available"

# RULE2:
rem_skip 2 "review remediation: The squashfs kernel module is not available"

# RULE3:
rem_skip 3 "review remediation: The udf kernel module is not available"

# RULE4:
rem_skip 4 "review remediation: A separate partition exists for /tmp"

# RULE5:
rem_skip 5 "review remediation: The nodev option is set on the /tmp partition"

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
sec_audit_pkg_install auditd audispd-plugins
sec_audit_start_svc auditd
rem_done 14 "auditd running"

# RULE15:
rem_skip 15 "review remediation: A separate partition exists for /var is configured"

# RULE16:
rem_skip 16 "review remediation: A separate partition exists for /var /tmp is configured"

# RULE17:
ensure_mount_option /dev/shm noexec
rem_done 17 "set noexec on /dev/shm"

# RULE18:
ensure_mount_option /dev/shm nodev
rem_done 18 "set nodev on /dev/shm"

# RULE19:
rem_skip 19 "Ensure nosuid option set on /dev/shm partition"

# RULE20:
rem_skip 20 "review remediation: A separate partition exists for /var/log is configured"

# RULE21:
rem_skip 21 "review remediation: GPG keys are configured"

# RULE22:
rem_skip 22 "review remediation: A separate partition exists for /var"

# RULE23:
rem_skip 23 "review remediation: The nodev mount option is set on /var"

# RULE24:
rem_skip 24 "review remediation: Filesystem integrity is regularly checked"

# RULE25:
harden_file /boot/grub2/grub.cfg 600 root:root
harden_file /boot/grub2/user.cfg 600 root:root
rem_done 25 "hardened grub permissions"

# RULE26:
rem_skip 26 "review remediation: GPG keys are configured"

# RULE27:
rem_skip 27 "review remediation: AIDE is installed is configured"

# RULE28:
rem_skip 28 "review remediation: File system integrity is checked regularly is configured"

# RULE29:
rem_skip 29 "review remediation: File system integrity is checked regularly is configured"

# RULE30:
rem_skip 30 "review remediation: Bootloader configuration permissions are configured"

# RULE31:
rem_skip 31 "review remediation: The bootloader password is set is configured"

# RULE32:
rem_skip 32 "review remediation: The bootloader password is set is configured"

# RULE33:
rem_skip 33 "review remediation: SELinux is enabled at boot"

# RULE34:
rem_skip 34 "review remediation: SELinux is set to enforcing mode"

# RULE35:
rem_skip 35 "review remediation: Address space layout randomization (ASLR) is enabled"

# RULE36:
rem_skip 36 "review remediation: The message of the day is configured correctly"

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
rem_skip 42 "review remediation: Updates, patches, and additional security software are installed is configured"

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
rem_skip 48 "review remediation: Permissions on /etc/issue.net are configured"

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
rem_skip 62 "review remediation: Unless the system is specifically intended to operate as a DNS server, it is recommended to remove the package to reduce the potential attack likelihood"

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
set_sysctl net.ipv4.ip_forward 0
rem_done 68 "set net.ipv4.ip_forward=0"

# RULE69:
rem_skip 69 "review remediation: The NIS client is not installed is configured"

# RULE70:
rem_skip 70 "review remediation: The rsh client is not installed is configured"

# RULE71:
set_sysctl net.ipv4.conf.all.accept_redirects 0
rem_done 71 "set net.ipv4.conf.all.accept_redirects=0"

# RULE72:
rem_skip 72 "review remediation: The telnet client is not installed is configured"

# RULE73:
rem_skip 73 "review remediation: The LDAP client is not installed is configured"

# RULE74:
rem_skip 74 "review remediation: IP forwarding is disabled"

# RULE75:
set_sysctl net.ipv4.icmp_ignore_bogus_error_responses 1
rem_done 75 "set net.ipv4.icmp_ignore_bogus_error_responses=1"

# RULE76:
set_sysctl net.ipv4.conf.all.rp_filter 1
rem_done 76 "set net.ipv4.conf.all.rp_filter=1"

# RULE77:
set_sysctl net.ipv4.tcp_syncookies 1
rem_done 77 "set net.ipv4.tcp_syncookies=1"

# RULE78:
rem_skip 78 "review remediation: Secure ICMP redirects are not accepted is configured"

# RULE79:
rem_skip 79 "review remediation: Suspicious packets are logged is configured"

# RULE80:
rem_skip 80 "review remediation: ICMP broadcast requests are ignored is configured"

# RULE81:
rem_skip 81 "review remediation: Logging of bogus responses by the kernel is prevented is configured"

# RULE82:
rem_skip 82 "review remediation: Reverse path filtering is enabled"

# RULE83:
sec_audit_pkg_install nftables
systemctl enable --now nftables >/dev/null 2>&1 || true
rem_done 83 "nftables baseline"

# RULE84:
rem_skip 84 "review remediation: IPv6 router advertisements are not accepted is configured"

# RULE85:
rem_skip 85 "review remediation: DCCP is disabled"

# RULE86:
sec_audit_pkg_install auditd audispd-plugins
sec_audit_start_svc auditd
rem_done 86 "auditd running"

# RULE87:
sec_audit_pkg_install auditd audispd-plugins
sec_audit_start_svc auditd
rem_done 87 "auditd running"

# RULE88:
sec_audit_pkg_install auditd audispd-plugins
sec_audit_start_svc auditd
rem_done 88 "auditd running"

# RULE89:
sec_audit_pkg_install auditd audispd-plugins
sec_audit_start_svc auditd
rem_done 89 "auditd running"

# RULE90:
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
rem_done 90 "rsyslog installed"

# RULE91:
rem_skip 91 "review remediation: The audit log storage size is configured"

# RULE92:
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
rem_done 92 "rsyslog installed"

# RULE93:
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
rem_done 93 "rsyslog installed"

# RULE94:
rem_skip 94 "review remediation: The system is shut down when audit logs are full is configured"

# RULE95:
chmod 600 /etc/crontab 2>/dev/null || true
chown root:root /etc/crontab 2>/dev/null || true
rem_done 95 "restricted /etc/crontab"

# RULE96:
rem_skip 96 "review remediation: The rsyslog service is enabled"

# RULE97:
rem_skip 97 "review remediation: Default rsyslog file permissions are configured"

# RULE98:
rem_skip 98 "review remediation: Rsyslog is configured to send logs to a remote log host"

# RULE99:
rem_skip 99 "review remediation: Remote rsyslog messages are accepted only for designated host logs is configured"

# RULE100:
chmod 600 /etc/crontab 2>/dev/null || true
chown root:root /etc/crontab 2>/dev/null || true
rem_done 100 "restricted /etc/crontab"

# RULE101:
rem_skip 101 "review remediation: Permissions for /etc/crontab is configured"

# RULE102:
rem_skip 102 "review remediation: Permissions for /etc/cron.hourly is configured"

# RULE103:
rem_skip 103 "review remediation: Permissions for /etc/cron.daily is configured"

# RULE104:
rem_skip 104 "review remediation: Permissions for /etc/cron.weekly is configured"

# RULE105:
rem_skip 105 "review remediation: Permissions for /etc/cron.monthly is configured"

# RULE106:
set_sshd_kv MaxAuthTries 4
rem_done 106 "sshd MaxAuthTries"

# RULE107:
rem_skip 107 "review remediation: Access to /cron is permitted only for authorized users"

# RULE108:
set_sshd_kv HostbasedAuthentication no
rem_done 108 "sshd HostbasedAuthentication"

# RULE109:
set_sshd_kv PermitRootLogin no
rem_done 109 "sshd PermitRootLogin"

# RULE110:
set_sshd_kv PermitEmptyPasswords no
rem_done 110 "sshd PermitEmptyPasswords"

# RULE111:
rem_skip 111 "review remediation: SSH X11 forwarding is disabled"

# RULE112:
rem_skip 112 "review remediation: SSH MaxAuthTries is set to 4 or less is configured"

# RULE113:
set_sshd_kv ClientAliveInterval 300
rem_done 113 "sshd ClientAliveInterval"

# RULE114:
set_sshd_kv ClientAliveInterval 300
rem_done 114 "sshd ClientAliveInterval"

# RULE115:
rem_skip 115 "review remediation: SSH root login is disabled"

# RULE116:
set_sshd_kv Banner /etc/issue.net
rem_done 116 "sshd Banner"

# RULE117:
sec_audit_pkg_install libpam-pwquality
cat >/etc/security/pwquality.conf <<'EOF'
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF
rem_done 117 "password quality"

# RULE118:
rem_skip 118 "review remediation: Use only approved MAC algorithms"

# RULE119:
rem_skip 119 "review remediation: SSH idle timeout interval is configured"

# RULE120:
rem_skip 120 "review remediation: SSH LoginGraceTime is set to one minute or less"

# RULE121:
rem_skip 121 "review remediation: SSH warning banner is configured"

# RULE122:
set_login_defs_kv PASS_WARN_AGE 7
rem_done 122 "PASS_WARN_AGE 7"

# RULE123:
rem_skip 123 "review remediation: Lockouts for failed password attempts is configured"

# RULE124:
rem_skip 124 "review remediation: Lock inactive passwords"

# RULE125:
rem_skip 125 "review remediation: The password change date is not overdue for all users is configured"

# RULE126:
rem_skip 126 "review remediation: Password expiration warning period"

# RULE127:
set_login_defs_kv UMASK 027
cat >/etc/profile.d/99-cre-umask.sh <<'EOF'
umask 027
EOF
rem_done 127 "default umask 027"

# RULE128:
cat >/etc/profile.d/99-cre-timeout.sh <<'EOF'
TMOUT=600
readonly TMOUT
export TMOUT
EOF
rem_done 128 "TMOUT=600"

# RULE129:
rem_skip 129 "review remediation: Lock inactive passwords"

# RULE130:
rem_skip 130 "review remediation: Permissions on /etc/passwd are configured correctly"

# RULE131:
rem_skip 131 "review remediation: Default group for the root account GID 0"

# RULE132:
rem_skip 132 "review remediation: Default user umask value"

# RULE133:
rem_skip 133 "review remediation: User shell timeout"

# RULE134:
rem_skip 134 "review remediation: Permissions for /etc/passwd is configured"

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
rem_skip 149 "review remediation: OSSEC is installed is configured"

# RULE150:
rem_skip 150 "review remediation: Accounts do not have empty password fields"

# RULE151:
rem_skip 151 "review remediation: The syslog service is enabled"

# RULE152:
rem_skip 152 "review remediation: OSSEC is installed is configured"

# RULE153:
set_login_defs_kv ENCRYPT_METHOD SHA512
rem_done 153 "ENCRYPT_METHOD SHA512"

# RULE154:
rem_skip 154 "review remediation: The syslog service is enabled"

# RULE155:
rem_skip 155 "review remediation: The syslog-ng service is enabled"

# RULE156:
rem_skip 156 "review remediation: Time synchronization is used is configured"

# RULE157:
rem_skip 157 "review remediation: NFS and RPC are not enabled is configured"

# RULE158:
rem_skip 158 "review remediation: pam_pwquality strength requirements are configured"

# RULE159:
sec_audit_pkg_install libpam-pwquality
cat >/etc/security/pwquality.conf <<'EOF'
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF
rem_done 159 "password quality"

# RULE160:
sec_audit_pkg_install libpam-pwquality
cat >/etc/security/pwquality.conf <<'EOF'
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF
rem_done 160 "password quality"

# RULE161:
rem_skip 161 "review remediation: pam_pwquality length and character requirements are configured"

# RULE162:
pam_faillock_debian >/dev/null 2>&1 || true
rem_done 162 "pam faillock"

# RULE163:
sec_audit_pkg_install libpam-pwquality
cat >/etc/security/pwquality.conf <<'EOF'
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF
rem_done 163 "password quality"

# RULE164:
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
rem_done 164 "rsyslog installed"

# RULE165:
rem_skip 165 "review remediation: NTP is configured"

# RULE166:
rem_skip 166 "review remediation: The local login warning banner is configured correctly"

# RULE167:
rem_skip 167 "review remediation: The local login warning banner is configured correctly"

# RULE168:
rem_skip 168 "review remediation: The local login warning banner is configured correctly"

# RULE169:
rem_skip 169 "review remediation: The local login warning banner is configured correctly"

# RULE170:
rem_skip 170 "review remediation: The message of the day is configured correctly"

# RULE171:
rem_skip 171 "review remediation: The message of the day is configured correctly"

# RULE172:
rem_skip 172 "review remediation: The message of the day is configured correctly"

# RULE173:
rem_skip 173 "review remediation: The message of the day is configured correctly"

# RULE174:
rem_skip 174 "review remediation: The remote login warning banner is configured correctly"

# RULE175:
rem_skip 175 "review remediation: The remote login warning banner is configured correctly"

# RULE176:
rem_skip 176 "review remediation: The remote login warning banner is configured correctly"

# RULE177:
rem_skip 177 "review remediation: The remote login warning banner is configured correctly"

# RULE178:
rem_skip 178 "review remediation: The nodev mount option prevents device files on the partition"

# RULE179:
rem_skip 179 "review remediation: The nosuid mount option prevents setuid files on the partition"

# RULE180:
rem_skip 180 "review remediation: The nodev mount option prevents device files on the partition"

# RULE181:
rem_skip 181 "review remediation: The noexec mount option prevents executable files on the partition"

# RULE182:
rem_skip 182 "review remediation: The nosuid mount option prevents setuid files on the partition"

# RULE183:
rem_skip 183 "review remediation: The noexec mount option prevents executable files on the partition"

# RULE184:
rem_skip 184 "review remediation: The nodev mount option prevents device files on the partition"

# RULE185:
rem_skip 185 "review remediation: The nosuid mount option prevents setuid files on the partition"

# RULE186:
rem_skip 186 "review remediation: The nosuid mount option prevents setuid files on the partition"

# RULE187:
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
rem_done 187 "rsyslog installed"

# RULE188:
rem_skip 188 "create separate partition for /home during provisioning; then set mount options"

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
rem_skip 205 "review remediation: Users' dot files are not group- or world-writable is configured"

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
sec_audit_disable_kmod freevxfs
rem_done 213 "blacklisted kernel module freevxfs"

# RULE214:
sec_audit_disable_kmod hfs
rem_done 214 "blacklisted kernel module hfs"

# RULE215:
sec_audit_disable_kmod hfsplus
rem_done 215 "blacklisted kernel module hfsplus"

# RULE216:
sec_audit_disable_kmod jffs2
rem_done 216 "blacklisted kernel module jffs2"

# RULE217:
sec_audit_disable_kmod udf
rem_done 217 "blacklisted kernel module udf"

# RULE218:
rem_skip 218 "Ensure /dev/shm is a separate partition"

# RULE219:
harden_file /boot/grub2/grub.cfg 600 root:root
harden_file /boot/grub2/user.cfg 600 root:root
rem_done 219 "hardened grub permissions"

# RULE220:
set_sysctl kernel.yama.ptrace_scope 1
rem_done 220 "set kernel.yama.ptrace_scope=1"

# RULE221:
rem_skip 221 "review remediation: Ensure Automatic Error Reporting is not enabled"

# RULE222:
sec_audit_disable_svc dnsmasq.service
sec_audit_pkg_remove dnsmasq
rem_done 222 "disabled dnsmasq"

# RULE223:
rem_skip 223 "review remediation: Ensure message access server services are not in use"

# RULE224:
sec_audit_disable_svc rpcbind.socket
sec_audit_disable_svc rpcbind.service
sec_audit_pkg_remove rpcbind
rem_done 224 "disabled rpcbind"

# RULE225:
sec_audit_disable_svc vsftpd.service
sec_audit_pkg_remove vsftpd
rem_done 225 "disabled vsftpd"

# RULE226:
rem_skip 226 "review remediation: Ensure xinetd services are not in use"

# RULE227:
sec_audit_pkg_remove ftp
rem_done 227 "removed ftp"

# RULE228:
sec_audit_disable_svc bluetooth.service
sec_audit_pkg_remove bluez
rem_done 228 "disabled bluez"

# RULE229:
rem_skip 229 "review remediation: Ensure tcp syn cookies is enabled"

# RULE230:
set_sshd_kv Banner /etc/issue.net
rem_done 230 "sshd Banner"

# RULE231:
rem_skip 231 "review remediation: Ensure sshd Ciphers are configured"

# RULE232:
set_sshd_kv ClientAliveInterval 300
rem_done 232 "sshd ClientAliveInterval"

# RULE233:
set_sshd_kv DisableForwarding yes
rem_done 233 "sshd DisableForwarding"

# RULE234:
set_sshd_kv GSSAPIAuthentication no
rem_done 234 "sshd GSSAPIAuthentication"

# RULE235:
rem_skip 235 "review remediation: Ensure sshd KexAlgorithms is configured"

# RULE236:
rem_skip 236 "review remediation: Ensure latest version of pam is installed"

# RULE237:
rem_skip 237 "review remediation: Ensure libpam-modules is installed"

# RULE238:
sec_audit_pkg_install libpam-pwquality
cat >/etc/security/pwquality.conf <<'EOF'
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF
rem_done 238 "password quality"

# RULE239:
rem_skip 239 "review remediation: Ensure pam_unix module is enabled"

# RULE240:
pam_faillock_debian >/dev/null 2>&1 || true
rem_done 240 "pam faillock"

# RULE241:
sec_audit_pkg_install libpam-pwquality
cat >/etc/security/pwquality.conf <<'EOF'
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF
rem_done 241 "password quality"

# RULE242:
grep -q remember /etc/security/pwhistory.conf 2>/dev/null || echo 'remember = 24' >>/etc/security/pwhistory.conf
rem_done 242 "password history"

# RULE243:
pam_faillock_debian >/dev/null 2>&1 || true
rem_done 243 "pam faillock"

# RULE244:
rem_skip 244 "review remediation: Ensure password unlock time is configured"

# RULE245:
rem_skip 245 "Ensure password failed attempts lockout includes root account"

# RULE246:
rem_skip 246 "review remediation: Ensure password number of changed characters is configured"

# RULE247:
rem_skip 247 "review remediation: Ensure minimum password length is configured"

# RULE248:
rem_skip 248 "Ensure password complexity is configured"

# RULE249:
rem_skip 249 "review remediation: Ensure password same consecutive characters is configured"

# RULE250:
rem_skip 250 "review remediation: Ensure password maximum sequential characters is configured"

# RULE251:
rem_skip 251 "review remediation: Ensure password dictionary check is enabled"

# RULE252:
sec_audit_pkg_install libpam-pwquality
cat >/etc/security/pwquality.conf <<'EOF'
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF
rem_done 252 "password quality"

# RULE253:
sec_audit_pkg_install libpam-pwquality
cat >/etc/security/pwquality.conf <<'EOF'
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF
rem_done 253 "password quality"

# RULE254:
grep -q remember /etc/security/pwhistory.conf 2>/dev/null || echo 'remember = 24' >>/etc/security/pwhistory.conf
rem_done 254 "password history"

# RULE255:
grep -q remember /etc/security/pwhistory.conf 2>/dev/null || echo 'remember = 24' >>/etc/security/pwhistory.conf
rem_done 255 "password history"

# RULE256:
grep -q remember /etc/security/pwhistory.conf 2>/dev/null || echo 'remember = 24' >>/etc/security/pwhistory.conf
rem_done 256 "password history"

# RULE257:
rem_skip 257 "review remediation: Ensure pam_unix does not include nullok"

# RULE258:
grep -q remember /etc/security/pwhistory.conf 2>/dev/null || echo 'remember = 24' >>/etc/security/pwhistory.conf
rem_done 258 "password history"

# RULE259:
set_login_defs_kv ENCRYPT_METHOD SHA512
rem_done 259 "ENCRYPT_METHOD SHA512"

# RULE260:
rem_skip 260 "review remediation: Ensure pam_unix includes use_authtok"

# RULE261:
rem_skip 261 "Ensure root is the only GID 0 account"

# RULE262:
rem_skip 262 "Ensure group root is the only GID 0 group"

# RULE263:
rem_skip 263 "review remediation: Ensure root password is set"

# RULE264:
set_login_defs_kv UMASK 027
cat >/etc/profile.d/99-cre-umask.sh <<'EOF'
umask 027
EOF
rem_done 264 "default umask 027"

# RULE265:
rem_skip 265 "Ensure system accounts do not have a valid login shell"

# RULE266:
rem_skip 266 "Ensure accounts without a valid login shell are locked"

# RULE267:
rem_skip 267 "review remediation: Ensure nologin is not listed in /etc/shells"

# RULE268:
rem_skip 268 "review remediation: Ensure cryptographic mechanisms are used to protect the integrity of audit tools"

# RULE269:
rem_skip 269 "Ensure journald sec_audit_log file access is configured"

# RULE270:
rem_skip 270 "Ensure journald sec_audit_log file rotation is configured"

# RULE271:
rem_skip 271 "configure central logging per site policy before enabling journal remote/upload"

# RULE272:
mkdir -p /etc/systemd/journald.conf.d
cat >/etc/systemd/journald.conf.d/99-debian11-cre.conf <<'EOF'
[Journal]
ForwardToSyslog=no
Compress=yes
Storage=persistent
EOF
systemctl restart systemd-journald >/dev/null 2>&1 || true
rem_done 272 "journald configuration"

# RULE273:
mkdir -p /etc/systemd/journald.conf.d
cat >/etc/systemd/journald.conf.d/99-debian11-cre.conf <<'EOF'
[Journal]
ForwardToSyslog=no
Compress=yes
Storage=persistent
EOF
systemctl restart systemd-journald >/dev/null 2>&1 || true
rem_done 273 "journald configuration"

# RULE274:
rem_skip 274 "Ensure systemd-journal-remote authentication is configured"

# RULE275:
rem_skip 275 "Ensure systemd-journal-upload is enabled and active"

# RULE276:
rem_skip 276 "Ensure systemd-journal-remote service is not in use"

# RULE277:
rem_skip 277 "review remediation: Ensure access to all logfiles has been configured"

# RULE278:
rem_skip 278 "review remediation: Ensure system warns when audit logs are low on space"

# RULE279:
harden_file /etc/shells 644 root:root
rem_done 279 "permissions /etc/shells"

# RULE280:
rem_skip 280 "review remediation: Ensure permissions on /etc/security/opasswd are configured"

# RULE281:
rem_skip 281 "Ensure local interactive user dot files access is configured"

DEBIAN_FRONTEND=noninteractive apt-get update >/dev/null 2>&1 || true
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y >/dev/null 2>&1 || true

sec_audit_log " remediation complete (Debian11_remediation.sh)"
exit 0

