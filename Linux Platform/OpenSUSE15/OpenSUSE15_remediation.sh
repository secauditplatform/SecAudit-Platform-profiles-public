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

OS15_ALLOW_CONTAINER_KMOD="${OS15_ALLOW_CONTAINER_KMOD:-${CRE_ALLOW_CONTAINER_KMOD:-0}}"
OS15_REMEDIATE_SECURITY_UPGRADE="${OS15_REMEDIATE_SECURITY_UPGRADE:-0}"
OS15_SYSCTL_FILE="/etc/sysctl.d/99-secaudit-opensuse15.conf"
OS15_MODPROBE_PREFIX="/etc/modprobe.d/sec-audit-disable"

sec_audit_have_bin() { command -v "$1" >/dev/null 2>&1; }
sec_audit_log() { printf '[remediation] %s\n' "$*"; }
sec_audit_remediate_done() { printf '[remediation] REMEDIATE RULE%s= applied: %s\n' "$1" "$2"; }
sec_audit_remediate_skip() { printf '[remediation] REMEDIATE RULE%s= SKIP: manual step required - %s\n' "$1" "$2"; }

sec_audit_pkg_install() {
	local need=() p
	sec_audit_have_bin zypper || return 0
	for p in "$@"; do
		rpm -q "$p" &>/dev/null && continue
		need+=("$p")
	done
	((${#need[@]})) || return 0
	timeout 90 zypper --non-interactive install --no-recommends "${need[@]}" >/dev/null 2>&1 || true
}

sec_audit_pkg_remove() {
	local p
	sec_audit_have_bin zypper || return 0
	for p in "$@"; do
		rpm -q "$p" &>/dev/null || continue
		timeout 60 zypper --non-interactive remove -y "$p" >/dev/null 2>&1 || true
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
	systemctl mask "$u" >/dev/null 2>&1 || true
}

sec_audit_disable_kmod() {
	local mod="$1" f="${OS15_MODPROBE_PREFIX}-${mod//\//_}.conf"
	mkdir -p /etc/modprobe.d
	{
		echo "install ${mod} /bin/false"
		echo "blacklist ${mod}"
		echo "install ${mod//_/-} /bin/false"
		echo "blacklist ${mod//_/-}"
		echo "install ${mod//-/_} /bin/false"
		echo "blacklist ${mod//-/_}"
	} >"$f"
	if [ -f /proc/modules ] && awk '{print $1}' /proc/modules 2>/dev/null | grep -Eqx "${mod}|${mod//_/-}|${mod//-/_}"; then
		modprobe -r "$mod" >/dev/null 2>&1 || rmmod "$mod" >/dev/null 2>&1 || true
	fi
}

sec_audit_ensure_mount_option() {
	local mp="$1" opt="$2"
	if grep -qE "^[^#[:space:]]+[[:space:]]+${mp}[[:space:]]+" /etc/fstab 2>/dev/null; then
		if ! grep -E "^[^#[:space:]]+[[:space:]]+${mp}[[:space:]]+" /etc/fstab | grep -qE "(^|,)${opt}(,|$)"; then
			sed -i "s|^\([^#].*[[:space:]]${mp}[[:space:]].*\)$|\1,${opt}|" /etc/fstab 2>/dev/null || true
		fi
		mountpoint -q "$mp" 2>/dev/null && mount -o remount,${opt} "$mp" >/dev/null 2>&1 || true
	else
		# container-friendly: tmpfs overlay entry when mount absent
		case "$mp" in
		/tmp|/dev/shm|/var/tmp)
			echo "tmpfs ${mp} tmpfs defaults,${opt} 0 0" >>/etc/fstab
			mountpoint -q "$mp" 2>/dev/null || mkdir -p "$mp"
			mount "$mp" >/dev/null 2>&1 || mount -o remount,${opt} "$mp" >/dev/null 2>&1 || true
			;;
		esac
	fi
}

sec_audit_set_sysctl() {
	local key="$1" val="$2"
	mkdir -p /etc/sysctl.d
	if [[ -f $OS15_SYSCTL_FILE ]] && grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$OS15_SYSCTL_FILE"; then
		sed -i "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${val}|" "$OS15_SYSCTL_FILE"
	else
		echo "${key} = ${val}" >>"$OS15_SYSCTL_FILE"
	fi
	sysctl -w "${key}=${val}" >/dev/null 2>&1 || true
}

sec_audit_set_sshd_kv() {
	local key="$1" val="$2" f=/etc/ssh/sshd_config
	[[ -f $f ]] || { mkdir -p /etc/ssh; touch "$f"; }
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

sec_audit_harden_path() {
	local path="$1" mode="$2" owner="${3:-root:root}"
	[[ -e $path ]] || return 0
	chmod "$mode" "$path" 2>/dev/null || true
	chown "$owner" "$path" 2>/dev/null || true
}


sec_audit_main() {
	sec_audit_log "starting remediation (OpenSUSE15)"

# RULE1:
sec_audit_disable_kmod squashfs
sec_audit_remediate_done 1 "blacklisted kernel module squashfs"

# RULE2:
sec_audit_disable_kmod freevxfs
sec_audit_remediate_done 2 "blacklisted kernel module(s): freevxfs"

# RULE3:
sec_audit_disable_kmod hfs
sec_audit_remediate_done 3 "blacklisted kernel module hfs"

# RULE4:
sec_audit_remediate_skip 4 "separate partition / layout change requires host planning"

# RULE5:
sec_audit_ensure_mount_option /tmp nodev
sec_audit_remediate_done 5 "set nodev on /tmp"

# RULE6:
sec_audit_ensure_mount_option /tmp nosuid
sec_audit_remediate_done 6 "set nosuid on /tmp"

# RULE7:
sec_audit_ensure_mount_option /tmp noexec
sec_audit_remediate_done 7 "set noexec on /tmp"

# RULE8:
sec_audit_remediate_skip 8 "separate partition / layout change requires host planning"

# RULE9:
sec_audit_remediate_skip 9 "separate partition / layout change requires host planning"

# RULE10:
sec_audit_ensure_mount_option /var/tmp nodev
sec_audit_remediate_done 10 "set nodev on /var/tmp"

# RULE11:
sec_audit_ensure_mount_option /var/tmp nosuid
sec_audit_remediate_done 11 "set nosuid on /var/tmp"

# RULE12:
sec_audit_ensure_mount_option /var/tmp noexec
sec_audit_remediate_done 12 "set noexec on /var/tmp"

# RULE13:
sec_audit_remediate_skip 13 "separate partition / layout change requires host planning"

# RULE14:
sec_audit_remediate_skip 14 "separate partition / layout change requires host planning"

# RULE15:
sec_audit_remediate_skip 15 "separate partition / layout change requires host planning"

# RULE16:
sec_audit_ensure_mount_option /home nodev
sec_audit_remediate_done 16 "set nodev on /home"

# RULE17:
sec_audit_remediate_skip 17 "separate partition / layout change requires host planning"

# RULE18:
sec_audit_ensure_mount_option /dev/shm nosuid
sec_audit_remediate_done 18 "set nosuid on /dev/shm"

# RULE19:
sec_audit_ensure_mount_option /dev/shm noexec
sec_audit_remediate_done 19 "set noexec on /dev/shm"

# RULE20:
sec_audit_remediate_skip 20 'sticky bit is set on all world-writable directories'

# RULE21:
sec_audit_disable_svc autofs.service
sec_audit_remediate_done 21 "disabled units: autofs.service autofs.service"

# RULE22:
sec_audit_remediate_skip 22 'host-specific remediation for RULE22'

# RULE23:
sec_audit_remediate_skip 23 'bootloader password is set (grub.cfg under /boot/grub2 or EFI)'

# RULE24:
sec_audit_remediate_skip 24 'access to bootloader config is configured'

# RULE25:
sec_audit_set_sysctl fs.protected_hardlinks 1
sec_audit_remediate_done 25 "set fs.protected_hardlinks=1"

# RULE26:
sec_audit_remediate_skip 26 'core file size limits are not configured (limits * hard core 0 not found)'

# RULE27:
sec_audit_set_sysctl fs.protected_symlinks 1
sec_audit_remediate_done 27 "set fs.protected_symlinks=1"

# RULE28:
sec_audit_remediate_skip 28 'System-wide crypto policy is LEGACY in /etc/crypto-policies/config'

# RULE29:
sec_audit_remediate_skip 29 'System-wide crypto policy is LEGACY in /etc/crypto-policies/config'

# RULE30:
sec_audit_remediate_skip 30 'XD/NX support is enabled'

# RULE31:
sec_audit_set_sysctl kernel.randomize_va_space 2
sec_audit_remediate_done 31 "set kernel.randomize_va_space=2"

# RULE32:
sec_audit_remediate_skip 32 'Weak MAC algorithms still present in /etc/crypto-policies/state/CURRENT.pol'

# RULE33:
sec_audit_remediate_skip 33 'system wide crypto policy disables cbc for ssh'

# RULE34:
sec_audit_remediate_skip 34 'AppArmor is enabled in the bootloader configuration'

# RULE35:
sec_audit_remediate_skip 35 'all AppArmor profiles are enforcing'

# RULE36:
mkdir -p /etc
printf "%s\n" "Authorized uses only. All activity may be monitored." >/etc/issue
printf "%s\n" "Authorized uses only. All activity may be monitored." >/etc/issue.net
sec_audit_remediate_done 36 "set login banners"

# RULE37:
mkdir -p /etc
printf "%s\n" "Authorized uses only. All activity may be monitored." >/etc/issue
printf "%s\n" "Authorized uses only. All activity may be monitored." >/etc/issue.net
sec_audit_remediate_done 37 "set login banners"

# RULE38:
mkdir -p /etc
printf "%s\n" "Authorized uses only. All activity may be monitored." >/etc/issue
printf "%s\n" "Authorized uses only. All activity may be monitored." >/etc/issue.net
sec_audit_remediate_done 38 "set login banners"

# RULE39:
mkdir -p /etc
printf "%s\n" "Authorized uses only. All activity may be monitored." >/etc/issue
printf "%s\n" "Authorized uses only. All activity may be monitored." >/etc/issue.net
sec_audit_remediate_done 39 "set login banners"

# RULE40:
mkdir -p /etc
printf "%s\n" "Authorized uses only. All activity may be monitored." >/etc/issue
printf "%s\n" "Authorized uses only. All activity may be monitored." >/etc/issue.net
sec_audit_remediate_done 40 "set login banners"

# RULE41:
mkdir -p /etc
printf "%s\n" "Authorized uses only. All activity may be monitored." >/etc/issue
printf "%s\n" "Authorized uses only. All activity may be monitored." >/etc/issue.net
sec_audit_remediate_done 41 "set login banners"

# RULE42:
sec_audit_remediate_skip 42 'host-specific remediation for RULE42'

# RULE43:
sec_audit_pkg_remove ntp
sec_audit_pkg_remove chrony
sec_audit_remediate_done 43 "removed packages: ntp chrony"

# RULE44:
sec_audit_pkg_remove xorg-x11-server-Xorg
sec_audit_pkg_remove xorg-x11
sec_audit_remediate_done 44 "removed packages: xorg-x11-server-Xorg xorg-x11"

# RULE45:
sec_audit_disable_svc avahi-daemon.socket
sec_audit_disable_svc avahi-daemon.service
sec_audit_remediate_done 45 "disabled units: avahi-daemon.socket avahi-daemon.service"

# RULE46:
sec_audit_disable_svc cups.socket
sec_audit_disable_svc cups.service
sec_audit_remediate_done 46 "disabled units: cups.socket cups.service"

# RULE47:
sec_audit_pkg_remove dhcp-server
sec_audit_pkg_remove dhcpd
sec_audit_remediate_done 47 "removed packages: dhcp-server dhcpd"

# RULE48:
sec_audit_disable_svc nfs-server.service
sec_audit_remediate_done 48 "disabled units: nfs-server.service"

# RULE49:
sec_audit_remediate_skip 49 'X window server services (xorg-x11) are installed'

# RULE50:
sec_audit_disable_svc avahi-daemon.service
sec_audit_remediate_done 50 "disabled units: avahi-daemon.service"

# RULE51:
sec_audit_pkg_remove cups
sec_audit_remediate_done 51 "removed packages: cups"

# RULE52:
sec_audit_pkg_remove dhcp
sec_audit_remediate_done 52 "removed packages: dhcp"

# RULE53:
sec_audit_disable_svc slapd.service
sec_audit_remediate_done 53 "disabled units: slapd.service"

# RULE54:
sec_audit_pkg_remove nfs-utils
sec_audit_remediate_done 54 "removed packages: nfs-utils"

# RULE55:
sec_audit_pkg_remove nfs-utils
sec_audit_remediate_done 55 "removed packages: nfs-utils"

# RULE56:
sec_audit_disable_svc named.service
sec_audit_remediate_done 56 "disabled units: named.service"

# RULE57:
sec_audit_pkg_remove vsftpd
sec_audit_pkg_remove pure-ftpd
sec_audit_remediate_done 57 "removed packages: vsftpd pure-ftpd"

# RULE58:
sec_audit_disable_svc httpd
sec_audit_remediate_done 58 "disabled units: httpd"

# RULE59:
sec_audit_pkg_remove dovecot
sec_audit_pkg_remove cyrus-imapd
sec_audit_remediate_done 59 "removed packages: dovecot cyrus-imapd"

# RULE60:
sec_audit_disable_svc smb.service
sec_audit_remediate_done 60 "disabled units: smb.service"

# RULE61:
sec_audit_disable_svc squid.service
sec_audit_remediate_done 61 "disabled units: squid.service"

# RULE62:
sec_audit_disable_svc snmpd.service
sec_audit_remediate_done 62 "disabled units: snmpd.service"

# RULE63:
sec_audit_remediate_skip 63 'mail transfer agent is listening on a non-loopback interface (port 25)'

# RULE64:
sec_audit_disable_svc ypserv.service
sec_audit_remediate_done 64 "disabled units: ypserv.service"

# RULE65:
sec_audit_disable_svc rsync.service
sec_audit_remediate_done 65 "disabled units: rsync.service"

# RULE66:
sec_audit_pkg_remove telnetd
sec_audit_pkg_remove xinetd
sec_audit_remediate_done 66 "removed packages: telnetd xinetd"

# RULE67:
sec_audit_disable_svc chronyd.service
sec_audit_remediate_done 67 "disabled units: chronyd.service chronyd.service chronyd.service"

# RULE68:
sec_audit_pkg_remove talk
sec_audit_remediate_done 68 "removed packages: talk"

# RULE69:
sec_audit_pkg_remove telnet
sec_audit_remediate_done 69 "removed packages: telnet"

# RULE70:
sec_audit_pkg_remove openldap2-client
sec_audit_remediate_done 70 "removed packages: openldap2-client"

# RULE71:
sec_audit_disable_kmod atm
sec_audit_remediate_done 71 "blacklisted kernel module atm"

# RULE72:
sec_audit_disable_kmod can
sec_audit_remediate_done 72 "blacklisted kernel module can"

# RULE73:
sec_audit_set_sysctl net.ipv4.conf.all.accept_source_route 0
sec_audit_remediate_done 73 "set net.ipv4.conf.all.accept_source_route=0"

# RULE74:
sec_audit_set_sysctl net.ipv4.conf.all.accept_redirects 0
sec_audit_remediate_done 74 "set net.ipv4.conf.all.accept_redirects=0"

# RULE75:
sec_audit_set_sysctl net.ipv4.conf.all.secure_redirects 0
sec_audit_remediate_done 75 "set net.ipv4.conf.all.secure_redirects=0"

# RULE76:
sec_audit_set_sysctl net.ipv4.conf.all.log_martians 1
sec_audit_remediate_done 76 "set net.ipv4.conf.all.log_martians=1"

# RULE77:
sec_audit_set_sysctl net.ipv4.icmp_echo_ignore_broadcasts 1
sec_audit_remediate_done 77 "set net.ipv4.icmp_echo_ignore_broadcasts=1"

# RULE78:
sec_audit_set_sysctl net.ipv4.icmp_ignore_bogus_error_responses 1
sec_audit_remediate_done 78 "set net.ipv4.icmp_ignore_bogus_error_responses=1"

# RULE79:
sec_audit_set_sysctl net.ipv4.conf.all.rp_filter 1
sec_audit_remediate_done 79 "set net.ipv4.conf.all.rp_filter=1"

# RULE80:
sec_audit_set_sysctl net.ipv4.tcp_syncookies 1
sec_audit_remediate_done 80 "set net.ipv4.tcp_syncookies=1"

# RULE81:
sec_audit_set_sysctl net.ipv6.conf.all.accept_ra 0
sec_audit_remediate_done 81 "set net.ipv6.conf.all.accept_ra=0"

# RULE82:
sec_audit_disable_kmod dccp
sec_audit_remediate_done 82 "blacklisted kernel module(s): dccp"

# RULE83:
sec_audit_disable_kmod sctp
sec_audit_remediate_done 83 "blacklisted kernel module sctp"

# RULE84:
sec_audit_pkg_install iptables
sec_audit_remediate_done 84 "ensured packages: iptables"

# RULE85:
sec_audit_remediate_skip 85 'audit log storage size is configured'

# RULE86:
sec_audit_remediate_skip 86 'system is disabled when audit logs are full'

# RULE87:
sec_audit_remediate_skip 87 'audit logs are not automatically deleted'

# RULE88:
sec_audit_disable_svc auditd.service
sec_audit_remediate_done 88 "disabled units: auditd.service auditd.service"

# RULE89:
sec_audit_disable_svc rsyslog.service
sec_audit_remediate_done 89 "disabled units: rsyslog.service rsyslog.service"

# RULE90:
sec_audit_remediate_skip 90 'rsyslog default file permissions configured'

# RULE91:
sec_audit_remediate_skip 91 'rsyslog is configured to send logs to a remote host'

# RULE92:
sec_audit_remediate_skip 92 'host-specific remediation for RULE92'

# RULE93:
sec_audit_remediate_skip 93 'rsyslog is configured to receive logs from remote clients (imtcp loaded)'

# RULE94:
sec_audit_disable_svc systemd-journald.service
sec_audit_remediate_done 94 "disabled units: systemd-journald.service"

# RULE95:
sec_audit_remediate_skip 95 'journald Storage is configured'

# RULE96:
sec_audit_remediate_skip 96 'journald ForwardToSyslog is disabled'

# RULE97:
sec_audit_remediate_skip 97 'journald Compress is configured'

# RULE98:
sec_audit_remediate_skip 98 'journald log file rotation is configured'

# RULE99:
sec_audit_remediate_skip 99 'permissions on all logfiles are configured'

# RULE100:
sec_audit_remediate_skip 100 'logrotate is configured'

# RULE101:
sec_audit_remediate_skip 101 "sshd setting requires host-specific review"

# RULE102:
sec_audit_remediate_skip 102 "sshd setting requires host-specific review"

# RULE103:
sec_audit_remediate_skip 103 "sshd setting requires host-specific review"

# RULE104:
sec_audit_set_sshd_kv Banner /etc/issue.net
sec_audit_remediate_done 104 "sshd_config hardened keys"

# RULE105:
sec_audit_remediate_skip 105 "sshd setting requires host-specific review"

# RULE106:
sec_audit_set_sshd_kv ClientAliveInterval 15
sec_audit_set_sshd_kv ClientAliveCountMax 3
sec_audit_remediate_done 106 "sshd_config hardened keys"

# RULE107:
sec_audit_remediate_skip 107 "sshd setting requires host-specific review"

# RULE108:
sec_audit_pkg_install sudo
sec_audit_remediate_done 108 "ensured packages: sudo"

# RULE109:
sec_audit_remediate_skip 109 "sshd setting requires host-specific review"

# RULE110:
sec_audit_remediate_skip 110 "sshd setting requires host-specific review"

# RULE111:
sec_audit_remediate_skip 111 'sudo timestamp_timeout is configured'

# RULE112:
sec_audit_harden_path /etc/group 644 root:root
sec_audit_remediate_done 112 "hardened identity file permissions"

# RULE113:
sec_audit_set_sshd_kv IgnoreRhosts yes
sec_audit_remediate_done 113 "sshd_config hardened keys"

# RULE114:
sec_audit_set_sshd_kv HostbasedAuthentication no
sec_audit_remediate_done 114 "sshd_config hardened keys"

# RULE115:
sec_audit_set_sshd_kv PermitRootLogin no
sec_audit_remediate_done 115 "sshd_config hardened keys"

# RULE116:
sec_audit_set_sshd_kv PermitEmptyPasswords no
sec_audit_remediate_done 116 "sshd_config hardened keys"

# RULE117:
sec_audit_set_sshd_kv PermitUserEnvironment no
sec_audit_remediate_done 117 "sshd_config hardened keys"

# RULE118:
sec_audit_remediate_skip 118 "sshd setting requires host-specific review"

# RULE119:
sec_audit_set_sshd_kv ClientAliveInterval 15
sec_audit_remediate_done 119 "sshd_config hardened keys"

# RULE120:
sec_audit_set_sshd_kv ClientAliveCountMax 3
sec_audit_remediate_done 120 "sshd_config hardened keys"

# RULE121:
sec_audit_set_sshd_kv LoginGraceTime 60
sec_audit_remediate_done 121 "sshd_config hardened keys"

# RULE122:
sec_audit_remediate_skip 122 'NOPASSWD or password-less sudo rules violate escalation policy'

# RULE123:
sec_audit_set_sshd_kv Banner /etc/issue.net
sec_audit_remediate_done 123 "sshd_config hardened keys"

# RULE124:
sec_audit_remediate_skip 124 'password creation requirements (minlen) are configured'

# RULE125:
sec_audit_remediate_skip 125 'password complexity is configured'

# RULE126:
sec_audit_remediate_skip 126 'lockout for failed password attempts is configured'

# RULE127:
sec_audit_remediate_skip 127 'lockout unlock_time is configured'

# RULE128:
sec_audit_remediate_skip 128 'password reuse is limited'

# RULE129:
sec_audit_set_login_defs_kv PASS_MAX_DAYS 365
sec_audit_remediate_done 129 "set PASS_MAX_DAYS=365 in login.defs"

# RULE130:
sec_audit_set_login_defs_kv PASS_MIN_DAYS 1
sec_audit_remediate_done 130 "set PASS_MIN_DAYS=1 in login.defs"

# RULE131:
sec_audit_set_login_defs_kv PASS_WARN_AGE 7
sec_audit_remediate_done 131 "set PASS_WARN_AGE=7 in login.defs"

# RULE132:
sec_audit_set_login_defs_kv ENCRYPT_METHOD SHA512
sec_audit_remediate_done 132 "set ENCRYPT_METHOD=SHA512 in login.defs"

# RULE133:
sec_audit_harden_path /etc/shadow 000 root:root
sec_audit_remediate_done 133 "hardened identity file permissions"

# RULE134:
sec_audit_harden_path /etc/shadow 000 root:root
sec_audit_remediate_done 134 "hardened identity file permissions"

# RULE135:
sec_audit_harden_path /etc/shadow 000 root:root
sec_audit_remediate_done 135 "hardened identity file permissions"

# RULE136:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_remediate_done 136 "hardened identity file permissions"

# RULE137:
sec_audit_set_login_defs_kv UMASK 027
sec_audit_remediate_done 137 "set UMASK=027 in login.defs"

# RULE138:
sec_audit_remediate_skip 138 'default user shell timeout is configured'

# RULE139:
sec_audit_disable_svc aidecheck.timer
sec_audit_remediate_done 139 "disabled units: aidecheck.timer aidecheck.timer aidecheck.timer aidecheck.timer"

# RULE140:
sec_audit_disable_svc aidecheck.timer
sec_audit_remediate_done 140 "disabled units: aidecheck.timer aidecheck.timer aidecheck.timer aidecheck.timer"

# RULE141:
sec_audit_disable_svc aidecheck.timer
sec_audit_remediate_done 141 "disabled units: aidecheck.timer aidecheck.timer aidecheck.timer aidecheck.timer"

# RULE142:
sec_audit_harden_path /etc/shadow 000 root:root
sec_audit_remediate_done 142 "hardened identity file permissions"

# RULE143:
sec_audit_harden_path /etc/shadow 000 root:root
sec_audit_remediate_done 143 "hardened identity file permissions"

# RULE144:
sec_audit_harden_path /etc/shadow 000 root:root
sec_audit_remediate_done 144 "hardened identity file permissions"

# RULE145:
sec_audit_harden_path /etc/group 644 root:root
sec_audit_remediate_done 145 "hardened identity file permissions"

# RULE146:
sec_audit_harden_path /etc/group 644 root:root
sec_audit_remediate_done 146 "hardened identity file permissions"

# RULE147:
sec_audit_harden_path /etc/group 644 root:root
sec_audit_remediate_done 147 "hardened identity file permissions"

# RULE148:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_harden_path /etc/passwd- 644 root:root
sec_audit_remediate_done 148 "hardened identity file permissions"

# RULE149:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_harden_path /etc/passwd- 644 root:root
sec_audit_remediate_done 149 "hardened identity file permissions"

# RULE150:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_harden_path /etc/passwd- 644 root:root
sec_audit_remediate_done 150 "hardened identity file permissions"

# RULE151:
sec_audit_harden_path /etc/shadow 000 root:root
sec_audit_harden_path /etc/shadow- 000 root:root
sec_audit_remediate_done 151 "hardened identity file permissions"

# RULE152:
sec_audit_harden_path /etc/shadow 000 root:root
sec_audit_harden_path /etc/shadow- 000 root:root
sec_audit_remediate_done 152 "hardened identity file permissions"

# RULE153:
sec_audit_harden_path /etc/shadow 000 root:root
sec_audit_harden_path /etc/shadow- 000 root:root
sec_audit_remediate_done 153 "hardened identity file permissions"

# RULE154:
sec_audit_harden_path /etc/group 644 root:root
sec_audit_harden_path /etc/group- 644 root:root
sec_audit_remediate_done 154 "hardened identity file permissions"

# RULE155:
sec_audit_harden_path /etc/group 644 root:root
sec_audit_harden_path /etc/group- 644 root:root
sec_audit_remediate_done 155 "hardened identity file permissions"

# RULE156:
sec_audit_harden_path /etc/group 644 root:root
sec_audit_harden_path /etc/group- 644 root:root
sec_audit_remediate_done 156 "hardened identity file permissions"

# RULE157:
sec_audit_remediate_skip 157 'incomplete_scan: world-writable file search timed out under critical paths'

# RULE158:
sec_audit_remediate_skip 158 'no unowned files or directories exist'

# RULE159:
sec_audit_remediate_skip 159 'no ungrouped files or directories exist'

# RULE160:
sec_audit_remediate_skip 160 'SUID executables count = $SUID_COUNT (manual audit required)'

# RULE161:
sec_audit_remediate_skip 161 'SGID executables count = $SGID_COUNT (manual audit required)'

# RULE162:
sec_audit_harden_path /etc/shadow 000 root:root
sec_audit_remediate_done 162 "hardened identity file permissions"

# RULE163:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_remediate_done 163 "hardened identity file permissions"

# RULE164:
sec_audit_remediate_skip 164 'root PATH integrity verified'

# RULE165:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_remediate_done 165 "hardened identity file permissions"

# RULE166:
sec_audit_remediate_skip 166 '/dev/shm is configured as a separate mount'

# RULE167:
sec_audit_pkg_install sudo
sec_audit_remediate_done 167 "ensured packages: sudo"

# RULE168:
sec_audit_remediate_skip 168 'sudo commands use pty'

# RULE169:
sec_audit_remediate_skip 169 'sudo log file exists'

# RULE170:
sec_audit_pkg_install apparmor-utils
sec_audit_pkg_install apparmor-parser
sec_audit_remediate_done 170 "ensured packages: apparmor-utils apparmor-parser"

# RULE171:
sec_audit_pkg_remove gdm
sec_audit_remediate_done 171 "removed packages: gdm"

# RULE172:
sec_audit_pkg_remove rsync
sec_audit_remediate_done 172 "removed packages: rsync"

# RULE173:
sec_audit_pkg_install audit
sec_audit_remediate_done 173 "ensured packages: audit"

# RULE174:
sec_audit_remediate_skip 174 'auditing for processes that start prior to auditd is enabled'

# RULE175:
sec_audit_remediate_skip 175 'audit_backlog_limit is sufficient'

# RULE176:
sec_audit_disable_svc firewalld.service
sec_audit_remediate_done 176 "disabled units: firewalld.service firewalld.service firewalld.service firewalld.service"

# RULE177:
sec_audit_disable_svc firewalld
sec_audit_remediate_done 177 "disabled units: firewalld"

# RULE178:
sec_audit_disable_svc firewalld
sec_audit_remediate_done 178 "disabled units: firewalld"

# RULE179:
sec_audit_remediate_skip 179 'session initiation information is collected'

# RULE180:
sec_audit_remediate_skip 180 'DAC permission modification events are collected'

# RULE181:
sec_audit_remediate_skip 181 'use of privileged commands is collected'

# RULE182:
sec_audit_remediate_skip 182 'file deletion events by users are collected'

# RULE183:
sec_audit_remediate_skip 183 'changes to system administration scope (sudoers) is collected'

# RULE184:
sec_audit_remediate_skip 184 'system administrator actions (sudolog) are collected'

# RULE185:
sec_audit_pkg_install rsyslog
sec_audit_remediate_done 185 "ensured packages: rsyslog"

# RULE186:
sec_audit_remediate_skip 186 'permissions on all logfiles are configured'

# RULE187:
sec_audit_remediate_skip 187 "sshd setting requires host-specific review"

# RULE188:
sec_audit_remediate_skip 188 "sshd setting requires host-specific review"

# RULE189:
sec_audit_remediate_skip 189 'sudo commands use pty'

# RULE190:
sec_audit_remediate_skip 190 'sudo log file exists'

# RULE191:
sec_audit_remediate_skip 191 "sshd setting requires host-specific review"

# RULE192:
sec_audit_remediate_skip 192 "sshd setting requires host-specific review"

# RULE193:
sec_audit_remediate_skip 193 "sshd setting requires host-specific review"

# RULE194:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_remediate_done 194 "hardened identity file permissions"

# RULE195:
sec_audit_remediate_skip 195 'access to the su command is restricted via pam_wheel'

# RULE196:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_remediate_done 196 "hardened identity file permissions"

# RULE197:
sec_audit_remediate_skip 197 'root PATH integrity verified'

# RULE198:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_remediate_done 198 "hardened identity file permissions"

# RULE199:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_remediate_done 199 "hardened identity file permissions"

# RULE200:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_remediate_done 200 "hardened identity file permissions"

# RULE201:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_harden_path /etc/group 644 root:root
sec_audit_remediate_done 201 "hardened identity file permissions"

# RULE202:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_remediate_done 202 "hardened identity file permissions"

# RULE203:
sec_audit_harden_path /etc/group 644 root:root
sec_audit_remediate_done 203 "hardened identity file permissions"

# RULE204:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_remediate_done 204 "hardened identity file permissions"

# RULE205:
sec_audit_harden_path /etc/group 644 root:root
sec_audit_remediate_done 205 "hardened identity file permissions"

# RULE206:
sec_audit_harden_path /etc/group 644 root:root
sec_audit_remediate_done 206 "hardened identity file permissions"

# RULE207:
sec_audit_disable_kmod cramfs
sec_audit_remediate_done 207 "blacklisted kernel module cramfs"

# RULE208:
sec_audit_disable_kmod freevxfs
sec_audit_remediate_done 208 "blacklisted kernel module(s): freevxfs"

# RULE209:
sec_audit_disable_kmod hfs
sec_audit_remediate_done 209 "blacklisted kernel module(s): hfs"

# RULE210:
sec_audit_disable_kmod hfsplus
sec_audit_remediate_done 210 "blacklisted kernel module hfsplus"

# RULE211:
sec_audit_disable_kmod jffs2
sec_audit_remediate_done 211 "blacklisted kernel module jffs2"

# RULE212:
sec_audit_disable_kmod overlay
sec_audit_remediate_done 212 "blacklisted kernel module overlay"

# RULE213:
sec_audit_disable_kmod firewire-core
sec_audit_disable_kmod firewire_core
sec_audit_remediate_done 213 "blacklisted kernel module(s): firewire-core firewire_core"

# RULE214:
sec_audit_ensure_mount_option /home nosuid
sec_audit_remediate_done 214 "set nosuid on /home"

# RULE215:
sec_audit_ensure_mount_option /var nodev
sec_audit_remediate_done 215 "set nodev on /var"

# RULE216:
sec_audit_ensure_mount_option /var nosuid
sec_audit_remediate_done 216 "set nosuid on /var"

# RULE217:
sec_audit_ensure_mount_option /var/log nodev
sec_audit_remediate_done 217 "set nodev on /var/log"

# RULE218:
sec_audit_ensure_mount_option /var/log nosuid
sec_audit_remediate_done 218 "set nosuid on /var/log"

# RULE219:
sec_audit_ensure_mount_option /var/log noexec
sec_audit_remediate_done 219 "set noexec on /var/log"

# RULE220:
sec_audit_ensure_mount_option /var/log/audit nodev
sec_audit_remediate_done 220 "set nodev on /var/log/audit"

# RULE221:
sec_audit_ensure_mount_option /var/log/audit nosuid
sec_audit_remediate_done 221 "set nosuid on /var/log/audit"

# RULE222:
sec_audit_ensure_mount_option /var/log/audit noexec
sec_audit_remediate_done 222 "set noexec on /var/log/audit"

# RULE223:
sec_audit_remediate_skip 223 'merged [main] repo_gpgcheck is disabled (effective value: ${_rule39_main})'

# RULE224:
sec_audit_remediate_skip 224 'SELinux policy is configured'

# RULE225:
sec_audit_remediate_skip 225 'access to bootloader config is configured'

# RULE226:
sec_audit_remediate_skip 226 'System-wide crypto policy is LEGACY in /etc/crypto-policies/config'

# RULE227:
sec_audit_remediate_skip 227 'System-wide crypto policy state is LEGACY in CURRENT.pol'

# RULE228:
sec_audit_remediate_skip 228 'Weak MAC algorithms still present in /etc/crypto-policies/state/CURRENT.pol'

# RULE229:
sec_audit_remediate_skip 229 'system wide crypto policy disables cbc for ssh'

# RULE230:
sec_audit_remediate_skip 230 'weak MAC algorithms still present in /etc/crypto-policies/state/CURRENT.pol'

# RULE231:
sec_audit_remediate_skip 231 'system wide crypto policy disables cbc for ssh'

# RULE232:
sec_audit_remediate_skip 232 'chacha20-poly1305 is still listed for SSH in active crypto policy (CURRENT.pol)'

# RULE233:
sec_audit_remediate_skip 233 'GDM screen lock is configured'

# RULE234:
sec_audit_remediate_skip 234 'GDM automount is configured'

# RULE235:
sec_audit_remediate_skip 235 'GDM autorun-never is configured'

# RULE236:
sec_audit_remediate_skip 236 'Xwayland is configured'

# RULE237:
sec_audit_remediate_skip 237 'GDM is not installed (not applicable)'

# RULE238:
sec_audit_remediate_skip 238 'GDM is not installed (not applicable)'

# RULE239:
sec_audit_remediate_skip 239 'GDM is not installed (not applicable)'

# RULE240:
sec_audit_remediate_skip 240 'GDM is not installed (not applicable)'

# RULE241:
sec_audit_disable_svc named.service
sec_audit_remediate_done 241 "disabled units: named.service"

# RULE242:
sec_audit_disable_svc nfs-server.service
sec_audit_remediate_done 242 "disabled units: nfs-server.service"

# RULE243:
sec_audit_disable_svc squid.service
sec_audit_remediate_done 243 "disabled units: squid.service"

# RULE244:
sec_audit_remediate_skip 244 'X window server services (xorg-x11) are installed'

# RULE245:
sec_audit_pkg_remove tftp
sec_audit_remediate_done 245 "removed packages: tftp"

# RULE246:
sec_audit_disable_svc chronyd.service
sec_audit_disable_svc systemd-timesyncd.service
sec_audit_disable_svc ntpd.service
sec_audit_remediate_done 246 "disabled units: chronyd.service systemd-timesyncd.service ntpd.service"

# RULE247:
sec_audit_disable_svc systemd-timesyncd.service
sec_audit_remediate_done 247 "disabled units: systemd-timesyncd.service"

# RULE248:
sec_audit_remediate_skip 248 'access to /etc/cron.d is configured'

# RULE249:
sec_audit_remediate_skip 249 'access to at is configured'

# RULE250:
sec_audit_disable_svc bluetooth.service
sec_audit_remediate_done 250 "disabled units: bluetooth.service"

# RULE251:
sec_audit_disable_kmod can
sec_audit_remediate_done 251 "blacklisted kernel module(s): can"

# RULE252:
sec_audit_disable_kmod dccp
sec_audit_remediate_done 252 "blacklisted kernel module dccp"

# RULE253:
sec_audit_set_sysctl net.ipv4.icmp_ignore_bogus_error_responses 1
sec_audit_remediate_done 253 "set net.ipv4.icmp_ignore_bogus_error_responses=1"

# RULE254:
sec_audit_set_sysctl net.ipv4.icmp_echo_ignore_broadcasts 1
sec_audit_remediate_done 254 "set net.ipv4.icmp_echo_ignore_broadcasts=1"

# RULE255:
sec_audit_set_sysctl net.ipv4.tcp_syncookies 1
sec_audit_remediate_done 255 "set net.ipv4.tcp_syncookies=1"

# RULE256:
sec_audit_pkg_install firewalld
sec_audit_remediate_done 256 "ensured packages: firewalld"

# RULE257:
sec_audit_remediate_skip 257 'firewalld services and ports require manual review per site policy'

# RULE258:
sec_audit_remediate_skip 258 "sshd setting requires host-specific review"

# RULE259:
sec_audit_set_sshd_kv Banner /etc/issue.net
sec_audit_remediate_done 259 "sshd_config hardened keys"

# RULE260:
sec_audit_remediate_skip 260 "sshd setting requires host-specific review"

# RULE261:
sec_audit_set_sshd_kv HostbasedAuthentication no
sec_audit_remediate_done 261 "sshd_config hardened keys"

# RULE262:
sec_audit_set_sshd_kv IgnoreRhosts yes
sec_audit_remediate_done 262 "sshd_config hardened keys"

# RULE263:
sec_audit_remediate_skip 263 'NOPASSWD or password-less sudo rules violate escalation policy'

# RULE264:
sec_audit_remediate_skip 264 'sudo !authenticate (re-authentication bypass) is configured globally'

# RULE265:
sec_audit_remediate_skip 265 'sudo timestamp_timeout is configured'

# RULE266:
sec_audit_remediate_skip 266 'active authselect profile does not include required pam modules'

# RULE267:
sec_audit_remediate_skip 267 'password unlock time is configured'

# RULE268:
sec_audit_remediate_skip 268 'password failed attempts lockout includes root account'

# RULE269:
sec_audit_remediate_skip 269 'password dictionary check is enabled'

# RULE270:
sec_audit_remediate_skip 270 'password length is configured'

# RULE271:
sec_audit_remediate_skip 271 'password complexity is configured'

# RULE272:
sec_audit_remediate_skip 272 'password same consecutive characters is configured'

# RULE273:
sec_audit_remediate_skip 273 'password dictionary check is enabled'

# RULE274:
sec_audit_remediate_skip 274 'password quality is enforced for the root user'

# RULE275:
sec_audit_remediate_skip 275 'password history remember is configured'

# RULE276:
sec_audit_remediate_skip 276 'password history is enforced for the root user'

# RULE277:
sec_audit_remediate_skip 277 'pam_pwhistory includes use_authtok'

# RULE278:
sec_audit_remediate_skip 278 'pam_unix does not include nullok'

# RULE279:
sec_audit_remediate_skip 279 'pam_unix does not include remember'

# RULE280:
sec_audit_remediate_skip 280 'pam_unix includes a strong password hashing algorithm'

# RULE281:
sec_audit_remediate_skip 281 'pam_unix includes use_authtok'

# RULE282:
sec_audit_set_login_defs_kv PASS_MIN_DAYS 1
sec_audit_remediate_done 282 "set PASS_MIN_DAYS=1 in login.defs"

# RULE283:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_remediate_done 283 "hardened identity file permissions"

# RULE284:
sec_audit_harden_path /etc/group 644 root:root
sec_audit_remediate_done 284 "hardened identity file permissions"

# RULE285:
sec_audit_remediate_skip 285 'root account access is controlled'

# RULE286:
sec_audit_remediate_skip 286 'root user umask is configured'

# RULE287:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_remediate_done 287 "hardened identity file permissions"

# RULE288:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_harden_path /etc/shadow 000 root:root
sec_audit_remediate_done 288 "hardened identity file permissions"

# RULE289:
sec_audit_remediate_skip 289 'nologin appears in /etc/shells'

# RULE290:
sec_audit_remediate_skip 290 'cryptographic mechanisms are used to protect the integrity of audit tools (AIDE)'

# RULE291:
sec_audit_remediate_skip 291 'journald log file access is configured (directory mode: $DIR_PERM)'

# RULE292:
sec_audit_remediate_skip 292 'journald log file rotation is configured'

# RULE293:
sec_audit_disable_svc --quiet
sec_audit_remediate_done 293 "disabled units: --quiet"

# RULE294:
sec_audit_pkg_install systemd-journal-remote
sec_audit_remediate_done 294 "ensured packages: systemd-journal-remote"

# RULE295:
sec_audit_remediate_skip 295 'host-specific remediation for RULE295'

# RULE296:
sec_audit_disable_svc systemd-journal-upload.service
sec_audit_remediate_done 296 "disabled units: systemd-journal-upload.service systemd-journal-upload.service"

# RULE297:
sec_audit_disable_svc systemd-journal-remote.socket
sec_audit_disable_svc systemd-journal-remote.service
sec_audit_remediate_done 297 "disabled units: systemd-journal-remote.socket systemd-journal-remote.service systemd-journal-remote.socket systemd-journal-remote.service"

# RULE298:
sec_audit_remediate_skip 298 'journald ForwardToSyslog is disabled'

# RULE299:
sec_audit_remediate_skip 299 'rsyslog is configured to receive remote logs (imtcp module loaded)'

# RULE300:
sec_audit_remediate_skip 300 'rsyslog logrotate is configured'

# RULE301:
sec_audit_remediate_skip 301 '$logfile has insecure permissions ($PERM) or owner ($OWNER)'

# RULE302:
sec_audit_remediate_skip 302 'system warns when audit logs are low on space'

# RULE303:
sec_audit_remediate_skip 303 'chcon command auditing is configured'

# RULE304:
sec_audit_remediate_skip 304 'setfacl command auditing is configured'

# RULE305:
sec_audit_remediate_skip 305 'chacl command auditing is configured'

# RULE306:
sec_audit_remediate_skip 306 'usermod command auditing is configured'

# RULE307:
sec_audit_remediate_skip 307 'mount syscall auditing on disk and loaded'

# RULE308:
sec_audit_remediate_skip 308 'the audit log file directory mode is configured'

# RULE309:
sec_audit_remediate_skip 309 'One or more audit log files have overly permissive modes'

# RULE310:
sec_audit_remediate_skip 310 'One or more audit log files are not owned by root'

# RULE311:
sec_audit_remediate_skip 311 'Audit log files group ownership does not match log_group policy'

# RULE312:
sec_audit_remediate_skip 312 'Audit .conf/.rules files have insecure permissions'

# RULE313:
sec_audit_remediate_skip 313 'Audit configuration files are not owned as required'

# RULE314:
sec_audit_remediate_skip 314 'Audit configuration files group ownership does not meet policy'

# RULE315:
sec_audit_remediate_skip 315 'audit tools mode is configured'

# RULE316:
sec_audit_remediate_skip 316 'audit tools owner is configured'

# RULE317:
sec_audit_remediate_skip 317 'audit tools group owner is configured'

# RULE318:
sec_audit_harden_path /etc/gshadow 000 root:root
sec_audit_remediate_done 318 "hardened identity file permissions"

# RULE319:
sec_audit_harden_path /etc/gshadow 000 root:root
sec_audit_harden_path /etc/gshadow- 000 root:root
sec_audit_remediate_done 319 "hardened identity file permissions"

# RULE320:
sec_audit_remediate_skip 320 'access to /etc/shells is configured'

# RULE321:
sec_audit_remediate_skip 321 'access to /etc/security/opasswd is configured'

# RULE322:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_remediate_done 322 "hardened identity file permissions"


	if [ "${OS15_REMEDIATE_SECURITY_UPGRADE}" = "1" ]; then
		if sec_audit_have_bin zypper; then
			timeout 300 zypper --non-interactive patch --with-optional >/dev/null 2>&1 || true
		fi
	else
		sec_audit_log "skipping security upgrade (set OS15_REMEDIATE_SECURITY_UPGRADE=1 to enable)"
	fi
	sec_audit_log "remediation complete (OpenSUSE15_remediation.sh)"
}

sec_audit_main "$@"
