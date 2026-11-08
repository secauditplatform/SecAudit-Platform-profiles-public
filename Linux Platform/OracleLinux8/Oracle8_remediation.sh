#!/bin/bash
# Full remediation for OracleLinux8 — generated from audit rule bodies (sec_audit_* style).

export LC_ALL=C

if [ -z "${BASH_VERSION:-}" ]; then
	if command -v bash >/dev/null 2>&1; then
		exec bash "$0" "$@"
	fi
	printf '%s\n' "ERROR: bash is required." >&2
	exit 1
fi

set +e

CRE_ALLOW_CONTAINER_KMOD="${CRE_ALLOW_CONTAINER_KMOD:-0}"
REMEDIATE_SECURITY_UPGRADE="${REMEDIATE_SECURITY_UPGRADE:-0}"
SYSCTL_FILE="/etc/sysctl.d/99-secaudit-oraclelinux8.conf"
MODPROBE_PREFIX="/etc/modprobe.d/sec-audit-disable"
AUDIT_RULES_FILE="/etc/audit/rules.d/99-secaudit-oraclelinux8.rules"

sec_audit_have_bin() { command -v "$1" >/dev/null 2>&1; }
sec_audit_log() { printf '[remediation] %s\n' "$*"; }
sec_audit_remediate_done() { printf '[remediation] REMEDIATE RULE%s= applied: %s\n' "$1" "$2"; }
sec_audit_remediate_skip() { printf '[remediation] REMEDIATE RULE%s= SKIP: manual step required - %s\n' "$1" "$2"; }

sec_audit_pkg_install() {
	local need=() p
	if sec_audit_have_bin dnf; then
		for p in "$@"; do rpm -q "$p" &>/dev/null || need+=("$p"); done
		((${#need[@]})) || return 0
		timeout 120 dnf install -y "${need[@]}" >/dev/null 2>&1 || true
	elif sec_audit_have_bin yum; then
		for p in "$@"; do rpm -q "$p" &>/dev/null || need+=("$p"); done
		((${#need[@]})) || return 0
		timeout 120 yum install -y "${need[@]}" >/dev/null 2>&1 || true
	fi
}

sec_audit_pkg_remove() {
	local p
	if sec_audit_have_bin dnf; then
		for p in "$@"; do
			rpm -q "$p" &>/dev/null || continue
			timeout 90 dnf remove -y "$p" >/dev/null 2>&1 || true
		done
	elif sec_audit_have_bin yum; then
		for p in "$@"; do
			rpm -q "$p" &>/dev/null || continue
			timeout 90 yum remove -y "$p" >/dev/null 2>&1 || true
		done
	fi
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
	local mod="$1" f="${MODPROBE_PREFIX}-${mod//\//_}.conf"
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
		case "$mp" in
		/tmp|/dev/shm|/var/tmp)
			echo "tmpfs ${mp} tmpfs defaults,${opt} 0 0" >>/etc/fstab
			mkdir -p "$mp"
			mount "$mp" >/dev/null 2>&1 || mount -o remount,${opt} "$mp" >/dev/null 2>&1 || true
			;;
		esac
	fi
}

sec_audit_set_sysctl() {
	local key="$1" val="$2"
	mkdir -p /etc/sysctl.d
	if [[ -f $SYSCTL_FILE ]] && grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$SYSCTL_FILE"; then
		sed -i "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${val}|" "$SYSCTL_FILE"
	else
		echo "${key} = ${val}" >>"$SYSCTL_FILE"
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

sec_audit_set_pwquality_kv() {
	local key="$1" val="$2" f=/etc/security/pwquality.conf
	mkdir -p /etc/security
	touch "$f"
	if grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$f"; then
		sed -i "s/^[[:space:]]*${key}[[:space:]]*=.*/${key} = ${val}/" "$f"
	else
		echo "${key} = ${val}" >>"$f"
	fi
}

sec_audit_set_faillock_kv() {
	local key="$1" val="$2" f=/etc/security/faillock.conf
	mkdir -p /etc/security
	touch "$f"
	if grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$f"; then
		sed -i "s/^[[:space:]]*${key}[[:space:]]*=.*/${key} = ${val}/" "$f"
	else
		echo "${key} = ${val}" >>"$f"
	fi
}

sec_audit_set_yum_gpgcheck() {
	local f
	for f in /etc/yum.conf /etc/dnf/dnf.conf; do
		[[ -f $f ]] || continue
		if grep -qE '^[[:space:]]*gpgcheck[[:space:]]*=' "$f"; then
			sed -i 's/^[[:space:]]*gpgcheck[[:space:]]*=.*/gpgcheck=1/' "$f"
		elif grep -qE '^\[main\]' "$f"; then
			sed -i '/^\[main\]/a gpgcheck=1' "$f"
		fi
	done
}

sec_audit_harden_path() {
	local path="$1" mode="$2" owner="${3:-root:root}"
	[[ -e $path ]] || return 0
	chmod "$mode" "$path" 2>/dev/null || true
	chown "$owner" "$path" 2>/dev/null || true
}

sec_audit_append_audit_watch() {
	local spec="$1"
	mkdir -p /etc/audit/rules.d
	touch "$AUDIT_RULES_FILE"
	grep -Fqx "$spec" "$AUDIT_RULES_FILE" 2>/dev/null || echo "$spec" >>"$AUDIT_RULES_FILE"
}


sec_audit_main() {
	sec_audit_log "starting remediation (OracleLinux8)"

# RULE1:
sec_audit_disable_kmod cramfs
sec_audit_remediate_done 1 "blacklisted kernel module cramfs"

# RULE2:
sec_audit_disable_kmod freevxfs
sec_audit_remediate_done 2 "blacklisted kernel module freevxfs"

# RULE3:
sec_audit_disable_kmod hfs
sec_audit_remediate_done 3 "blacklisted kernel module hfs"

# RULE4:
sec_audit_disable_kmod hfsplus
sec_audit_remediate_done 4 "blacklisted kernel module hfsplus"

# RULE5:
sec_audit_disable_kmod jffs2
sec_audit_remediate_done 5 "blacklisted kernel module jffs2"

# RULE6:
sec_audit_disable_kmod overlay
sec_audit_remediate_done 6 "blacklisted kernel module overlay"

# RULE7:
sec_audit_disable_kmod squashfs
sec_audit_remediate_done 7 "blacklisted kernel module squashfs"

# RULE8:
sec_audit_disable_kmod udf
sec_audit_remediate_done 8 "blacklisted kernel module udf"

# RULE9:
sec_audit_disable_kmod firewire-core
sec_audit_disable_kmod firewire_core
sec_audit_remediate_done 9 "blacklisted kernel module(s): firewire-core firewire_core"

# RULE10:
sec_audit_disable_kmod usb-storage
sec_audit_disable_kmod usb_storage
sec_audit_remediate_done 10 "blacklisted kernel module(s): usb-storage usb_storage"

# RULE11:
sec_audit_remediate_skip 11 "separate partition / layout change requires host planning"

# RULE12:
sec_audit_ensure_mount_option /tmp nodev
sec_audit_remediate_done 12 "set nodev on /tmp"

# RULE13:
sec_audit_ensure_mount_option /tmp nosuid
sec_audit_remediate_done 13 "set nosuid on /tmp"

# RULE14:
sec_audit_ensure_mount_option /tmp noexec
sec_audit_remediate_done 14 "set noexec on /tmp"

# RULE15:
sec_audit_remediate_skip 15 "separate partition / layout change requires host planning"

# RULE16:
sec_audit_ensure_mount_option /dev/shm nodev
sec_audit_remediate_done 16 "set nodev on /dev/shm"

# RULE17:
sec_audit_ensure_mount_option /dev/shm nosuid
sec_audit_remediate_done 17 "set nosuid on /dev/shm"

# RULE18:
sec_audit_ensure_mount_option /dev/shm noexec
sec_audit_remediate_done 18 "set noexec on /dev/shm"

# RULE19:
sec_audit_remediate_skip 19 "separate partition / layout change requires host planning"

# RULE20:
sec_audit_ensure_mount_option /home nodev
sec_audit_remediate_done 20 "set nodev on /home"

# RULE21:
sec_audit_ensure_mount_option /home nosuid
sec_audit_remediate_done 21 "set nosuid on /home"

# RULE22:
sec_audit_remediate_skip 22 "separate partition / layout change requires host planning"

# RULE23:
sec_audit_ensure_mount_option /var nodev
sec_audit_remediate_done 23 "set nodev on /var"

# RULE24:
sec_audit_ensure_mount_option /var nosuid
sec_audit_remediate_done 24 "set nosuid on /var"

# RULE25:
sec_audit_remediate_skip 25 "separate partition / layout change requires host planning"

# RULE26:
sec_audit_ensure_mount_option /var/tmp nodev
sec_audit_remediate_done 26 "set nodev on /var/tmp"

# RULE27:
sec_audit_ensure_mount_option /var/tmp nosuid
sec_audit_remediate_done 27 "set nosuid on /var/tmp"

# RULE28:
sec_audit_ensure_mount_option /var/tmp noexec
sec_audit_remediate_done 28 "set noexec on /var/tmp"

# RULE29:
sec_audit_remediate_skip 29 "separate partition / layout change requires host planning"

# RULE30:
sec_audit_ensure_mount_option /var/log nodev
sec_audit_remediate_done 30 "set nodev on /var/log"

# RULE31:
sec_audit_ensure_mount_option /var/log nosuid
sec_audit_remediate_done 31 "set nosuid on /var/log"

# RULE32:
sec_audit_ensure_mount_option /var/log noexec
sec_audit_remediate_done 32 "set noexec on /var/log"

# RULE33:
sec_audit_remediate_skip 33 "separate partition / layout change requires host planning"

# RULE34:
sec_audit_ensure_mount_option /var/log/audit nodev
sec_audit_remediate_done 34 "set nodev on /var/log/audit"

# RULE35:
sec_audit_ensure_mount_option /var/log/audit nosuid
sec_audit_remediate_done 35 "set nosuid on /var/log/audit"

# RULE36:
sec_audit_ensure_mount_option /var/log/audit noexec
sec_audit_remediate_done 36 "set noexec on /var/log/audit"

# RULE37:
sec_audit_set_yum_gpgcheck
sec_audit_remediate_done 37 "enabled yum/dnf gpgcheck"

# RULE38:
sec_audit_set_yum_gpgcheck
sec_audit_remediate_done 38 "enabled yum/dnf gpgcheck"

# RULE39:
sec_audit_set_yum_gpgcheck
sec_audit_remediate_done 39 "enabled yum/dnf gpgcheck"

# RULE40:
sec_audit_remediate_skip 40 '/etc/yum.repos.d is missing'

# RULE41:
sec_audit_remediate_skip 41 'install_weak_deps is false in merged [main] (weak dependencies not installed by default)'

# RULE42:
sec_audit_pkg_install libselinux
sec_audit_remediate_done 42 "ensured packages: libselinux"

# RULE43:
sec_audit_remediate_skip 43 'SELinux is disabled via kernel command line or bootloader configuration'

# RULE44:
if [[ -f /etc/selinux/config ]]; then sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config; fi
setenforce 1 >/dev/null 2>&1 || true
sec_audit_remediate_done 44 "SELinux enforcing in config (reboot may be required)"

# RULE45:
if [[ -f /etc/selinux/config ]]; then sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config; fi
setenforce 1 >/dev/null 2>&1 || true
sec_audit_remediate_done 45 "SELinux enforcing in config (reboot may be required)"

# RULE46:
if [[ -f /etc/selinux/config ]]; then sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config; fi
setenforce 1 >/dev/null 2>&1 || true
sec_audit_remediate_done 46 "SELinux enforcing in config (reboot may be required)"

# RULE47:
sec_audit_remediate_skip 47 'Processes running with unconfined_service_t were detected'

# RULE48:
sec_audit_pkg_remove setroubleshoot
sec_audit_remediate_done 48 "removed packages: setroubleshoot"

# RULE49:
sec_audit_remediate_skip 49 'bootloader password is set (grub.cfg under /boot/grub2 or EFI)'

# RULE50:
sec_audit_remediate_skip 50 'access to bootloader config is configured'

# RULE51:
sec_audit_remediate_skip 51 'limits * hard core 0 present and systemd DefaultLimitCORE does not allow unlimited core dumps'

# RULE52:
sec_audit_set_sysctl fs.protected_hardlinks 1
sec_audit_remediate_done 52 "sysctl hardening applied"

# RULE53:
sec_audit_set_sysctl fs.protected_symlinks 1
sec_audit_remediate_done 53 "sysctl hardening applied"

# RULE54:
sec_audit_set_sysctl fs.suid_dumpable 0
sec_audit_remediate_done 54 "sysctl hardening applied"

# RULE55:
sec_audit_set_sysctl kernel.dmesg_restrict 1
sec_audit_remediate_done 55 "sysctl hardening applied"

# RULE56:
sec_audit_set_sysctl kernel.kptr_restrict 1
sec_audit_remediate_done 56 "sysctl hardening applied"

# RULE57:
sec_audit_set_sysctl kernel.yama.ptrace_scope 1
sec_audit_remediate_done 57 "sysctl hardening applied"

# RULE58:
sec_audit_set_sysctl kernel.randomize_va_space 2
sec_audit_remediate_done 58 "sysctl hardening applied"

# RULE59:
sec_audit_remediate_skip 59 'merged coredump.conf sets ProcessSizeMax=0; kernel.core_pattern uses systemd-coredump'

# RULE60:
sec_audit_remediate_skip 60 'merged systemd/coredump.conf sets Storage=none'

# RULE61:
sec_audit_remediate_skip 61 'System-wide crypto policy is LEGACY in /etc/crypto-policies/config'

# RULE62:
sec_audit_remediate_skip 62 'Weak MAC algorithms still present in /etc/crypto-policies/state/CURRENT.pol'

# RULE63:
sec_audit_remediate_skip 63 'system wide crypto policy disables cbc for ssh'

# RULE64:
mkdir -p /etc
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue.net
sec_audit_remediate_done 64 "set login banners"

# RULE65:
mkdir -p /etc
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue.net
sec_audit_remediate_done 65 "set login banners"

# RULE66:
mkdir -p /etc
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue.net
sec_audit_remediate_done 66 "set login banners"

# RULE67:
mkdir -p /etc
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue.net
sec_audit_remediate_done 67 "set login banners"

# RULE68:
mkdir -p /etc
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue.net
sec_audit_remediate_done 68 "set login banners"

# RULE69:
mkdir -p /etc
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue.net
sec_audit_remediate_done 69 "set login banners"

# RULE70:
sec_audit_remediate_skip 70 'GDM login banner is configured'

# RULE71:
sec_audit_remediate_skip 71 'GDM disable-user-list is configured'

# RULE72:
sec_audit_remediate_skip 72 'GDM screen lock is configured'

# RULE73:
sec_audit_remediate_skip 73 'GDM automount is configured'

# RULE74:
sec_audit_remediate_skip 74 'GDM autorun-never is configured'

# RULE75:
sec_audit_remediate_skip 75 'Xwayland is configured'

# RULE76:
sec_audit_disable_svc autofs.service
sec_audit_remediate_done 76 "disabled units: autofs.service"

# RULE77:
sec_audit_disable_svc avahi-daemon.socket
sec_audit_disable_svc avahi-daemon.service
sec_audit_remediate_done 77 "disabled units: avahi-daemon.socket avahi-daemon.service"

# RULE78:
sec_audit_disable_svc cockpit.socket
sec_audit_disable_svc cockpit.service
sec_audit_remediate_done 78 "disabled units: cockpit.socket cockpit.service"

# RULE79:
sec_audit_disable_svc dhcpd.service
sec_audit_disable_svc dhcpd6.service
sec_audit_remediate_done 79 "disabled units: dhcpd.service dhcpd6.service"

# RULE80:
sec_audit_disable_svc named.service
sec_audit_remediate_done 80 "disabled units: named.service"

# RULE81:
sec_audit_disable_svc dnsmasq.service
sec_audit_remediate_done 81 "disabled units: dnsmasq.service"

# RULE82:
sec_audit_disable_svc vsftpd.service
sec_audit_remediate_done 82 "disabled units: vsftpd.service"

# RULE83:
sec_audit_disable_svc dovecot.socket
sec_audit_disable_svc dovecot.service
sec_audit_disable_svc cyrus-imapd.service
sec_audit_remediate_done 83 "disabled units: dovecot.socket dovecot.service cyrus-imapd.service"

# RULE84:
sec_audit_disable_svc nfs-server.service
sec_audit_remediate_done 84 "disabled units: nfs-server.service"

# RULE85:
sec_audit_disable_svc cups.socket
sec_audit_disable_svc cups.service
sec_audit_remediate_done 85 "disabled units: cups.socket cups.service"

# RULE86:
sec_audit_disable_svc rpcbind.socket
sec_audit_disable_svc rpcbind.service
sec_audit_remediate_done 86 "disabled units: rpcbind.socket rpcbind.service"

# RULE87:
sec_audit_disable_svc rsyncd.socket
sec_audit_disable_svc rsyncd.service
sec_audit_remediate_done 87 "disabled units: rsyncd.socket rsyncd.service"

# RULE88:
sec_audit_disable_svc smb.service
sec_audit_remediate_done 88 "disabled units: smb.service"

# RULE89:
sec_audit_disable_svc snmpd.service
sec_audit_remediate_done 89 "disabled units: snmpd.service"

# RULE90:
sec_audit_disable_svc telnet.socket
sec_audit_remediate_done 90 "disabled units: telnet.socket"

# RULE91:
sec_audit_disable_svc tftp.socket
sec_audit_disable_svc tftp.service
sec_audit_remediate_done 91 "disabled units: tftp.socket tftp.service"

# RULE92:
sec_audit_disable_svc squid.service
sec_audit_remediate_done 92 "disabled units: squid.service"

# RULE93:
sec_audit_disable_svc httpd.service
sec_audit_disable_svc nginx.service
sec_audit_remediate_done 93 "disabled units: httpd.service nginx.service"

# RULE94:
sec_audit_pkg_remove gdm
sec_audit_remediate_done 94 "removed packages: gdm"

# RULE95:
sec_audit_pkg_remove xorg-x11-server-Xwayland
sec_audit_remediate_done 95 "removed packages: xorg-x11-server-Xwayland"

# RULE96:
sec_audit_pkg_remove ftp
sec_audit_remediate_done 96 "removed packages: ftp"

# RULE97:
sec_audit_pkg_remove openldap-clients
sec_audit_remediate_done 97 "removed packages: openldap-clients"

# RULE98:
sec_audit_pkg_remove telnet
sec_audit_remediate_done 98 "removed packages: telnet"

# RULE99:
sec_audit_pkg_remove tftp
sec_audit_remediate_done 99 "removed packages: tftp"

# RULE100:
sec_audit_start_svc chronyd.service
sec_audit_remediate_done 100 "ensured required services enabled/started"

# RULE101:
sec_audit_pkg_install chrony
sec_audit_start_svc chronyd.service
sec_audit_remediate_done 101 "ensured chrony installed/started"

# RULE102:
sec_audit_pkg_install chrony
sec_audit_start_svc chronyd.service
sec_audit_remediate_done 102 "ensured chrony installed/started"

# RULE103:
sec_audit_remediate_skip 103 'cron daemon is enabled and active'

# RULE104:
sec_audit_remediate_skip 104 'access to /etc/crontab is configured'

# RULE105:
sec_audit_remediate_skip 105 'access to /etc/cron.hourly is configured'

# RULE106:
sec_audit_remediate_skip 106 'access to /etc/cron.daily is configured'

# RULE107:
sec_audit_remediate_skip 107 'access to /etc/cron.weekly is configured'

# RULE108:
sec_audit_remediate_skip 108 'access to /etc/cron.monthly is configured'

# RULE109:
sec_audit_remediate_skip 109 'access to /etc/cron.yearly is configured'

# RULE110:
sec_audit_remediate_skip 110 'access to /etc/cron.d is configured'

# RULE111:
sec_audit_remediate_skip 111 'access to crontab is configured'

# RULE112:
sec_audit_remediate_skip 112 'access to at is configured'

# RULE113:
sec_audit_remediate_skip 113 'IPv6 status is identified'

# RULE114:
sec_audit_remediate_skip 114 'Wireless interfaces are present under /sys/class/net'

# RULE115:
sec_audit_disable_svc bluetooth.service
sec_audit_remediate_done 115 "disabled units: bluetooth.service"

# RULE116:
sec_audit_disable_kmod atm
sec_audit_remediate_done 116 "blacklisted kernel module atm"

# RULE117:
sec_audit_disable_kmod can
sec_audit_remediate_done 117 "blacklisted kernel module can"

# RULE118:
sec_audit_disable_kmod dccp
sec_audit_remediate_done 118 "blacklisted kernel module dccp"

# RULE119:
sec_audit_disable_kmod tipc
sec_audit_remediate_done 119 "blacklisted kernel module tipc"

# RULE120:
sec_audit_disable_kmod rds
sec_audit_remediate_done 120 "blacklisted kernel module rds"

# RULE121:
sec_audit_disable_kmod sctp
sec_audit_remediate_done 121 "blacklisted kernel module sctp"

# RULE122:
sec_audit_set_sysctl net.ipv4.ip_forward 0
sec_audit_remediate_done 122 "sysctl hardening applied"

# RULE123:
sec_audit_remediate_skip 123 'host-specific remediation for RULE123'

# RULE124:
sec_audit_remediate_skip 124 'host-specific remediation for RULE124'

# RULE125:
sec_audit_set_sysctl net.ipv4.conf.all.send_redirects 0
sec_audit_remediate_done 125 "sysctl hardening applied"

# RULE126:
sec_audit_set_sysctl net.ipv4.conf.default.send_redirects 0
sec_audit_remediate_done 126 "sysctl hardening applied"

# RULE127:
sec_audit_set_sysctl net.ipv4.conf.all.accept_redirects 0
sec_audit_remediate_done 127 "sysctl hardening applied"

# RULE128:
sec_audit_set_sysctl net.ipv4.conf.all.secure_redirects 0
sec_audit_remediate_done 128 "sysctl hardening applied"

# RULE129:
sec_audit_set_sysctl net.ipv4.conf.all.rp_filter 1
sec_audit_remediate_done 129 "sysctl hardening applied"

# RULE130:
sec_audit_set_sysctl net.ipv4.conf.default.rp_filter 1
sec_audit_remediate_done 130 "sysctl hardening applied"

# RULE131:
sec_audit_set_sysctl net.ipv4.conf.all.log_martians 1
sec_audit_remediate_done 131 "sysctl hardening applied"

# RULE132:
sec_audit_set_sysctl net.ipv4.conf.default.log_martians 1
sec_audit_remediate_done 132 "sysctl hardening applied"

# RULE133:
sec_audit_set_sysctl net.ipv4.tcp_syncookies 1
sec_audit_remediate_done 133 "sysctl hardening applied"

# RULE134:
sec_audit_remediate_skip 134 'host-specific remediation for RULE134'

# RULE135:
sec_audit_remediate_skip 135 'host-specific remediation for RULE135'

# RULE136:
sec_audit_set_sysctl net.ipv6.conf.all.accept_redirects 0
sec_audit_remediate_done 136 "sysctl hardening applied"

# RULE137:
sec_audit_set_sysctl net.ipv6.conf.all.accept_ra 0
sec_audit_remediate_done 137 "sysctl hardening applied"

# RULE138:
sec_audit_set_sysctl net.ipv6.conf.default.accept_ra 0
sec_audit_remediate_done 138 "sysctl hardening applied"

# RULE156:
sec_audit_harden_path /etc/ssh/sshd_config 600 root:root
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key; do sec_audit_harden_path "$_k" 600 root:root; done; shopt -u nullglob
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key.pub; do sec_audit_harden_path "$_k" 644 root:root; done; shopt -u nullglob
sec_audit_remediate_done 156 "hardened ssh host key / sshd_config permissions"

# RULE157:
sec_audit_set_sshd_kv LoginGraceTime 60
sec_audit_remediate_done 157 "sshd_config hardened keys"

# RULE158:
sec_audit_set_sshd_kv LogLevel INFO
sec_audit_remediate_done 158 "sshd_config hardened keys"

# RULE159:
sec_audit_harden_path /etc/ssh/sshd_config 600 root:root
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key; do sec_audit_harden_path "$_k" 600 root:root; done; shopt -u nullglob
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key.pub; do sec_audit_harden_path "$_k" 644 root:root; done; shopt -u nullglob
sec_audit_remediate_done 159 "hardened ssh host key / sshd_config permissions"

# RULE160:
sec_audit_set_sshd_kv MaxAuthTries 4
sec_audit_remediate_done 160 "sshd_config hardened keys"

# RULE161:
sec_audit_set_sshd_kv MaxStartups 10:30:60
sec_audit_remediate_done 161 "sshd_config hardened keys"

# RULE162:
sec_audit_set_sshd_kv MaxSessions 10
sec_audit_remediate_done 162 "sshd_config hardened keys"

# RULE163:
sec_audit_set_sshd_kv PermitEmptyPasswords no
sec_audit_remediate_done 163 "sshd_config hardened keys"

# RULE164:
sec_audit_set_sshd_kv PermitRootLogin no
sec_audit_remediate_done 164 "sshd_config hardened keys"

# RULE165:
sec_audit_set_sshd_kv PermitUserEnvironment no
sec_audit_remediate_done 165 "sshd_config hardened keys"

# RULE166:
sec_audit_set_sshd_kv UsePAM yes
sec_audit_remediate_done 166 "sshd_config hardened keys"

# RULE167:
sec_audit_pkg_install sudo
sec_audit_remediate_done 167 "ensured packages: sudo"

# RULE168:
sec_audit_pkg_install sudo
mkdir -p /etc/sudoers.d
grep -q use_pty /etc/sudoers /etc/sudoers.d/* 2>/dev/null || echo 'Defaults use_pty' >/etc/sudoers.d/99-secaudit-pty
grep -q logfile /etc/sudoers /etc/sudoers.d/* 2>/dev/null || echo 'Defaults logfile="/var/log/sudo.log"' >/etc/sudoers.d/99-secaudit-logfile
chmod 440 /etc/sudoers.d/99-secaudit-pty /etc/sudoers.d/99-secaudit-logfile 2>/dev/null || true
sec_audit_remediate_done 168 "sudo use_pty/logfile baseline"

# RULE169:
sec_audit_remediate_skip 169 'sudo log file exists'

# RULE170:
sec_audit_remediate_skip 170 'NOPASSWD or password-less sudo rules violate escalation policy'

# RULE171:
sec_audit_remediate_skip 171 'sudo timestamp_timeout is configured'

# RULE172:
sec_audit_harden_path /etc/group 644 root:root
sec_audit_remediate_done 172 "hardened identity/config file permissions"

# RULE173:
sec_audit_set_pwquality_kv minlen 14
sec_audit_set_pwquality_kv minclass 4
sec_audit_remediate_done 173 "pwquality minlen/minclass baseline"

# RULE174:
sec_audit_set_faillock_kv deny 5
sec_audit_set_faillock_kv unlock_time 900
sec_audit_remediate_done 174 "faillock deny/unlock_time baseline"

# RULE175:
sec_audit_set_pwquality_kv minlen 14
sec_audit_set_pwquality_kv minclass 4
sec_audit_remediate_done 175 "pwquality minlen/minclass baseline"

# RULE176:
sec_audit_remediate_skip 176 'pam_pwhistory.so on password stack in resolved password-auth/system-auth'

# RULE177:
sec_audit_remediate_skip 177 'pam_unix.so on password stack in resolved password-auth/system-auth'

# RULE178:
sec_audit_set_faillock_kv deny 5
sec_audit_set_faillock_kv unlock_time 900
sec_audit_remediate_done 178 "faillock deny/unlock_time baseline"

# RULE179:
sec_audit_set_faillock_kv deny 5
sec_audit_set_faillock_kv unlock_time 900
sec_audit_remediate_done 179 "faillock deny/unlock_time baseline"

# RULE180:
sec_audit_set_pwquality_kv minlen 14
sec_audit_set_pwquality_kv minclass 4
sec_audit_remediate_done 180 "pwquality minlen/minclass baseline"

# RULE181:
sec_audit_set_pwquality_kv minlen 14
sec_audit_set_pwquality_kv minclass 4
sec_audit_remediate_done 181 "pwquality minlen/minclass baseline"

# RULE182:
sec_audit_set_pwquality_kv minlen 14
sec_audit_set_pwquality_kv minclass 4
sec_audit_remediate_done 182 "pwquality minlen/minclass baseline"

# RULE183:
sec_audit_set_pwquality_kv minlen 14
sec_audit_set_pwquality_kv minclass 4
sec_audit_remediate_done 183 "pwquality minlen/minclass baseline"

# RULE184:
sec_audit_remediate_skip 184 'password history remember is configured'

# RULE185:
sec_audit_remediate_skip 185 'password history is enforced for the root user'

# RULE186:
sec_audit_remediate_skip 186 'pam_pwhistory includes use_authtok'

# RULE187:
sec_audit_remediate_skip 187 'pam_unix does not include nullok'

# RULE188:
sec_audit_remediate_skip 188 'pam_unix does not include remember'

# RULE189:
sec_audit_remediate_skip 189 'pam_unix includes use_authtok'

# RULE190:
sec_audit_set_login_defs_kv PASS_MAX_DAYS 365
sec_audit_remediate_done 190 "set PASS_MAX_DAYS=365 in login.defs"

# RULE191:
sec_audit_set_login_defs_kv PASS_MIN_DAYS 1
sec_audit_remediate_done 191 "set PASS_MIN_DAYS=1 in login.defs"

# RULE192:
sec_audit_set_login_defs_kv PASS_WARN_AGE 7
sec_audit_remediate_done 192 "set PASS_WARN_AGE=7 in login.defs"

# RULE193:
sec_audit_set_login_defs_kv ENCRYPT_METHOD SHA512
sec_audit_remediate_done 193 "set ENCRYPT_METHOD=SHA512 in login.defs"

# RULE194:
sec_audit_set_login_defs_kv INACTIVE 30
sec_audit_remediate_done 194 "set INACTIVE=30 in login.defs"

# RULE195:
sec_audit_harden_path /etc/shadow 000 root:root
sec_audit_remediate_done 195 "hardened identity/config file permissions"

# RULE196:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_remediate_done 196 "hardened identity/config file permissions"

# RULE139:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_remediate_done 139 "hardened identity/config file permissions"

# RULE140:
sec_audit_harden_path /etc/group 644 root:root
sec_audit_remediate_done 140 "hardened identity/config file permissions"

# RULE141:
sec_audit_remediate_skip 141 'root account access is controlled'

# RULE142:
sec_audit_remediate_skip 142 'Root PATH contains empty directory (::)'

# RULE143:
sec_audit_remediate_skip 143 'root user umask is configured'

# RULE144:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_remediate_done 144 "hardened identity/config file permissions"

# RULE145:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_harden_path /etc/shadow 000 root:root
sec_audit_remediate_done 145 "hardened identity/config file permissions"

# RULE146:
sec_audit_remediate_skip 146 'nologin appears in /etc/shells'

# RULE147:
sec_audit_remediate_skip 147 'default user shell timeout is configured'

# RULE148:
sec_audit_remediate_skip 148 'default user umask is configured'

# RULE149:
sec_audit_pkg_install aide
sec_audit_remediate_done 149 "ensured packages: aide"

# RULE150:
sec_audit_remediate_skip 150 'filesystem integrity is regularly checked (cron/cron.d entry references aide)'

# RULE151:
sec_audit_remediate_skip 151 'journald service is active'

# RULE152:
sec_audit_remediate_skip 152 'journald log file access is configured (directory mode: $DIR_PERM)'

# RULE153:
sec_audit_remediate_skip 153 'journald log file rotation is configured'

# RULE154:
sec_audit_remediate_skip 154 'more than one logging system is in use (both rsyslog and journald are active)'

# RULE155:
sec_audit_start_svc auditd.service
sec_audit_start_svc rsyslog.service
sec_audit_remediate_done 155 "ensured required services enabled/started"


	if [ "${REMEDIATE_SECURITY_UPGRADE}" = "1" ]; then
		if sec_audit_have_bin dnf; then
			timeout 300 dnf upgrade --security -y >/dev/null 2>&1 || true
		elif sec_audit_have_bin yum; then
			timeout 300 yum update --security -y >/dev/null 2>&1 || true
		fi
	else
		sec_audit_log "skipping security upgrade (set REMEDIATE_SECURITY_UPGRADE=1 to enable)"
	fi
	sec_audit_log "remediation complete (Oracle8_remediation.sh)"
}

sec_audit_main "$@"
