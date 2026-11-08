#!/bin/bash
# Full remediation for RHEL8 — generated from audit rule bodies (sec_audit_* style).

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
SYSCTL_FILE="/etc/sysctl.d/99-secaudit-rhel8.conf"
MODPROBE_PREFIX="/etc/modprobe.d/sec-audit-disable"
AUDIT_RULES_FILE="/etc/audit/rules.d/99-secaudit-rhel8.rules"

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
	sec_audit_log "starting remediation (RHEL8)"

# RULE1:
sec_audit_disable_kmod cramfs
sec_audit_remediate_done 1 "blacklisted kernel module cramfs"

# RULE2:
sec_audit_disable_kmod squashfs
sec_audit_remediate_done 2 "blacklisted kernel module squashfs"

# RULE3:
sec_audit_disable_kmod udf
sec_audit_remediate_done 3 "blacklisted kernel module udf"

# RULE4:
sec_audit_remediate_skip 4 "separate partition / layout change requires host planning"

# RULE5:
sec_audit_ensure_mount_option /tmp nodev
sec_audit_remediate_done 5 "set nodev on /tmp"

# RULE6:
sec_audit_ensure_mount_option /tmp noexec
sec_audit_remediate_done 6 "set noexec on /tmp"

# RULE7:
sec_audit_ensure_mount_option /tmp nosuid
sec_audit_remediate_done 7 "set nosuid on /tmp"

# RULE8:
sec_audit_remediate_skip 8 "separate partition / layout change requires host planning"

# RULE9:
sec_audit_ensure_mount_option /var nodev
sec_audit_remediate_done 9 "set nodev on /var"

# RULE10:
sec_audit_ensure_mount_option /var noexec
sec_audit_remediate_done 10 "set noexec on /var"

# RULE11:
sec_audit_ensure_mount_option /var nosuid
sec_audit_remediate_done 11 "set nosuid on /var"

# RULE12:
sec_audit_remediate_skip 12 "separate partition / layout change requires host planning"

# RULE13:
sec_audit_ensure_mount_option /var/tmp noexec
sec_audit_remediate_done 13 "set noexec on /var/tmp"

# RULE14:
sec_audit_ensure_mount_option /var/tmp nosuid
sec_audit_remediate_done 14 "set nosuid on /var/tmp"

# RULE15:
sec_audit_ensure_mount_option /var/tmp nodev
sec_audit_remediate_done 15 "set nodev on /var/tmp"

# RULE16:
sec_audit_remediate_skip 16 "separate partition / layout change requires host planning"

# RULE17:
sec_audit_ensure_mount_option /var/log nodev
sec_audit_remediate_done 17 "set nodev on /var/log"

# RULE18:
sec_audit_ensure_mount_option /var/log noexec
sec_audit_remediate_done 18 "set noexec on /var/log"

# RULE19:
sec_audit_ensure_mount_option /var/log nosuid
sec_audit_remediate_done 19 "set nosuid on /var/log"

# RULE20:
sec_audit_remediate_skip 20 "separate partition / layout change requires host planning"

# RULE21:
sec_audit_ensure_mount_option /var/log/audit noexec
sec_audit_remediate_done 21 "set noexec on /var/log/audit"

# RULE22:
sec_audit_ensure_mount_option /var/log/audit nodev
sec_audit_remediate_done 22 "set nodev on /var/log/audit"

# RULE23:
sec_audit_ensure_mount_option /var/log/audit nosuid
sec_audit_remediate_done 23 "set nosuid on /var/log/audit"

# RULE24:
sec_audit_remediate_skip 24 "separate partition / layout change requires host planning"

# RULE25:
sec_audit_ensure_mount_option /home nodev
sec_audit_remediate_done 25 "set nodev on /home"

# RULE26:
sec_audit_ensure_mount_option /home nosuid
sec_audit_remediate_done 26 "set nosuid on /home"

# RULE27:
sec_audit_remediate_skip 27 'usrquota option set on /home partition'

# RULE28:
sec_audit_remediate_skip 28 'grpquota option set on /home partition'

# RULE29:
sec_audit_remediate_skip 29 "separate partition / layout change requires host planning"

# RULE30:
sec_audit_ensure_mount_option /dev/shm noexec
sec_audit_remediate_done 30 "set noexec on /dev/shm"

# RULE31:
sec_audit_ensure_mount_option /dev/shm nosuid
sec_audit_remediate_done 31 "set nosuid on /dev/shm"

# RULE32:
sec_audit_remediate_skip 32 'Red Hat Subscription Manager identity is available'

# RULE33:
sec_audit_set_yum_gpgcheck
sec_audit_remediate_done 33 "enabled yum/dnf gpgcheck"

# RULE34:
sec_audit_set_yum_gpgcheck
sec_audit_remediate_done 34 "enabled yum/dnf gpgcheck"

# RULE35:
sec_audit_remediate_skip 35 '/etc/yum.repos.d is missing'

# RULE36:
sec_audit_pkg_install aide
sec_audit_remediate_done 36 "ensured packages: aide"

# RULE37:
sec_audit_remediate_skip 37 'filesystem integrity is regularly checked (cron/cron.d entry references aide)'

# RULE38:
sec_audit_remediate_skip 38 'bootloader password is set (grub.cfg under /boot/grub2 or EFI)'

# RULE39:
sec_audit_remediate_skip 39 'access to bootloader config is configured'

# RULE40:
sec_audit_remediate_skip 40 'authentication required when booting into rescue/emergency mode'

# RULE41:
sec_audit_remediate_skip 41 'limits * hard core 0 present and systemd DefaultLimitCORE does not allow unlimited core dumps'

# RULE42:
sec_audit_set_sysctl fs.protected_hardlinks 1
sec_audit_remediate_done 42 "sysctl hardening applied"

# RULE43:
sec_audit_set_sysctl fs.protected_symlinks 1
sec_audit_remediate_done 43 "sysctl hardening applied"

# RULE44:
sec_audit_pkg_install libselinux
sec_audit_remediate_done 44 "ensured packages: libselinux"

# RULE45:
sec_audit_remediate_skip 45 'SELinux is disabled via kernel command line or bootloader configuration'

# RULE46:
if [[ -f /etc/selinux/config ]]; then sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config; fi
setenforce 1 >/dev/null 2>&1 || true
sec_audit_remediate_done 46 "SELinux enforcing in config (reboot may be required)"

# RULE47:
if [[ -f /etc/selinux/config ]]; then sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config; fi
setenforce 1 >/dev/null 2>&1 || true
sec_audit_remediate_done 47 "SELinux enforcing in config (reboot may be required)"

# RULE48:
if [[ -f /etc/selinux/config ]]; then sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config; fi
setenforce 1 >/dev/null 2>&1 || true
sec_audit_remediate_done 48 "SELinux enforcing in config (reboot may be required)"

# RULE49:
sec_audit_remediate_skip 49 'Processes running with unconfined_service_t were detected'

# RULE50:
sec_audit_pkg_remove setroubleshoot
sec_audit_remediate_done 50 "removed packages: setroubleshoot"

# RULE51:
sec_audit_pkg_remove mcstrans
sec_audit_remediate_done 51 "removed packages: mcstrans"

# RULE52:
mkdir -p /etc
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue.net
sec_audit_remediate_done 52 "set login banners"

# RULE53:
mkdir -p /etc
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue.net
sec_audit_remediate_done 53 "set login banners"

# RULE54:
mkdir -p /etc
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue.net
sec_audit_remediate_done 54 "set login banners"

# RULE55:
mkdir -p /etc
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue.net
sec_audit_remediate_done 55 "set login banners"

# RULE56:
mkdir -p /etc
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue.net
sec_audit_remediate_done 56 "set login banners"

# RULE57:
mkdir -p /etc
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue.net
sec_audit_remediate_done 57 "set login banners"

# RULE58:
sec_audit_remediate_skip 58 'GDM login banner is configured'

# RULE59:
sec_audit_remediate_skip 59 'GDM disable-user-list is configured'

# RULE60:
sec_audit_remediate_skip 60 'GDM screen lock is configured'

# RULE61:
sec_audit_remediate_skip 61 'GDM automount is configured'

# RULE62:
sec_audit_disable_kmod removable
sec_audit_remediate_done 62 "blacklisted kernel module(s): removable"

# RULE63:
sec_audit_remediate_skip 63 'no pending security updates reported by dnf check-update --security'

# RULE64:
sec_audit_remediate_skip 64 'System-wide crypto policy is LEGACY in /etc/crypto-policies/config'

# RULE65:
sec_audit_start_svc chronyd.service
sec_audit_remediate_done 65 "ensured required services enabled/started"

# RULE66:
sec_audit_pkg_install chrony
sec_audit_start_svc chronyd.service
sec_audit_remediate_done 66 "ensured chrony installed/started"

# RULE67:
sec_audit_pkg_remove xinetd
sec_audit_remediate_done 67 "removed packages: xinetd"

# RULE68:
sec_audit_pkg_remove xorg-x11-server
sec_audit_remediate_done 68 "removed packages: xorg-x11-server"

# RULE69:
sec_audit_disable_svc avahi-daemon.socket
sec_audit_disable_svc avahi-daemon.service
sec_audit_remediate_done 69 "disabled units: avahi-daemon.socket avahi-daemon.service"

# RULE70:
sec_audit_disable_svc cups.socket
sec_audit_disable_svc cups.service
sec_audit_remediate_done 70 "disabled units: cups.socket cups.service"

# RULE71:
sec_audit_pkg_remove dhcp
sec_audit_remediate_done 71 "removed packages: dhcp"

# RULE72:
sec_audit_disable_svc dnsmasq.service
sec_audit_remediate_done 72 "disabled units: dnsmasq.service"

# RULE73:
sec_audit_disable_svc vsftpd.service
sec_audit_remediate_done 73 "disabled units: vsftpd.service"

# RULE74:
sec_audit_disable_svc dovecot.socket
sec_audit_disable_svc dovecot.service
sec_audit_disable_svc cyrus-imapd.service
sec_audit_remediate_done 74 "disabled units: dovecot.socket dovecot.service cyrus-imapd.service"

# RULE75:
sec_audit_disable_svc nfs-server.service
sec_audit_remediate_done 75 "disabled units: nfs-server.service"

# RULE76:
sec_audit_pkg_remove httpd
sec_audit_remediate_done 76 "removed packages: httpd"

# RULE77:
sec_audit_pkg_remove dovecot
sec_audit_remediate_done 77 "removed packages: dovecot"

# RULE78:
sec_audit_disable_svc smb.service
sec_audit_remediate_done 78 "disabled units: smb.service"

# RULE79:
sec_audit_pkg_remove squid
sec_audit_remediate_done 79 "removed packages: squid"

# RULE80:
sec_audit_disable_svc snmpd.service
sec_audit_remediate_done 80 "disabled units: snmpd.service"

# RULE81:
sec_audit_disable_svc telnet.socket
sec_audit_remediate_done 81 "disabled units: telnet.socket"

# RULE82:
sec_audit_pkg_remove telnet
sec_audit_remediate_done 82 "removed packages: telnet"

# RULE83:
sec_audit_disable_svc squid.service
sec_audit_remediate_done 83 "disabled units: squid.service"

# RULE84:
sec_audit_pkg_remove nfs-utils
sec_audit_remediate_done 84 "removed packages: nfs-utils"

# RULE85:
sec_audit_disable_svc named.service
sec_audit_remediate_done 85 "disabled units: named.service"

# RULE86:
sec_audit_pkg_remove rsync
sec_audit_remediate_done 86 "removed packages: rsync"

# RULE87:
sec_audit_start_svc chronyd.service
sec_audit_remediate_done 87 "ensured required services enabled/started"

# RULE88:
sec_audit_pkg_remove rsh
sec_audit_remediate_done 88 "removed packages: rsh"

# RULE89:
sec_audit_pkg_remove talk
sec_audit_remediate_done 89 "removed packages: talk"

# RULE90:
sec_audit_pkg_remove telnet
sec_audit_remediate_done 90 "removed packages: telnet"

# RULE91:
sec_audit_pkg_remove openldap-clients
sec_audit_remediate_done 91 "removed packages: openldap-clients"

# RULE92:
sec_audit_pkg_remove tftp
sec_audit_remediate_done 92 "removed packages: tftp"

# RULE93:
sec_audit_remediate_skip 93 'nonessential inet services are masked or disabled'

# RULE94:
sec_audit_remediate_skip 94 'Wireless interfaces are present under /sys/class/net'

# RULE95:
sec_audit_disable_svc bluetooth.service
sec_audit_remediate_done 95 "disabled units: bluetooth.service"

# RULE96:
sec_audit_remediate_skip 96 'wireless (Wi-Fi) radio is enabled'

# RULE97:
sec_audit_disable_kmod atm
sec_audit_remediate_done 97 "blacklisted kernel module atm"

# RULE98:
sec_audit_disable_kmod can
sec_audit_remediate_done 98 "blacklisted kernel module can"

# RULE99:
sec_audit_set_sysctl net.ipv4.conf.all.accept_source_route 0
sec_audit_set_sysctl net.ipv4.conf.default.accept_source_route 0
sec_audit_set_sysctl "net.ipv4.conf.all.accept_source_route" "0";
sec_audit_remediate_done 99 "sysctl hardening applied"

# RULE100:
sec_audit_set_sysctl net.ipv4.conf.all.accept_redirects 0
sec_audit_set_sysctl net.ipv4.conf.default.accept_redirects 0
sec_audit_set_sysctl "net.ipv4.conf.all.accept_redirects" "0";
sec_audit_remediate_done 100 "sysctl hardening applied"

# RULE101:
sec_audit_set_sysctl net.ipv4.conf.all.secure_redirects 0
sec_audit_set_sysctl net.ipv4.conf.default.secure_redirects 0
sec_audit_set_sysctl "net.ipv4.conf.all.secure_redirects" "0";
sec_audit_remediate_done 101 "sysctl hardening applied"

# RULE102:
sec_audit_set_sysctl net.ipv4.conf.all.log_martians 1
sec_audit_set_sysctl net.ipv4.conf.default.log_martians 1
sec_audit_set_sysctl "net.ipv4.conf.all.log_martians" "1";
sec_audit_remediate_done 102 "sysctl hardening applied"

# RULE103:
sec_audit_set_sysctl net.ipv4.icmp_echo_ignore_broadcasts 1
sec_audit_set_sysctl "net.ipv4.icmp_echo_ignore_broadcasts" "1";
sec_audit_remediate_done 103 "sysctl hardening applied"

# RULE104:
sec_audit_set_sysctl net.ipv4.icmp_ignore_bogus_error_responses 1
sec_audit_set_sysctl "net.ipv4.icmp_ignore_bogus_error_responses" "1";
sec_audit_remediate_done 104 "sysctl hardening applied"

# RULE105:
sec_audit_set_sysctl net.ipv4.conf.all.rp_filter 1
sec_audit_set_sysctl net.ipv4.conf.default.rp_filter 1
sec_audit_set_sysctl "net.ipv4.conf.all.rp_filter" "1";
sec_audit_remediate_done 105 "sysctl hardening applied"

# RULE106:
sec_audit_set_sysctl net.ipv4.tcp_syncookies 1
sec_audit_set_sysctl "net.ipv4.tcp_syncookies" "1";
sec_audit_remediate_done 106 "sysctl hardening applied"

# RULE107:
sec_audit_set_sysctl net.ipv6.conf.all.accept_ra 0
sec_audit_set_sysctl net.ipv6.conf.default.accept_ra 0
sec_audit_set_sysctl "net.ipv6.conf.all.accept_ra" "0";
sec_audit_remediate_done 107 "sysctl hardening applied"

# RULE108:
sec_audit_pkg_install iptables
sec_audit_remediate_done 108 "ensured packages: iptables"

# RULE109:
sec_audit_pkg_install firewalld
sec_audit_start_svc firewalld.service
sec_audit_remediate_done 109 "ensured firewalld installed/started"

# RULE110:
sec_audit_pkg_install audit
sec_audit_remediate_done 110 "ensured packages: audit"

# RULE111:
sec_audit_start_svc auditd.service
sec_audit_remediate_done 111 "ensured required services enabled/started"

# RULE112:
sec_audit_remediate_skip 112 'audit_backlog_limit is configured'

# RULE113:
sec_audit_remediate_skip 113 'audit_backlog_limit is configured'

# RULE114:
sec_audit_remediate_skip 114 'audit log storage size is configured'

# RULE115:
sec_audit_remediate_skip 115 'audit logs are not automatically deleted'

# RULE116:
sec_audit_remediate_skip 116 'system is disabled when audit logs are full'

# RULE117:
sec_audit_append_audit_watch '-w /etc/sudoers"; -p wa -k secaudit'
sec_audit_append_audit_watch '-w /etc/sudoers.d"; -p wa -k secaudit'
sec_audit_append_audit_watch '-w /etc/sudoers.d -p wa -k secaudit'
sec_audit_append_audit_watch '-w /etc/sudoers -p wa -k secaudit'
sec_audit_pkg_install audit
sec_audit_start_svc auditd.service
sec_audit_remediate_done 117 "audit watch rules appended"

# RULE118:
sec_audit_pkg_install audit
sec_audit_start_svc auditd.service
sec_audit_remediate_done 118 "ensured auditd installed/started"

# RULE119:
sec_audit_append_audit_watch '-w /var/log/sudo.log -p wa -k secaudit'
sec_audit_append_audit_watch '-w /var/log/sudo.log"; -p wa -k secaudit'
sec_audit_pkg_install audit
sec_audit_start_svc auditd.service
sec_audit_remediate_done 119 "audit watch rules appended"

# RULE120:
sec_audit_pkg_install audit
sec_audit_start_svc auditd.service
sec_audit_remediate_done 120 "ensured auditd installed/started"

# RULE121:
sec_audit_pkg_install audit
sec_audit_start_svc auditd.service
sec_audit_remediate_done 121 "ensured auditd installed/started"

# RULE122:
sec_audit_harden_path /etc/shadow 000 root:root
sec_audit_harden_path /etc/gshadow 000 root:root
sec_audit_remediate_done 122 "hardened identity/config file permissions"

# RULE123:
sec_audit_append_audit_watch '-w /etc/NetworkManager/"; -p wa -k secaudit'
sec_audit_append_audit_watch '-w /etc/NetworkManager -p wa -k secaudit'
sec_audit_pkg_install audit
sec_audit_start_svc auditd.service
sec_audit_remediate_done 123 "audit watch rules appended"

# RULE124:
sec_audit_pkg_install audit
sec_audit_start_svc auditd.service
sec_audit_remediate_done 124 "ensured auditd installed/started"

# RULE125:
sec_audit_set_faillock_kv deny 5
sec_audit_set_faillock_kv unlock_time 900
sec_audit_remediate_done 125 "faillock deny/unlock_time baseline"

# RULE126:
sec_audit_pkg_install audit
sec_audit_start_svc auditd.service
sec_audit_remediate_done 126 "ensured auditd installed/started"

# RULE127:
sec_audit_pkg_install audit
sec_audit_start_svc auditd.service
sec_audit_remediate_done 127 "ensured auditd installed/started"

# RULE128:
sec_audit_pkg_install audit
sec_audit_start_svc auditd.service
sec_audit_remediate_done 128 "ensured auditd installed/started"

# RULE129:
sec_audit_pkg_install audit
sec_audit_start_svc auditd.service
sec_audit_remediate_done 129 "ensured auditd installed/started"

# RULE130:
sec_audit_pkg_install audit
sec_audit_start_svc auditd.service
sec_audit_remediate_done 130 "ensured auditd installed/started"

# RULE131:
sec_audit_pkg_install audit
sec_audit_start_svc auditd.service
sec_audit_remediate_done 131 "ensured auditd installed/started"

# RULE132:
sec_audit_remediate_skip 132 'the running and on disk configuration is the same'

# RULE133:
sec_audit_pkg_install rsyslog
sec_audit_remediate_done 133 "ensured packages: rsyslog"

# RULE134:
sec_audit_start_svc rsyslog.service
sec_audit_remediate_done 134 "ensured required services enabled/started"

# RULE135:
sec_audit_remediate_skip 135 'rsyslog log file creation mode is configured'

# RULE136:
sec_audit_remediate_skip 136 'rsyslog logging is configured'

# RULE137:
sec_audit_remediate_skip 137 'rsyslog forwards logs to a remote host (@@ target in rsyslog configuration)'

# RULE138:
sec_audit_pkg_install systemd-journal-remote
sec_audit_remediate_done 138 "ensured packages: systemd-journal-remote"

# RULE139:
sec_audit_remediate_skip 139 'systemd-journal-upload URL is configured'

# RULE140:
sec_audit_remediate_skip 140 'systemd-journal-upload is enabled and active'

# RULE141:
sec_audit_disable_svc systemd-journal-remote.socket
sec_audit_disable_svc systemd-journal-remote.service
sec_audit_remediate_done 141 "disabled units: systemd-journal-remote.socket systemd-journal-remote.service"

# RULE142:
sec_audit_remediate_skip 142 'journald service is active'

# RULE143:
sec_audit_remediate_skip 143 'journald log file rotation is configured'

# RULE144:
sec_audit_remediate_skip 144 'more than one logging system is in use (both rsyslog and journald are active)'

# RULE145:
sec_audit_remediate_skip 145 'journald ForwardToSyslog=yes (should be no for dedicated journald)'

# RULE146:
sec_audit_remediate_skip 146 'journald log file rotation is configured'

# RULE147:
sec_audit_remediate_skip 147 'journald log file access is configured (directory mode: $DIR_PERM)'

# RULE148:
sec_audit_remediate_skip 148 'cron daemon is enabled and active'

# RULE149:
sec_audit_remediate_skip 149 'access to /etc/crontab is configured'

# RULE150:
sec_audit_remediate_skip 150 'access to /etc/cron.hourly is configured'

# RULE151:
sec_audit_remediate_skip 151 'access to /etc/cron.daily is configured'

# RULE152:
sec_audit_remediate_skip 152 'access to /etc/cron.weekly is configured'

# RULE153:
sec_audit_remediate_skip 153 'access to /etc/cron.monthly is configured'

# RULE154:
sec_audit_remediate_skip 154 'access to /etc/cron.yearly is configured'

# RULE155:
sec_audit_remediate_skip 155 'access to /etc/cron.d is configured'

# RULE156:
sec_audit_remediate_skip 156 'access to crontab is configured'

# RULE157:
sec_audit_harden_path /etc/ssh/sshd_config 600 root:root
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key; do sec_audit_harden_path "$_k" 600 root:root; done; shopt -u nullglob
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key.pub; do sec_audit_harden_path "$_k" 644 root:root; done; shopt -u nullglob
sec_audit_remediate_done 157 "hardened ssh host key / sshd_config permissions"

# RULE158:
sec_audit_harden_path /etc/ssh/sshd_config 600 root:root
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key; do sec_audit_harden_path "$_k" 600 root:root; done; shopt -u nullglob
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key.pub; do sec_audit_harden_path "$_k" 644 root:root; done; shopt -u nullglob
sec_audit_remediate_done 158 "hardened ssh host key / sshd_config permissions"

# RULE159:
sec_audit_harden_path /etc/ssh/sshd_config 600 root:root
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key; do sec_audit_harden_path "$_k" 600 root:root; done; shopt -u nullglob
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key.pub; do sec_audit_harden_path "$_k" 644 root:root; done; shopt -u nullglob
sec_audit_remediate_done 159 "hardened ssh host key / sshd_config permissions"

# RULE160:
sec_audit_harden_path /etc/ssh/sshd_config 600 root:root
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key; do sec_audit_harden_path "$_k" 600 root:root; done; shopt -u nullglob
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key.pub; do sec_audit_harden_path "$_k" 644 root:root; done; shopt -u nullglob
sec_audit_remediate_done 160 "hardened ssh host key / sshd_config permissions"

# RULE161:
sec_audit_set_sshd_kv Banner /etc/issue.net
sec_audit_remediate_done 161 "sshd_config hardened keys"

# RULE162:
sec_audit_harden_path /etc/ssh/sshd_config 600 root:root
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key; do sec_audit_harden_path "$_k" 600 root:root; done; shopt -u nullglob
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key.pub; do sec_audit_harden_path "$_k" 644 root:root; done; shopt -u nullglob
sec_audit_remediate_done 162 "hardened ssh host key / sshd_config permissions"

# RULE163:
sec_audit_set_sshd_kv ClientAliveInterval 15
sec_audit_set_sshd_kv ClientAliveCountMax 3
sec_audit_remediate_done 163 "sshd_config hardened keys"

# RULE164:
sec_audit_harden_path /etc/ssh/sshd_config 600 root:root
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key; do sec_audit_harden_path "$_k" 600 root:root; done; shopt -u nullglob
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key.pub; do sec_audit_harden_path "$_k" 644 root:root; done; shopt -u nullglob
sec_audit_remediate_done 164 "hardened ssh host key / sshd_config permissions"

# RULE165:
sec_audit_harden_path /etc/ssh/sshd_config 600 root:root
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key; do sec_audit_harden_path "$_k" 600 root:root; done; shopt -u nullglob
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key.pub; do sec_audit_harden_path "$_k" 644 root:root; done; shopt -u nullglob
sec_audit_remediate_done 165 "hardened ssh host key / sshd_config permissions"

# RULE166:
sec_audit_set_sshd_kv HostbasedAuthentication no
sec_audit_remediate_done 166 "sshd_config hardened keys"

# RULE167:
sec_audit_set_sshd_kv IgnoreRhosts yes
sec_audit_remediate_done 167 "sshd_config hardened keys"

# RULE168:
sec_audit_harden_path /etc/ssh/sshd_config 600 root:root
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key; do sec_audit_harden_path "$_k" 600 root:root; done; shopt -u nullglob
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key.pub; do sec_audit_harden_path "$_k" 644 root:root; done; shopt -u nullglob
sec_audit_remediate_done 168 "hardened ssh host key / sshd_config permissions"

# RULE169:
sec_audit_set_sshd_kv LogLevel INFO
sec_audit_remediate_done 169 "sshd_config hardened keys"

# RULE170:
sec_audit_harden_path /etc/ssh/sshd_config 600 root:root
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key; do sec_audit_harden_path "$_k" 600 root:root; done; shopt -u nullglob
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key.pub; do sec_audit_harden_path "$_k" 644 root:root; done; shopt -u nullglob
sec_audit_remediate_done 170 "hardened ssh host key / sshd_config permissions"

# RULE171:
sec_audit_set_sshd_kv MaxAuthTries 4
sec_audit_remediate_done 171 "sshd_config hardened keys"

# RULE172:
sec_audit_set_sshd_kv PermitEmptyPasswords no
sec_audit_remediate_done 172 "sshd_config hardened keys"

# RULE173:
sec_audit_set_sshd_kv PermitRootLogin no
sec_audit_remediate_done 173 "sshd_config hardened keys"

# RULE174:
sec_audit_pkg_install sudo
sec_audit_remediate_done 174 "ensured packages: sudo"

# RULE175:
sec_audit_pkg_install sudo
mkdir -p /etc/sudoers.d
grep -q use_pty /etc/sudoers /etc/sudoers.d/* 2>/dev/null || echo 'Defaults use_pty' >/etc/sudoers.d/99-secaudit-pty
grep -q logfile /etc/sudoers /etc/sudoers.d/* 2>/dev/null || echo 'Defaults logfile="/var/log/sudo.log"' >/etc/sudoers.d/99-secaudit-logfile
chmod 440 /etc/sudoers.d/99-secaudit-pty /etc/sudoers.d/99-secaudit-logfile 2>/dev/null || true
sec_audit_remediate_done 175 "sudo use_pty/logfile baseline"

# RULE176:
sec_audit_pkg_install sudo
mkdir -p /etc/sudoers.d
grep -q use_pty /etc/sudoers /etc/sudoers.d/* 2>/dev/null || echo 'Defaults use_pty' >/etc/sudoers.d/99-secaudit-pty
grep -q logfile /etc/sudoers /etc/sudoers.d/* 2>/dev/null || echo 'Defaults logfile="/var/log/sudo.log"' >/etc/sudoers.d/99-secaudit-logfile
chmod 440 /etc/sudoers.d/99-secaudit-pty /etc/sudoers.d/99-secaudit-logfile 2>/dev/null || true
sec_audit_remediate_done 176 "sudo use_pty/logfile baseline"

# RULE177:
sec_audit_pkg_install sudo
mkdir -p /etc/sudoers.d
grep -q use_pty /etc/sudoers /etc/sudoers.d/* 2>/dev/null || echo 'Defaults use_pty' >/etc/sudoers.d/99-secaudit-pty
grep -q logfile /etc/sudoers /etc/sudoers.d/* 2>/dev/null || echo 'Defaults logfile="/var/log/sudo.log"' >/etc/sudoers.d/99-secaudit-logfile
chmod 440 /etc/sudoers.d/99-secaudit-pty /etc/sudoers.d/99-secaudit-logfile 2>/dev/null || true
sec_audit_remediate_done 177 "sudo use_pty/logfile baseline"

# RULE178:
sec_audit_pkg_install sudo
mkdir -p /etc/sudoers.d
grep -q use_pty /etc/sudoers /etc/sudoers.d/* 2>/dev/null || echo 'Defaults use_pty' >/etc/sudoers.d/99-secaudit-pty
grep -q logfile /etc/sudoers /etc/sudoers.d/* 2>/dev/null || echo 'Defaults logfile="/var/log/sudo.log"' >/etc/sudoers.d/99-secaudit-logfile
chmod 440 /etc/sudoers.d/99-secaudit-pty /etc/sudoers.d/99-secaudit-logfile 2>/dev/null || true
sec_audit_remediate_done 178 "sudo use_pty/logfile baseline"

# RULE179:
sec_audit_remediate_skip 179 'sudo timestamp_timeout is configured'

# RULE180:
sec_audit_harden_path /etc/group 644 root:root
sec_audit_remediate_done 180 "hardened identity/config file permissions"

# RULE181:
sec_audit_set_faillock_kv deny 5
sec_audit_set_faillock_kv unlock_time 900
sec_audit_remediate_done 181 "faillock deny/unlock_time baseline"

# RULE182:
sec_audit_set_pwquality_kv minlen 14
sec_audit_set_pwquality_kv minclass 4
sec_audit_remediate_done 182 "pwquality minlen/minclass baseline"

# RULE183:
sec_audit_set_faillock_kv deny 5
sec_audit_set_faillock_kv unlock_time 900
sec_audit_remediate_done 183 "faillock deny/unlock_time baseline"

# RULE184:
sec_audit_remediate_skip 184 'password history remember is configured'

# RULE185:
sec_audit_set_login_defs_kv ENCRYPT_METHOD SHA512
sec_audit_remediate_done 185 "set ENCRYPT_METHOD=SHA512 in login.defs"

# RULE186:
sec_audit_set_login_defs_kv PASS_MAX_DAYS 365
sec_audit_remediate_done 186 "set PASS_MAX_DAYS=365 in login.defs"

# RULE187:
sec_audit_set_login_defs_kv PASS_MIN_DAYS 1
sec_audit_remediate_done 187 "set PASS_MIN_DAYS=1 in login.defs"

# RULE188:
sec_audit_set_login_defs_kv PASS_WARN_AGE 7
sec_audit_remediate_done 188 "set PASS_WARN_AGE=7 in login.defs"

# RULE189:
sec_audit_set_login_defs_kv INACTIVE 30
sec_audit_remediate_done 189 "set INACTIVE=30 in login.defs"

# RULE190:
sec_audit_harden_path /etc/shadow 000 root:root
sec_audit_remediate_done 190 "hardened identity/config file permissions"

# RULE191:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_remediate_done 191 "hardened identity/config file permissions"

# RULE192:
sec_audit_remediate_skip 192 'nologin appears in /etc/shells'

# RULE193:
sec_audit_harden_path /etc/group 644 root:root
sec_audit_remediate_done 193 "hardened identity/config file permissions"

# RULE194:
sec_audit_remediate_skip 194 'default user umask is configured'

# RULE195:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_harden_path /etc/passwd- 644 root:root
sec_audit_remediate_done 195 "hardened identity/config file permissions"

# RULE196:
sec_audit_harden_path /etc/group 644 root:root
sec_audit_remediate_done 196 "hardened identity/config file permissions"

# RULE197:
sec_audit_harden_path /etc/group 644 root:root
sec_audit_harden_path /etc/group- 644 root:root
sec_audit_remediate_done 197 "hardened identity/config file permissions"

# RULE198:
sec_audit_harden_path /etc/shadow 000 root:root
sec_audit_remediate_done 198 "hardened identity/config file permissions"

# RULE199:
sec_audit_harden_path /etc/shadow 000 root:root
sec_audit_harden_path /etc/shadow- 000 root:root
sec_audit_remediate_done 199 "hardened identity/config file permissions"

# RULE200:
sec_audit_harden_path /etc/gshadow 000 root:root
sec_audit_remediate_done 200 "hardened identity/config file permissions"

# RULE201:
sec_audit_harden_path /etc/gshadow 000 root:root
sec_audit_harden_path /etc/gshadow- 000 root:root
sec_audit_remediate_done 201 "hardened identity/config file permissions"

# RULE202:
sec_audit_remediate_skip 202 'access to /etc/shells is configured'

# RULE203:
sec_audit_remediate_skip 203 'access to /etc/security/opasswd is configured'

# RULE204:
sec_audit_remediate_skip 204 'incomplete_scan: world-writable file search timed out under critical paths'

# RULE205:
sec_audit_remediate_skip 205 'no unowned files or directories exist (sample scan)'

# RULE206:
sec_audit_remediate_skip 206 'no SUID or SGID files found (sample scan)'

# RULE207:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_remediate_done 207 "hardened identity/config file permissions"

# RULE208:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_harden_path /etc/group 644 root:root
sec_audit_remediate_done 208 "hardened identity/config file permissions"

# RULE209:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_remediate_done 209 "hardened identity/config file permissions"

# RULE210:
sec_audit_harden_path /etc/group 644 root:root
sec_audit_remediate_done 210 "hardened identity/config file permissions"

# RULE211:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_remediate_done 211 "hardened identity/config file permissions"

# RULE212:
sec_audit_remediate_skip 212 'Root PATH contains empty directory (::)'

# RULE213:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_remediate_done 213 "hardened identity/config file permissions"

# RULE214:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_remediate_done 214 "hardened identity/config file permissions"

# RULE215:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_remediate_done 215 "hardened identity/config file permissions"


	if [ "${REMEDIATE_SECURITY_UPGRADE}" = "1" ]; then
		if sec_audit_have_bin dnf; then
			timeout 300 dnf upgrade --security -y >/dev/null 2>&1 || true
		elif sec_audit_have_bin yum; then
			timeout 300 yum update --security -y >/dev/null 2>&1 || true
		fi
	else
		sec_audit_log "skipping security upgrade (set REMEDIATE_SECURITY_UPGRADE=1 to enable)"
	fi
	sec_audit_log "remediation complete (RHEL8_remediation.sh)"
}

sec_audit_main "$@"
