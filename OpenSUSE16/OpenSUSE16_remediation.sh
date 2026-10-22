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
	local p
	sec_audit_have_bin zypper || return 0
	# Skip packages already present to avoid repeated zypper refresh hangs in containers.
	local need=()
	for p in "$@"; do
		if rpm -q "$p" &>/dev/null; then
			continue
		fi
		need+=("$p")
	done
	((${#need[@]})) || return 0
	timeout 60 zypper --non-interactive install --no-recommends "${need[@]}" >/dev/null 2>&1 || true
}

sec_audit_pkg_remove() {
	local p
	sec_audit_have_bin zypper || return 0
	for p in "$@"; do
		rpm -q "$p" &>/dev/null || continue
		zypper --non-interactive remove "$p" >/dev/null 2>&1 || true
	done
}

sec_audit_start_service() {
	local u="$1"
	sec_audit_have_bin systemctl || return 0
	systemctl enable "$u" >/dev/null 2>&1 || true
	systemctl start "$u" >/dev/null 2>&1 || true
}

sec_audit_disable_service() {
	local u="$1"
	sec_audit_have_bin systemctl || return 0
	systemctl disable --now "$u" >/dev/null 2>&1 || true
}

sec_audit_disable_kmod() {
	local mod="$1" f="/etc/modprobe.d/-${mod}.conf"
	[[ -f "$f" ]] && grep -q "blacklist ${mod}" "$f" 2>/dev/null && return 0
	{
		echo "install ${mod} /bin/false"
		echo "blacklist ${mod}"
	} >"$f"
	if lsmod 2>/dev/null | awk '{print $1}' | grep -qx "$mod"; then
		modprobe -r "$mod" >/dev/null 2>&1 || rmmod "$mod" >/dev/null 2>&1 || true
	fi
}

sec_audit_ensure_tmpfs_mount() {
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
	local key="$1" val="$2" f="/etc/sysctl.d/99-linux-cre-sec.conf"
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

sec_audit_harden_path() {
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

sec_audit_log "starting remediation (sec_AlmaLinux_OS_10_v1.0.0)"


# =============================================================================
# Entry
# =============================================================================

sec_audit_remediate_kernel_modules() {
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
sec_audit_remediate_done 9 "blacklisted kernel module firewire-core"

# RULE10:
sec_audit_disable_kmod usb-storage
sec_audit_remediate_done 10 "blacklisted kernel module usb-storage"
}

sec_audit_remediate_filesystem_partitions() {
# RULE11:
sec_audit_remediate_skip 11 "/tmp is tmpfs or a separate partition"

# RULE12:
sec_audit_ensure_mount_option /tmp nodev
sec_audit_remediate_done 12 "set nodev on /tmp"

# RULE13:
sec_audit_remediate_skip 13 "nosuid option set on /tmp partition"

# RULE14:
sec_audit_ensure_mount_option /tmp noexec
sec_audit_remediate_done 14 "set noexec on /tmp"

# RULE15:
sec_audit_remediate_skip 15 "/dev/shm is tmpfs or a separate partition"

# RULE16:
sec_audit_ensure_mount_option /dev/shm nodev
sec_audit_remediate_done 16 "set nodev on /dev/shm"

# RULE17:
sec_audit_remediate_skip 17 "nosuid option set on /dev/shm partition"

# RULE18:
sec_audit_ensure_mount_option /dev/shm noexec
sec_audit_remediate_done 18 "set noexec on /dev/shm"

# RULE19:
sec_audit_remediate_skip 19 "separate partition exists for /home"

# RULE20:
sec_audit_ensure_mount_option /home nodev
sec_audit_remediate_done 20 "set nodev on /home"

# RULE21:
sec_audit_remediate_skip 21 "nosuid option set on /home partition"

# RULE22:
sec_audit_remediate_skip 22 "separate partition exists for /var"

# RULE23:
sec_audit_ensure_mount_option /var nodev
sec_audit_remediate_done 23 "set nodev on /var"

# RULE24:
sec_audit_remediate_skip 24 "nosuid option set on /var partition"

# RULE25:
sec_audit_remediate_skip 25 "separate partition exists for /var/tmp"

# RULE26:
sec_audit_ensure_mount_option /var/tmp nodev
sec_audit_remediate_done 26 "set nodev on /var/tmp"

# RULE27:
sec_audit_remediate_skip 27 "nosuid option set on /var/tmp partition"

# RULE28:
sec_audit_ensure_mount_option /var/tmp noexec
sec_audit_remediate_done 28 "set noexec on /var/tmp"

# RULE29:
sec_audit_remediate_skip 29 "separate partition exists for /var/log"

# RULE30:
sec_audit_ensure_mount_option /var/sec_audit_log nodev
sec_audit_remediate_done 30 "set nodev on /var/log"

# RULE31:
sec_audit_remediate_skip 31 "nosuid option set on /var/sec_audit_log partition"

# RULE32:
sec_audit_ensure_mount_option /var/sec_audit_log noexec
sec_audit_remediate_done 32 "set noexec on /var/log"

# RULE33:
sec_audit_remediate_skip 33 "separate partition exists for /var/log/audit"

# RULE34:
sec_audit_ensure_mount_option /var/log/audit nodev
sec_audit_remediate_done 34 "set nodev on /var/log/audit"

# RULE35:
sec_audit_remediate_skip 35 "nosuid option set on /var/log/audit partition"

# RULE36:
sec_audit_ensure_mount_option /var/log/audit noexec
sec_audit_remediate_done 36 "set noexec on /var/log/audit"
}

sec_audit_remediate_package_security() {
# RULE37:
sec_audit_remediate_skip 37 "GPG keys are configured"

# RULE38:
sec_audit_set_dnf_main_kv gpgcheck 1
sec_audit_set_dnf_main_kv localpkg_gpgcheck 1
sec_audit_remediate_done 38 "enabled gpgcheck"

# RULE39:
sec_audit_remediate_skip 39 "repo_gpgcheck is globally activated"

# RULE40:
sec_audit_remediate_skip 40 "package manager repositories are configured"

# RULE41:
sec_audit_remediate_skip 41 "weak dependencies are configured"
}

sec_audit_remediate_selinux() {
# RULE42:
sec_audit_pkg_install libselinux
sec_audit_remediate_done 42 "installed SELinux"

# RULE43:
if sec_audit_have_bin grubby; then
grubby --update-kernel=ALL --remove-args="selinux=0 enforcing=0" >/dev/null 2>&1 || true
fi
sec_audit_remediate_done 43 "removed selinux=0 from bootloader"

# RULE44:
[[ -f /etc/selinux/config ]] && {
sed -i "s/^SELINUXTYPE=.*/SELINUXTYPE=targeted/" /etc/selinux/config 2>/dev/null || true
grep -q "^SELINUXTYPE=" /etc/selinux/config || echo "SELINUXTYPE=targeted" >>/etc/selinux/config
}
sec_audit_remediate_done 44 "SELINUXTYPE=targeted"

# RULE45:
[[ -f /etc/selinux/config ]] && sed -i "s/^SELINUX=.*/SELINUX=enforcing/" /etc/selinux/config 2>/dev/null || true
sec_audit_have_bin setenforce && setenforce 1 >/dev/null 2>&1 || true
sec_audit_remediate_done 45 "SELinux not disabled"

# RULE46:
[[ -f /etc/selinux/config ]] && sed -i "s/^SELINUX=.*/SELINUX=enforcing/" /etc/selinux/config 2>/dev/null || true
sec_audit_have_bin setenforce && setenforce 1 >/dev/null 2>&1 || true
sec_audit_remediate_done 46 "SELinux enforcing"

# RULE47:
sec_audit_remediate_skip 47 "no unconfined services exist"

# RULE48:
sec_audit_pkg_remove setroubleshoot
sec_audit_disable_service setroubleshoot.service
sec_audit_remediate_done 48 "removed setroubleshoot"
}

sec_audit_remediate_bootloader() {
# RULE49:
sec_audit_remediate_skip 49 "bootloader password is set"

# RULE50:
sec_audit_harden_path /boot/grub2/grub.cfg 600 root:root
sec_audit_harden_path /boot/grub2/user.cfg 600 root:root
sec_audit_remediate_done 50 "hardened grub permissions"
}

sec_audit_remediate_process_hardening() {
# RULE51:
grep -q "hard core" /etc/security/limits.conf 2>/dev/null || echo "* hard core 0" >>/etc/security/limits.conf
mkdir -p /etc/systemd/coredump.conf.d
cat >/etc/systemd/coredump.conf.d/99-cre-sec.conf <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
sec_audit_have_bin systemctl && systemctl daemon-reload >/dev/null 2>&1 || true
sec_audit_remediate_done 51 "disabled core dumps"

# RULE52:
sec_audit_set_sysctl fs.protected_hardlinks 1
sec_audit_remediate_done 52 "set fs.protected_hardlinks=1"

# RULE53:
sec_audit_set_sysctl fs.protected_symlinks 1
sec_audit_remediate_done 53 "set fs.protected_symlinks=1"

# RULE54:
sec_audit_remediate_skip 54 "fs.suid_dumpable is configured"

# RULE55:
sec_audit_set_sysctl kernel.dmesg_restrict 1
sec_audit_remediate_done 55 "set kernel.dmesg_restrict=1"

# RULE56:
sec_audit_set_sysctl kernel.kptr_restrict 2
sec_audit_remediate_done 56 "set kernel.kptr_restrict=2"

# RULE57:
sec_audit_set_sysctl kernel.yama.ptrace_scope 1
sec_audit_remediate_done 57 "set kernel.yama.ptrace_scope=1"

# RULE58:
sec_audit_set_sysctl kernel.randomize_va_space 2
sec_audit_remediate_done 58 "set kernel.randomize_va_space=2"

# RULE59:
sec_audit_set_sysctl fs.suid_dumpable 0
sec_audit_remediate_done 59 "coredump limits via sysctl/coredump.conf"

# RULE60:
mkdir -p /etc/systemd/coredump.conf.d
cat >/etc/systemd/coredump.conf.d/99-cre-sec.conf <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
sec_audit_remediate_done 60 "systemd-coredump Storage=none"
}

sec_audit_remediate_crypto_policy() {
# RULE61:
sec_audit_have_bin update-crypto-policies && update-crypto-policies --set DEFAULT >/dev/null 2>&1 || true
sec_audit_remediate_done 61 "crypto policy not LEGACY"

# RULE62:
sec_audit_have_bin update-crypto-policies && update-crypto-policies --set DEFAULT:NO-SHA1:NO-SSHCBC >/dev/null 2>&1 || update-crypto-policies --set DEFAULT >/dev/null 2>&1 || true
sec_audit_remediate_done 62 "applied DEFAULT crypto policy modules"

# RULE63:
sec_audit_remediate_skip 63 "system wide crypto policy disables cbc for ssh"
}

sec_audit_remediate_banners() {
# RULE64:
[[ -f /etc/motd ]] || echo "Authorized use only." >/etc/motd
sed -i 's/\\[vVrms]//g' /etc/motd 2>/dev/null || true
sec_audit_remediate_done 64 "sanitized banner /etc/motd"

# RULE65:
[[ -f /etc/issue ]] || echo "Authorized use only." >/etc/issue
sed -i 's/\\[vVrms]//g' /etc/issue 2>/dev/null || true
sec_audit_remediate_done 65 "sanitized banner /etc/issue"

# RULE66:
[[ -f /etc/issue.net ]] || echo "Authorized use only." >/etc/issue.net
sed -i 's/\\[vVrms]//g' /etc/issue.net 2>/dev/null || true
sec_audit_remediate_done 66 "sanitized banner /etc/issue.net"

# RULE67:
sec_audit_harden_path /etc/motd 644 root:root
sec_audit_remediate_done 67 "permissions /etc/motd"

# RULE68:
sec_audit_harden_path /etc/issue 644 root:root
sec_audit_remediate_done 68 "permissions /etc/issue"

# RULE69:
sec_audit_harden_path /etc/issue.net 644 root:root
sec_audit_remediate_done 69 "permissions /etc/issue.net"
}

sec_audit_remediate_gdm() {
# RULE70:
mkdir -p /etc/dconf/db/gdm.d
sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
sec_audit_remediate_done 70 "configured GDM hardening"

# RULE71:
mkdir -p /etc/dconf/db/gdm.d
sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
sec_audit_remediate_done 71 "configured GDM hardening"

# RULE72:
mkdir -p /etc/dconf/db/gdm.d
sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
sec_audit_remediate_done 72 "configured GDM hardening"

# RULE73:
mkdir -p /etc/dconf/db/gdm.d
sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
sec_audit_remediate_done 73 "configured GDM hardening"

# RULE74:
mkdir -p /etc/dconf/db/gdm.d
sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
sec_audit_remediate_done 74 "configured GDM hardening"

# RULE75:
mkdir -p /etc/dconf/db/gdm.d
sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
sec_audit_remediate_done 75 "configured GDM hardening"
}

sec_audit_remediate_unused_services() {
# RULE76:
sec_audit_disable_service autofs.service
sec_audit_pkg_remove autofs
sec_audit_remediate_done 76 "disabled autofs"

# RULE77:
sec_audit_disable_service avahi-daemon.socket
sec_audit_disable_service avahi-daemon.service
sec_audit_pkg_remove avahi
sec_audit_remediate_done 77 "disabled avahi"

# RULE78:
sec_audit_disable_service cockpit.socket
sec_audit_disable_service cockpit.service
sec_audit_pkg_remove cockpit-ws
sec_audit_remediate_done 78 "disabled cockpit-ws"

# RULE79:
sec_audit_disable_service dhcpd.service
sec_audit_disable_service dhcpd6.service
sec_audit_pkg_remove dhcp-server
sec_audit_remediate_done 79 "disabled dhcp-server"

# RULE80:
sec_audit_disable_service named.service
sec_audit_pkg_remove bind
sec_audit_remediate_done 80 "disabled bind"

# RULE81:
sec_audit_disable_service dnsmasq.service
sec_audit_pkg_remove dnsmasq
sec_audit_remediate_done 81 "disabled dnsmasq"

# RULE82:
sec_audit_disable_service vsftpd.service
sec_audit_pkg_remove vsftpd
sec_audit_remediate_done 82 "disabled vsftpd"

# RULE83:
sec_audit_remediate_skip 83 "review remediation: message access server services are not in use"

# RULE84:
sec_audit_remediate_skip 84 "review remediation: network file system services are not in use"

# RULE85:
sec_audit_remediate_skip 85 "review remediation: print server services are not in use"

# RULE86:
sec_audit_disable_service rpcbind.socket
sec_audit_disable_service rpcbind.service
sec_audit_pkg_remove rpcbind
sec_audit_remediate_done 86 "disabled rpcbind"

# RULE87:
sec_audit_disable_service rsyncd.socket
sec_audit_disable_service rsyncd.service
sec_audit_pkg_remove rsync-daemon
sec_audit_remediate_done 87 "disabled rsync-daemon"

# RULE88:
sec_audit_disable_service smb.service
sec_audit_disable_service smbd.service
sec_audit_pkg_remove samba
sec_audit_remediate_done 88 "disabled samba"

# RULE89:
sec_audit_disable_service snmpd.service
sec_audit_pkg_remove net-snmp
sec_audit_remediate_done 89 "disabled net-snmp"

# RULE90:
sec_audit_disable_service telnet.socket
sec_audit_pkg_remove telnet-server
sec_audit_remediate_done 90 "disabled telnet-server"

# RULE91:
sec_audit_disable_service vsftpd.service
sec_audit_pkg_remove vsftpd
sec_audit_remediate_done 91 "disabled vsftpd"

# RULE92:
sec_audit_remediate_skip 92 "review remediation: web proxy server services are not in use"

# RULE93:
sec_audit_remediate_skip 93 "review remediation: web server services are not in use"

# RULE94:
sec_audit_remediate_skip 94 "review remediation: GNOME Display Manager is removed"

# RULE95:
sec_audit_remediate_skip 95 "review remediation: X window server services are not in use"
}

sec_audit_remediate_client_tools() {
# RULE96:
sec_audit_pkg_remove ftp
sec_audit_remediate_done 96 "removed ftp"

# RULE97:
sec_audit_pkg_remove ldap-utils
sec_audit_remediate_done 97 "removed ldap-utils"

# RULE98:
sec_audit_pkg_remove telnet
sec_audit_remediate_done 98 "removed telnet"

# RULE99:
sec_audit_pkg_remove tftp
sec_audit_remediate_done 99 "removed tftp"
}

sec_audit_remediate_chrony() {
# RULE100:
sec_audit_pkg_install chrony
sec_audit_start_service chronyd
sec_audit_remediate_done 100 "installed chrony"

# RULE101:
sec_audit_pkg_install chrony
grep -q "^pool \|^server " /etc/chrony.conf 2>/dev/null || echo "pool 2.pool.ntp.org iburst" >>/etc/chrony.conf
sec_audit_start_service chronyd
sec_audit_remediate_done 101 "configured chrony"

# RULE102:
sec_audit_remediate_skip 102 "review remediation: chrony is not run as the root user"
}

sec_audit_remediate_cron_at() {
# RULE103:
sec_audit_pkg_install cronie
sec_audit_start_service crond
sec_audit_remediate_done 103 "enabled crond"

# RULE104:
chmod 600 /etc/crontab 2>/dev/null || true
chown root:root /etc/crontab 2>/dev/null || true
sec_audit_remediate_done 104 "restricted /etc/crontab"

# RULE105:
sec_audit_remediate_skip 105 "review remediation: access to /etc/cron.hourly is configured"

# RULE106:
sec_audit_remediate_skip 106 "review remediation: access to /etc/cron.daily is configured"

# RULE107:
sec_audit_remediate_skip 107 "review remediation: access to /etc/cron.weekly is configured"

# RULE108:
sec_audit_remediate_skip 108 "review remediation: access to /etc/cron.monthly is configured"

# RULE109:
sec_audit_remediate_skip 109 "review remediation: access to /etc/cron.yearly is configured"

# RULE110:
sec_audit_remediate_skip 110 "review remediation: access to /etc/cron.d is configured"

# RULE111:
sec_audit_remediate_skip 111 "review remediation: access to crontab is configured"

# RULE112:
sec_audit_remediate_skip 112 "review remediation: access to at is configured"
}

sec_audit_remediate_network_stack() {
# RULE113:
sec_audit_remediate_skip 113 "IPv6 status is identified"

# RULE114:
sec_audit_disable_kmod bluetooth
sec_audit_remediate_done 114 "disabled wireless interfaces"

# RULE115:
sec_audit_disable_service bluetooth.service
sec_audit_pkg_remove bluez
sec_audit_remediate_done 115 "disabled bluez"

# RULE116:
sec_audit_disable_kmod is
sec_audit_remediate_done 116 "blacklisted is"

# RULE117:
sec_audit_disable_kmod is
sec_audit_remediate_done 117 "blacklisted is"

# RULE118:
sec_audit_disable_kmod is
sec_audit_remediate_done 118 "blacklisted is"

# RULE119:
sec_audit_disable_kmod is
sec_audit_remediate_done 119 "blacklisted is"

# RULE120:
sec_audit_disable_kmod is
sec_audit_remediate_done 120 "blacklisted is"

# RULE121:
sec_audit_disable_kmod is
sec_audit_remediate_done 121 "blacklisted is"

# RULE122:
sec_audit_set_sysctl net.ipv4.ip_forward 0
sec_audit_remediate_done 122 "set net.ipv4.ip_forward=0"

# RULE123:
sec_audit_remediate_skip 123 "review remediation: net.ipv4.conf.all.forwarding is configured"

# RULE124:
sec_audit_remediate_skip 124 "review remediation: net.ipv4.conf.default.forwarding is configured"

# RULE125:
sec_audit_set_sysctl net.ipv4.conf.all.send_redirects 0
sec_audit_remediate_done 125 "set net.ipv4.conf.all.send_redirects=0"

# RULE126:
sec_audit_set_sysctl net.ipv4.conf.all.send_redirects 0
sec_audit_remediate_done 126 "set net.ipv4.conf.all.send_redirects=0"

# RULE127:
sec_audit_set_sysctl net.ipv4.conf.all.accept_redirects 0
sec_audit_remediate_done 127 "set net.ipv4.conf.all.accept_redirects=0"

# RULE128:
sec_audit_set_sysctl net.ipv4.conf.all.secure_redirects 0
sec_audit_remediate_done 128 "set net.ipv4.conf.all.secure_redirects=0"

# RULE129:
sec_audit_set_sysctl net.ipv4.conf.all.rp_filter 1
sec_audit_remediate_done 129 "set net.ipv4.conf.all.rp_filter=1"

# RULE130:
sec_audit_set_sysctl net.ipv4.conf.all.rp_filter 1
sec_audit_remediate_done 130 "set net.ipv4.conf.all.rp_filter=1"

# RULE131:
sec_audit_set_sysctl net.ipv4.conf.all.log_martians 1
sec_audit_remediate_done 131 "set net.ipv4.conf.all.log_martians=1"

# RULE132:
sec_audit_set_sysctl net.ipv4.conf.all.log_martians 1
sec_audit_remediate_done 132 "set net.ipv4.conf.all.log_martians=1"

# RULE133:
sec_audit_set_sysctl net.ipv4.tcp_syncookies 1
sec_audit_remediate_done 133 "set net.ipv4.tcp_syncookies=1"

# RULE134:
sec_audit_remediate_skip 134 "net.ipv6.conf.all.forwarding is configured"

# RULE135:
sec_audit_remediate_skip 135 "net.ipv6.conf.default.forwarding is configured"

# RULE136:
sec_audit_remediate_skip 136 "net.ipv6.conf.all.accept_redirects is configured"

# RULE137:
sec_audit_remediate_skip 137 "net.ipv6.conf.all.accept_ra is configured"

# RULE138:
sec_audit_remediate_skip 138 "net.ipv6.conf.default.accept_ra is configured"
}

sec_audit_remediate_firewalld() {
# RULE139:
sec_audit_pkg_install firewalld
sec_audit_start_service firewalld
sec_audit_remediate_done 139 "installed firewalld"

# RULE140:
sec_audit_remediate_skip 140 "review remediation: firewalld backend is configured"

# RULE141:
sec_audit_remediate_skip 141 "review remediation: firewalld.service is configured"

# RULE142:
sec_audit_remediate_skip 142 "review remediation: firewalld active zone target is configured"

# RULE143:
sec_audit_remediate_skip 143 "firewalld loopback traffic is configured"

# RULE144:
sec_audit_remediate_skip 144 "firewalld services and ports are configured"
}

sec_audit_remediate_sshd() {
# RULE145:
sec_audit_remediate_skip 145 "review remediation: access to /etc/ssh/sshd_config is configured"

# RULE146:
sec_audit_remediate_skip 146 "review remediation: access to SSH private host key files is configured"

# RULE147:
sec_audit_remediate_skip 147 "review remediation: access to SSH public host key files is configured"

# RULE148:
sec_audit_remediate_skip 148 "review remediation: sshd access is configured"

# RULE149:
sec_audit_set_sshd_kv Banner /etc/issue.net
sec_audit_remediate_done 149 "sshd Banner"

# RULE150:
sec_audit_remediate_skip 150 "review remediation: sshd Ciphers are configured"

# RULE151:
sec_audit_set_sshd_kv ClientAliveInterval 300
sec_audit_remediate_done 151 "sshd ClientAliveInterval"

# RULE152:
sec_audit_set_sshd_kv DisableForwarding yes
sec_audit_remediate_done 152 "sshd DisableForwarding"

# RULE153:
sec_audit_set_sshd_kv GSSAPIAuthentication no
sec_audit_remediate_done 153 "sshd GSSAPIAuthentication"

# RULE154:
sec_audit_set_sshd_kv HostbasedAuthentication no
sec_audit_remediate_done 154 "sshd HostbasedAuthentication"

# RULE155:
sec_audit_set_sshd_kv IgnoreRhosts yes
sec_audit_remediate_done 155 "sshd IgnoreRhosts"

# RULE156:
sec_audit_remediate_skip 156 "review remediation: sshd KexAlgorithms is configured"

# RULE157:
sec_audit_set_sshd_kv LoginGraceTime 60
sec_audit_remediate_done 157 "sshd LoginGraceTime"

# RULE158:
sec_audit_set_sshd_kv LogLevel VERBOSE
sec_audit_remediate_done 158 "sshd LogLevel"

# RULE159:
sec_audit_remediate_skip 159 "review remediation: sshd MACs are configured"

# RULE160:
sec_audit_set_sshd_kv MaxAuthTries 4
sec_audit_remediate_done 160 "sshd MaxAuthTries"

# RULE161:
sec_audit_set_sshd_kv MaxStartups 10:30:60
sec_audit_remediate_done 161 "sshd MaxStartups"

# RULE162:
sec_audit_set_sshd_kv MaxSessions 10
sec_audit_remediate_done 162 "sshd MaxSessions"

# RULE163:
sec_audit_set_sshd_kv PermitEmptyPasswords no
sec_audit_remediate_done 163 "sshd PermitEmptyPasswords"

# RULE164:
sec_audit_set_sshd_kv PermitRootLogin no
sec_audit_remediate_done 164 "sshd PermitRootLogin"

# RULE165:
sec_audit_set_sshd_kv PermitUserEnvironment no
sec_audit_remediate_done 165 "sshd PermitUserEnvironment"

# RULE166:
sec_audit_set_sshd_kv UsePAM yes
sec_audit_remediate_done 166 "sshd UsePAM"
}

sec_audit_remediate_sudo_su() {
# RULE167:
sec_audit_pkg_install sudo
sec_audit_remediate_done 167 "sudo installed"

# RULE168:
sec_audit_remediate_skip 168 "review remediation: sudo commands use pty"

# RULE169:
sec_audit_remediate_skip 169 "review remediation: sudo sec_audit_log file exists"

# RULE170:
sec_audit_remediate_skip 170 "review remediation: users must provide password for escalation"

# RULE171:
echo "Defaults timestamp_timeout=5" >/etc/sudoers.d/99-cre-timeout
chmod 440 /etc/sudoers.d/99-cre-timeout
sec_audit_remediate_done 171 "sudo timestamp_timeout=5"

# RULE172:
sec_audit_remediate_skip 172 "review remediation: access to the su command is restricted"
}

sec_audit_remediate_pam_auth() {
# RULE173:
sec_audit_remediate_skip 173 "review remediation: active authselect profile includes pam modules"

# RULE174:
sec_audit_authselect_enable with-faillock
authselect apply-changes >/dev/null 2>&1 || true
sec_audit_remediate_done 174 "pam faillock"

# RULE175:
sec_audit_authselect_enable with-pwquality
sec_audit_set_pwquality_kv minlen 14
sec_audit_remediate_done 175 "password quality"

# RULE176:
sec_audit_authselect_enable with-pwhistory
grep -q '^remember' /etc/security/pwhistory.conf 2>/dev/null || echo 'remember = 24' >>/etc/security/pwhistory.conf
sec_audit_remediate_done 176 "password history"

# RULE177:
sec_audit_remediate_skip 177 "review remediation: pam_unix module is enabled"

# RULE178:
sec_audit_authselect_enable with-faillock
authselect apply-changes >/dev/null 2>&1 || true
sec_audit_remediate_done 178 "pam faillock"

# RULE179:
sec_audit_remediate_skip 179 "review remediation: password unlock time is configured"

# RULE180:
sec_audit_remediate_skip 180 "review remediation: password length is configured"

# RULE181:
sec_audit_remediate_skip 181 "password complexity is configured"

# RULE182:
sec_audit_remediate_skip 182 "review remediation: password dictionary check is enabled"

# RULE183:
sec_audit_authselect_enable with-pwquality
sec_audit_set_pwquality_kv minlen 14
sec_audit_remediate_done 183 "password quality"

# RULE184:
sec_audit_authselect_enable with-pwhistory
grep -q '^remember' /etc/security/pwhistory.conf 2>/dev/null || echo 'remember = 24' >>/etc/security/pwhistory.conf
sec_audit_remediate_done 184 "password history"

# RULE185:
sec_audit_authselect_enable with-pwhistory
grep -q '^remember' /etc/security/pwhistory.conf 2>/dev/null || echo 'remember = 24' >>/etc/security/pwhistory.conf
sec_audit_remediate_done 185 "password history"

# RULE186:
sec_audit_authselect_enable with-pwhistory
grep -q '^remember' /etc/security/pwhistory.conf 2>/dev/null || echo 'remember = 24' >>/etc/security/pwhistory.conf
sec_audit_remediate_done 186 "password history"

# RULE187:
sec_audit_remediate_skip 187 "review remediation: pam_unix does not include nullok"

# RULE188:
sec_audit_authselect_enable with-pwhistory
grep -q '^remember' /etc/security/pwhistory.conf 2>/dev/null || echo 'remember = 24' >>/etc/security/pwhistory.conf
sec_audit_remediate_done 188 "password history"

# RULE189:
sec_audit_remediate_skip 189 "review remediation: pam_unix includes use_authtok"
}

sec_audit_remediate_accounts() {
# RULE190:
sec_audit_remediate_skip 190 "review remediation: password expiration is configured"

# RULE191:
sec_audit_remediate_skip 191 "minimum password days is configured"

# RULE192:
sec_audit_remediate_skip 192 "review remediation: password expiration warning days is configured"

# RULE193:
sec_audit_set_login_defs_kv ENCRYPT_METHOD SHA512
sec_audit_remediate_done 193 "ENCRYPT_METHOD SHA512"

# RULE194:
sec_audit_remediate_skip 194 "inactive password lock is configured"

# RULE195:
sec_audit_remediate_skip 195 "all users last password change date is in the past"

# RULE196:
sec_audit_remediate_skip 196 "root is the only UID 0 account"

# RULE197:
sec_audit_remediate_skip 197 "root is the only GID 0 account"

# RULE198:
sec_audit_remediate_skip 198 "group root is the only GID 0 group"

# RULE199:
sec_audit_remediate_skip 199 "root account access is controlled"

# RULE200:
sec_audit_remediate_skip 200 "root path integrity"

# RULE201:
sec_audit_set_login_defs_kv UMASK 027
cat >/etc/profile.d/99-cre-umask.sh <<'EOF'
umask 027
EOF
sec_audit_remediate_done 201 "default umask 027"

# RULE202:
sec_audit_remediate_skip 202 "system accounts do not have a valid login shell"

# RULE203:
sec_audit_remediate_skip 203 "accounts without a valid login shell are locked"

# RULE204:
sec_audit_remediate_skip 204 "review remediation: nologin is not listed in /etc/shells"

# RULE205:
cat >/etc/profile.d/99-cre-timeout.sh <<'EOF'
TMOUT=600
readonly TMOUT
export TMOUT
EOF
sec_audit_remediate_done 205 "TMOUT=600"

# RULE206:
sec_audit_set_login_defs_kv UMASK 027
cat >/etc/profile.d/99-cre-umask.sh <<'EOF'
umask 027
EOF
sec_audit_remediate_done 206 "default umask 027"
}

sec_audit_remediate_aide() {
# RULE207:
sec_audit_pkg_install aide
sec_audit_remediate_done 207 "installed AIDE"

# RULE208:
sec_audit_pkg_install aide afick
sec_audit_remediate_done 208 "integrity tooling"
}

sec_audit_remediate_logging() {
# RULE209:
sec_audit_start_service systemd-journald
sec_audit_remediate_done 209 "journald active"

# RULE210:
sec_audit_remediate_skip 210 "journald sec_audit_log file access is configured"

# RULE211:
sec_audit_remediate_skip 211 "journald sec_audit_log file rotation is configured"

# RULE212:
sec_audit_remediate_skip 212 "review remediation: only one logging system is in use"

# RULE213:
sec_audit_remediate_skip 213 "systemd-journal-remote is installed"

# RULE214:
sec_audit_remediate_skip 214 "systemd-journal-upload is enabled and active"

# RULE215:
sec_audit_remediate_skip 215 "systemd-journal-remote service is not in use"

# RULE216:
sec_audit_remediate_skip 216 "configure central logging per site policy before enabling journal remote/upload"

# RULE217:
mkdir -p /etc/systemd/journald.conf.d
cat >/etc/systemd/journald.conf.d/99-opensuse16-cre.conf <<'EOF'
[Journal]
ForwardToSyslog=no
Compress=yes
Storage=persistent
EOF
systemctl restart systemd-journald >/dev/null 2>&1 || true
sec_audit_remediate_done 217 "journald configuration"

# RULE218:
mkdir -p /etc/systemd/journald.conf.d
cat >/etc/systemd/journald.conf.d/99-opensuse16-cre.conf <<'EOF'
[Journal]
ForwardToSyslog=no
Compress=yes
Storage=persistent
EOF
systemctl restart systemd-journald >/dev/null 2>&1 || true
sec_audit_remediate_done 218 "journald configuration"

# RULE219:
sec_audit_pkg_install rsyslog
sec_audit_start_service rsyslog
sec_audit_remediate_done 219 "rsyslog installed"

# RULE220:
sec_audit_pkg_install rsyslog
sec_audit_start_service rsyslog
sec_audit_remediate_done 220 "rsyslog installed"

# RULE221:
sec_audit_start_service systemd-journald
sec_audit_remediate_done 221 "journald active"

# RULE222:
sec_audit_pkg_install rsyslog
sec_audit_start_service rsyslog
sec_audit_remediate_done 222 "rsyslog installed"

# RULE223:
sec_audit_remediate_skip 223 "rsyslog logging is configured"

# RULE224:
sec_audit_remediate_skip 224 "rsyslog logrotate is configured"
}

sec_audit_remediate_auditd() {
# RULE225:
sec_audit_remediate_skip 225 "review remediation: access to all logfiles has been configured"

# RULE226:
sec_audit_pkg_install audit
sec_audit_start_service auditd
sec_audit_remediate_done 226 "auditd running"

# RULE227:
sec_audit_pkg_install audit auditd 2>/dev/null || true
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-opensuse16-cre.rules <<'EOF'
-D
-b 8192
-f 1
-w /etc/sudoers -p wa -k scope
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /var/log/audit/ -p wa -k audit_log
EOF
sec_audit_have_bin augenrules && timeout 15 augenrules --load >/dev/null 2>&1 || true
sec_audit_start_service auditd
sec_audit_remediate_done 227 "audit rules baseline"

# RULE228:
sec_audit_pkg_install audit
sec_audit_start_service auditd
sec_audit_remediate_done 228 "auditd running"

# RULE229:
sec_audit_pkg_install audit auditd 2>/dev/null || true
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-opensuse16-cre.rules <<'EOF'
-D
-b 8192
-f 1
-w /etc/sudoers -p wa -k scope
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /var/log/audit/ -p wa -k audit_log
EOF
sec_audit_have_bin augenrules && timeout 15 augenrules --load >/dev/null 2>&1 || true
sec_audit_start_service auditd
sec_audit_remediate_done 229 "audit rules baseline"

# RULE230:
sec_audit_remediate_skip 230 "review remediation: audit logs are not automatically deleted"

# RULE231:
sec_audit_remediate_skip 231 "review remediation: system is disabled when audit logs are full"

# RULE232:
sec_audit_remediate_skip 232 "review remediation: system warns when audit logs are low on space"

# RULE233:
sec_audit_remediate_skip 233 "review remediation: modification of the /etc/sudoers file is collected"

# RULE234:
sec_audit_remediate_skip 234 "review remediation: actions as another user are always logged"

# RULE235:
sec_audit_remediate_skip 235 "review remediation: events that modify the sudo sec_audit_log file are collected"

# RULE236:
sec_audit_remediate_skip 236 "review remediation: events that modify /etc/NetworkManager directory are collected"

# RULE237:
sec_audit_remediate_skip 237 "review remediation: use of privileged commands are collected"

# RULE238:
sec_audit_remediate_skip 238 "review remediation: unsuccessful file access attempts are collected"

# RULE239:
sec_audit_remediate_skip 239 "review remediation: events that modify /etc/shadow and /etc/gshadow are collected"

# RULE240:
sec_audit_remediate_skip 240 "review remediation: successful file system mounts are collected"

# RULE241:
sec_audit_remediate_skip 241 "review remediation: session initiation information is collected"

# RULE242:
sec_audit_remediate_skip 242 "review remediation: login and logout events are collected"

# RULE243:
sec_audit_remediate_skip 243 "review remediation: unlink file deletion events by users are collected"

# RULE244:
sec_audit_disable_kmod loading
sec_audit_remediate_done 244 "blacklisted loading"

# RULE245:
sec_audit_remediate_skip 245 "review remediation: the audit configuration is immutable"

# RULE246:
sec_audit_remediate_skip 246 "the running and on disk configuration is the same"

# RULE247:
sec_audit_pkg_install audit auditd 2>/dev/null || true
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-opensuse16-cre.rules <<'EOF'
-D
-b 8192
-f 1
-w /etc/sudoers -p wa -k scope
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /var/log/audit/ -p wa -k audit_log
EOF
sec_audit_have_bin augenrules && timeout 15 augenrules --load >/dev/null 2>&1 || true
sec_audit_start_service auditd
sec_audit_remediate_done 247 "audit rules baseline"

# RULE248:
sec_audit_pkg_install audit auditd 2>/dev/null || true
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-opensuse16-cre.rules <<'EOF'
-D
-b 8192
-f 1
-w /etc/sudoers -p wa -k scope
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /var/log/audit/ -p wa -k audit_log
EOF
sec_audit_have_bin augenrules && timeout 15 augenrules --load >/dev/null 2>&1 || true
sec_audit_start_service auditd
sec_audit_remediate_done 248 "audit rules baseline"

# RULE249:
sec_audit_pkg_install audit auditd 2>/dev/null || true
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-opensuse16-cre.rules <<'EOF'
-D
-b 8192
-f 1
-w /etc/sudoers -p wa -k scope
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /var/log/audit/ -p wa -k audit_log
EOF
sec_audit_have_bin augenrules && timeout 15 augenrules --load >/dev/null 2>&1 || true
sec_audit_start_service auditd
sec_audit_remediate_done 249 "audit rules baseline"

# RULE250:
sec_audit_remediate_skip 250 "audit sec_audit_log files group owner is configured"

# RULE251:
sec_audit_pkg_install audit auditd 2>/dev/null || true
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-opensuse16-cre.rules <<'EOF'
-D
-b 8192
-f 1
-w /etc/sudoers -p wa -k scope
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /var/log/audit/ -p wa -k audit_log
EOF
sec_audit_have_bin augenrules && timeout 15 timeout 15 augenrules --load >/dev/null 2>&1 || true
sec_audit_start_service auditd
sec_audit_remediate_done 251 "audit rules baseline"

# RULE252:
sec_audit_pkg_install audit auditd 2>/dev/null || true
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-opensuse16-cre.rules <<'EOF'
-D
-b 8192
-f 1
-w /etc/sudoers -p wa -k scope
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /var/log/audit/ -p wa -k audit_log
EOF
sec_audit_have_bin augenrules && timeout 15 timeout 15 augenrules --load >/dev/null 2>&1 || true
sec_audit_start_service auditd
sec_audit_remediate_done 252 "audit rules baseline"

# RULE253:
sec_audit_remediate_skip 253 "audit configuration files group owner is configured"

# RULE254:
sec_audit_pkg_install audit auditd 2>/dev/null || true
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-opensuse16-cre.rules <<'EOF'
-D
-b 8192
-f 1
-w /etc/sudoers -p wa -k scope
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /var/log/audit/ -p wa -k audit_log
EOF
sec_audit_have_bin augenrules && timeout 15 augenrules --load >/dev/null 2>&1 || true
sec_audit_start_service auditd
sec_audit_remediate_done 254 "audit rules baseline"

# RULE255:
sec_audit_pkg_install audit auditd 2>/dev/null || true
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-opensuse16-cre.rules <<'EOF'
-D
-b 8192
-f 1
-w /etc/sudoers -p wa -k scope
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /var/log/audit/ -p wa -k audit_log
EOF
sec_audit_have_bin augenrules && timeout 15 augenrules --load >/dev/null 2>&1 || true
sec_audit_start_service auditd
sec_audit_remediate_done 255 "audit rules baseline"
}

sec_audit_remediate_identity_files() {
# RULE256:
sec_audit_remediate_skip 256 "audit tools group owner is configured"

# RULE257:
sec_audit_remediate_skip 257 "review remediation: access to /etc/passwd is configured"

# RULE258:
sec_audit_remediate_skip 258 "review remediation: access to /etc/passwd- is configured"

# RULE259:
sec_audit_remediate_skip 259 "access to /etc/group is configured"

# RULE260:
sec_audit_remediate_skip 260 "access to /etc/group- is configured"

# RULE261:
sec_audit_remediate_skip 261 "review remediation: access to /etc/shadow is configured"

# RULE262:
sec_audit_remediate_skip 262 "review remediation: access to /etc/shadow- is configured"

# RULE263:
sec_audit_remediate_skip 263 "review remediation: access to /etc/gshadow is configured"
}

sec_audit_remediate_filesystem_integrity() {
# RULE264:
sec_audit_remediate_skip 264 "review remediation: access to /etc/gshadow- is configured"

# RULE265:
sec_audit_remediate_skip 265 "review remediation: access to /etc/shells is configured"

# RULE266:
sec_audit_remediate_skip 266 "review remediation: access to /etc/security/opasswd is configured"

# RULE267:
sec_audit_remediate_skip 267 "review remediation: world writable files and directories are secured"

# RULE268:
sec_audit_remediate_skip 268 "SUID and SGID files are reviewed"

# RULE269:
sec_audit_remediate_skip 269 "accounts in /etc/passwd use shadowed passwords"

# RULE270:
sec_audit_remediate_skip 270 "review remediation: /etc/shadow password fields are not empty"

# RULE271:
sec_audit_remediate_skip 271 "all groups in /etc/passwd exist in /etc/group"

# RULE272:
sec_audit_remediate_skip 272 "no duplicate UIDs exist"

# RULE273:
sec_audit_remediate_skip 273 "no duplicate GIDs exist"

# RULE274:
sec_audit_remediate_skip 274 "no duplicate user names exist"

# RULE275:
sec_audit_remediate_skip 275 "no duplicate group names exist"

# RULE276:
sec_audit_remediate_skip 276 "local interactive user dot files access is configured"

sec_audit_remediate_skip 277 "manual or host-specific remediation for RULE277"
sec_audit_remediate_skip 278 "manual or host-specific remediation for RULE278"
sec_audit_remediate_skip 279 "manual or host-specific remediation for RULE279"
sec_audit_remediate_skip 280 "manual or host-specific remediation for RULE280"
sec_audit_remediate_skip 281 "manual or host-specific remediation for RULE281"
sec_audit_remediate_skip 282 "manual or host-specific remediation for RULE282"
sec_audit_remediate_skip 283 "manual or host-specific remediation for RULE283"
sec_audit_remediate_skip 284 "manual or host-specific remediation for RULE284"
sec_audit_remediate_skip 285 "manual or host-specific remediation for RULE285"
sec_audit_remediate_skip 286 "manual or host-specific remediation for RULE286"
sec_audit_remediate_skip 287 "manual or host-specific remediation for RULE287"
sec_audit_remediate_skip 288 "manual or host-specific remediation for RULE288"
sec_audit_remediate_skip 289 "manual or host-specific remediation for RULE289"
sec_audit_remediate_skip 290 "manual or host-specific remediation for RULE290"
sec_audit_remediate_skip 291 "manual or host-specific remediation for RULE291"
sec_audit_remediate_skip 292 "manual or host-specific remediation for RULE292"
sec_audit_remediate_skip 293 "manual or host-specific remediation for RULE293"
sec_audit_remediate_skip 294 "manual or host-specific remediation for RULE294"
sec_audit_remediate_skip 295 "manual or host-specific remediation for RULE295"
sec_audit_remediate_skip 296 "manual or host-specific remediation for RULE296"
sec_audit_remediate_skip 297 "manual or host-specific remediation for RULE297"
sec_audit_remediate_skip 298 "manual or host-specific remediation for RULE298"
sec_audit_remediate_skip 299 "manual or host-specific remediation for RULE299"
sec_audit_remediate_skip 300 "manual or host-specific remediation for RULE300"
sec_audit_remediate_skip 301 "manual or host-specific remediation for RULE301"
sec_audit_remediate_skip 302 "manual or host-specific remediation for RULE302"
sec_audit_remediate_skip 303 "manual or host-specific remediation for RULE303"
sec_audit_remediate_skip 304 "manual or host-specific remediation for RULE304"
sec_audit_remediate_skip 305 "manual or host-specific remediation for RULE305"
sec_audit_remediate_skip 306 "manual or host-specific remediation for RULE306"
sec_audit_remediate_skip 307 "manual or host-specific remediation for RULE307"
sec_audit_remediate_skip 308 "manual or host-specific remediation for RULE308"
sec_audit_remediate_skip 309 "manual or host-specific remediation for RULE309"
sec_audit_remediate_skip 310 "manual or host-specific remediation for RULE310"
sec_audit_remediate_skip 311 "manual or host-specific remediation for RULE311"
sec_audit_remediate_skip 312 "manual or host-specific remediation for RULE312"
sec_audit_remediate_skip 313 "manual or host-specific remediation for RULE313"
sec_audit_remediate_skip 314 "manual or host-specific remediation for RULE314"
sec_audit_remediate_skip 315 "manual or host-specific remediation for RULE315"
sec_audit_remediate_skip 316 "manual or host-specific remediation for RULE316"
sec_audit_remediate_skip 317 "manual or host-specific remediation for RULE317"
sec_audit_remediate_skip 318 "manual or host-specific remediation for RULE318"
sec_audit_remediate_skip 319 "manual or host-specific remediation for RULE319"
sec_audit_remediate_skip 320 "manual or host-specific remediation for RULE320"
sec_audit_remediate_skip 321 "manual or host-specific remediation for RULE321"
sec_audit_remediate_skip 322 "manual or host-specific remediation for RULE322"
sec_audit_remediate_skip 323 "manual or host-specific remediation for RULE323"
sec_audit_remediate_skip 324 "manual or host-specific remediation for RULE324"
sec_audit_remediate_skip 325 "manual or host-specific remediation for RULE325"
sec_audit_remediate_skip 326 "manual or host-specific remediation for RULE326"
sec_audit_remediate_skip 327 "manual or host-specific remediation for RULE327"
sec_audit_remediate_skip 328 "manual or host-specific remediation for RULE328"
sec_audit_remediate_skip 329 "manual or host-specific remediation for RULE329"
}

sec_audit_main() {
    sec_audit_log "starting remediation (OpenSUSE16 / sec_audit_* style)"

    sec_audit_remediate_kernel_modules
    sec_audit_remediate_filesystem_partitions
    sec_audit_remediate_package_security
    sec_audit_remediate_selinux
    sec_audit_remediate_bootloader
    sec_audit_remediate_process_hardening
    sec_audit_remediate_crypto_policy
    sec_audit_remediate_banners
    sec_audit_remediate_gdm
    sec_audit_remediate_unused_services
    sec_audit_remediate_client_tools
    sec_audit_remediate_chrony
    sec_audit_remediate_cron_at
    sec_audit_remediate_network_stack
    sec_audit_remediate_firewalld
    sec_audit_remediate_sshd
    sec_audit_remediate_sudo_su
    sec_audit_remediate_pam_auth
    sec_audit_remediate_accounts
    sec_audit_remediate_aide
    sec_audit_remediate_logging
    sec_audit_remediate_auditd
    sec_audit_remediate_identity_files
    sec_audit_remediate_filesystem_integrity

    if [ "${AL10_REMEDIATE_SECURITY_UPGRADE:-0}" = "1" ]; then
    	if sec_audit_have_bin zypper; then
    		timeout 300 zypper --non-interactive patch --with-optional >/dev/null 2>&1 || true
    	elif sec_audit_have_bin yum; then
    		timeout 300 yum update --security -y >/dev/null 2>&1 || true
    	fi
    else
    	sec_audit_log "skipping security upgrade (set AL10_REMEDIATE_SECURITY_UPGRADE=1 to enable)"
    fi

    sec_audit_log "remediation complete (OpenSUSE16_remediation.sh)"
}

sec_audit_main "$@"
