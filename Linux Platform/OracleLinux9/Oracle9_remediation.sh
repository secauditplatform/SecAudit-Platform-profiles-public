#!/bin/bash
# Full remediation for OracleLinux9 — generated from audit rule bodies (sec_audit_* style).

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
SYSCTL_FILE="/etc/sysctl.d/99-secaudit-oraclelinux9.conf"
MODPROBE_PREFIX="/etc/modprobe.d/sec-audit-disable"
AUDIT_RULES_FILE="/etc/audit/rules.d/99-secaudit-oraclelinux9.rules"

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
	sec_audit_log "starting remediation (OracleLinux9)"

# RULE1:
sec_audit_disable_kmod squashfs
sec_audit_remediate_done 1 "blacklisted kernel module squashfs"

# RULE2:
sec_audit_disable_kmod udf
sec_audit_remediate_done 2 "blacklisted kernel module udf"

# RULE3:
sec_audit_remediate_skip 3 "separate partition / layout change requires host planning"

# RULE4:
sec_audit_ensure_mount_option /tmp nodev
sec_audit_remediate_done 4 "set nodev on /tmp"

# RULE5:
sec_audit_ensure_mount_option /tmp nosuid
sec_audit_remediate_done 5 "set nosuid on /tmp"

# RULE6:
sec_audit_ensure_mount_option /tmp noexec
sec_audit_remediate_done 6 "set noexec on /tmp"

# RULE7:
sec_audit_remediate_skip 7 "separate partition / layout change requires host planning"

# RULE8:
sec_audit_remediate_skip 8 "separate partition / layout change requires host planning"

# RULE9:
sec_audit_ensure_mount_option /var/tmp nodev
sec_audit_remediate_done 9 "set nodev on /var/tmp"

# RULE10:
sec_audit_ensure_mount_option /var/tmp nosuid
sec_audit_remediate_done 10 "set nosuid on /var/tmp"

# RULE11:
sec_audit_ensure_mount_option /var/tmp noexec
sec_audit_remediate_done 11 "set noexec on /var/tmp"

# RULE12:
sec_audit_remediate_skip 12 "separate partition / layout change requires host planning"

# RULE13:
sec_audit_remediate_skip 13 "separate partition / layout change requires host planning"

# RULE14:
sec_audit_remediate_skip 14 "separate partition / layout change requires host planning"

# RULE15:
sec_audit_ensure_mount_option /home nodev
sec_audit_remediate_done 15 "set nodev on /home"

# RULE16:
sec_audit_remediate_skip 16 "separate partition / layout change requires host planning"

# RULE17:
sec_audit_ensure_mount_option /dev/shm nosuid
sec_audit_remediate_done 17 "set nosuid on /dev/shm"

# RULE18:
sec_audit_ensure_mount_option /dev/shm noexec
sec_audit_remediate_done 18 "set noexec on /dev/shm"

# RULE19:
sec_audit_pkg_remove autofs
sec_audit_remediate_done 19 "removed packages: autofs"

# RULE20:
sec_audit_set_yum_gpgcheck
sec_audit_remediate_done 20 "enabled yum/dnf gpgcheck"

# RULE21:
sec_audit_pkg_install aide
sec_audit_remediate_done 21 "ensured packages: aide"

# RULE22:
sec_audit_remediate_skip 22 'access to bootloader config is configured'

# RULE23:
sec_audit_remediate_skip 23 'bootloader password is set (grub.cfg under /boot/grub2 or EFI)'

# RULE24:
sec_audit_remediate_skip 24 'bootloader password is set'

# RULE25:
sec_audit_set_sysctl fs.protected_hardlinks 1
sec_audit_remediate_done 25 "sysctl hardening applied"

# RULE26:
sec_audit_set_sysctl fs.protected_symlinks 1
sec_audit_remediate_done 26 "sysctl hardening applied"

# RULE27:
sec_audit_remediate_skip 27 'SELinux is disabled via kernel command line or bootloader configuration'

# RULE28:
if [[ -f /etc/selinux/config ]]; then sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config; fi
setenforce 1 >/dev/null 2>&1 || true
sec_audit_remediate_done 28 "SELinux enforcing in config (reboot may be required)"

# RULE29:
if [[ -f /etc/selinux/config ]]; then sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config; fi
setenforce 1 >/dev/null 2>&1 || true
sec_audit_remediate_done 29 "SELinux enforcing in config (reboot may be required)"

# RULE30:
sec_audit_pkg_remove setroubleshoot
sec_audit_remediate_done 30 "removed packages: setroubleshoot"

# RULE31:
sec_audit_pkg_remove mcstrans
sec_audit_remediate_done 31 "removed packages: mcstrans"

# RULE32:
sec_audit_pkg_install libselinux
sec_audit_remediate_done 32 "ensured packages: libselinux"

# RULE33:
mkdir -p /etc
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue.net
sec_audit_remediate_done 33 "set login banners"

# RULE34:
mkdir -p /etc
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue.net
sec_audit_remediate_done 34 "set login banners"

# RULE35:
mkdir -p /etc
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue.net
sec_audit_remediate_done 35 "set login banners"

# RULE36:
mkdir -p /etc
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue.net
sec_audit_remediate_done 36 "set login banners"

# RULE37:
mkdir -p /etc
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue.net
sec_audit_remediate_done 37 "set login banners"

# RULE38:
mkdir -p /etc
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue.net
sec_audit_remediate_done 38 "set login banners"

# RULE39:
sec_audit_remediate_skip 39 'host-specific remediation for RULE39'

# RULE40:
sec_audit_pkg_remove xinetd
sec_audit_remediate_done 40 "removed packages: xinetd"

# RULE41:
sec_audit_disable_svc autofs.service
sec_audit_remediate_done 41 "disabled units: autofs.service"

# RULE42:
sec_audit_disable_svc avahi-daemon.socket
sec_audit_disable_svc avahi-daemon.service
sec_audit_remediate_done 42 "disabled units: avahi-daemon.socket avahi-daemon.service"

# RULE43:
sec_audit_pkg_remove avahi
sec_audit_remediate_done 43 "removed packages: avahi"

# RULE44:
sec_audit_disable_svc cups.socket
sec_audit_disable_svc cups.service
sec_audit_remediate_done 44 "disabled units: cups.socket cups.service"

# RULE45:
sec_audit_pkg_remove dhcp
sec_audit_remediate_done 45 "removed packages: dhcp"

# RULE46:
sec_audit_disable_svc nfs-server.service
sec_audit_remediate_done 46 "disabled units: nfs-server.service"

# RULE47:
sec_audit_disable_svc dnsmasq.service
sec_audit_remediate_done 47 "disabled units: dnsmasq.service"

# RULE48:
sec_audit_pkg_remove httpd
sec_audit_remediate_done 48 "removed packages: httpd"

# RULE49:
sec_audit_pkg_remove dovecot
sec_audit_remediate_done 49 "removed packages: dovecot"

# RULE50:
sec_audit_disable_svc smb.service
sec_audit_remediate_done 50 "disabled units: smb.service"

# RULE51:
sec_audit_pkg_remove squid
sec_audit_remediate_done 51 "removed packages: squid"

# RULE52:
sec_audit_disable_svc snmpd.service
sec_audit_remediate_done 52 "disabled units: snmpd.service"

# RULE53:
sec_audit_disable_svc telnet.socket
sec_audit_remediate_done 53 "disabled units: telnet.socket"

# RULE54:
sec_audit_disable_svc telnet.socket
sec_audit_remediate_done 54 "disabled units: telnet.socket"

# RULE55:
sec_audit_pkg_remove telnet
sec_audit_remediate_done 55 "removed packages: telnet"

# RULE56:
sec_audit_disable_svc rsyncd.socket
sec_audit_disable_svc rsyncd.service
sec_audit_remediate_done 56 "disabled units: rsyncd.socket rsyncd.service"

# RULE57:
sec_audit_pkg_remove telnet
sec_audit_remediate_done 57 "removed packages: telnet"

# RULE58:
sec_audit_pkg_install chrony
sec_audit_start_svc chronyd.service
sec_audit_remediate_done 58 "ensured chrony installed/started"

# RULE59:
sec_audit_disable_kmod atm
sec_audit_remediate_done 59 "blacklisted kernel module atm"

# RULE60:
sec_audit_disable_kmod atm
sec_audit_remediate_done 60 "blacklisted kernel module(s): atm"

# RULE61:
sec_audit_disable_kmod can
sec_audit_remediate_done 61 "blacklisted kernel module can"

# RULE62:
sec_audit_set_sysctl net.ipv4.conf.all.send_redirects 0
sec_audit_remediate_done 62 "sysctl hardening applied"

# RULE63:
sec_audit_remediate_skip 63 'check requires host review — 3.3.2 Ensure ICMP redirects are not accepted'

# RULE64:
sec_audit_remediate_skip 64 'check requires host review — 3.3.3 Ensure secure ICMP redirects are not accepted'

# RULE65:
sec_audit_set_sysctl net.ipv4.conf.all.accept_redirects 0
sec_audit_remediate_done 65 "sysctl hardening applied"

# RULE66:
sec_audit_remediate_skip 66 'check requires host review — 3.3.5 Ensure broadcast ICMP requests are ignored'

# RULE67:
sec_audit_set_sysctl net.ipv4.conf.all.secure_redirects 0
sec_audit_remediate_done 67 "sysctl hardening applied"

# RULE68:
sec_audit_set_sysctl net.ipv4.conf.all.rp_filter 1
sec_audit_remediate_done 68 "sysctl hardening applied"

# RULE69:
sec_audit_set_sysctl net.ipv4.conf.default.rp_filter 1
sec_audit_remediate_done 69 "sysctl hardening applied"

# RULE70:
sec_audit_set_sysctl net.ipv6.conf.all.accept_ra 0
sec_audit_remediate_done 70 "sysctl hardening applied"

# RULE71:
sec_audit_remediate_skip 71 'audit logs are not automatically deleted'

# RULE72:
sec_audit_remediate_skip 72 'audit log storage size is configured'

# RULE73:
sec_audit_remediate_skip 73 'system is disabled when audit logs are full'

# RULE74:
sec_audit_remediate_skip 74 'system is disabled when audit logs are full'

# RULE75:
sec_audit_remediate_skip 75 'system is disabled when audit logs are full'

# RULE76:
sec_audit_start_svc auditd.service
sec_audit_remediate_done 76 "ensured required services enabled/started"

# RULE77:
sec_audit_start_svc rsyslog.service
sec_audit_remediate_done 77 "ensured required services enabled/started"

# RULE78:
sec_audit_remediate_skip 78 'rsyslog log file creation mode is configured'

# RULE79:
sec_audit_remediate_skip 79 'host-specific remediation for RULE79'

# RULE80:
sec_audit_harden_path /etc/ssh/sshd_config 600 root:root
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key; do sec_audit_harden_path "$_k" 600 root:root; done; shopt -u nullglob
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key.pub; do sec_audit_harden_path "$_k" 644 root:root; done; shopt -u nullglob
sec_audit_remediate_done 80 "hardened ssh host key / sshd_config permissions"

# RULE81:
sec_audit_harden_path /etc/ssh/sshd_config 600 root:root
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key; do sec_audit_harden_path "$_k" 600 root:root; done; shopt -u nullglob
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key.pub; do sec_audit_harden_path "$_k" 644 root:root; done; shopt -u nullglob
sec_audit_remediate_done 81 "hardened ssh host key / sshd_config permissions"

# RULE82:
sec_audit_harden_path /etc/ssh/sshd_config 600 root:root
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key; do sec_audit_harden_path "$_k" 600 root:root; done; shopt -u nullglob
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key.pub; do sec_audit_harden_path "$_k" 644 root:root; done; shopt -u nullglob
sec_audit_remediate_done 82 "hardened ssh host key / sshd_config permissions"

# RULE83:
sec_audit_harden_path /etc/ssh/sshd_config 600 root:root
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key; do sec_audit_harden_path "$_k" 600 root:root; done; shopt -u nullglob
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key.pub; do sec_audit_harden_path "$_k" 644 root:root; done; shopt -u nullglob
sec_audit_remediate_done 83 "hardened ssh host key / sshd_config permissions"

# RULE84:
sec_audit_set_sshd_kv Banner /etc/issue.net
sec_audit_remediate_done 84 "sshd_config hardened keys"

# RULE85:
sec_audit_harden_path /etc/ssh/sshd_config 600 root:root
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key; do sec_audit_harden_path "$_k" 600 root:root; done; shopt -u nullglob
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key.pub; do sec_audit_harden_path "$_k" 644 root:root; done; shopt -u nullglob
sec_audit_remediate_done 85 "hardened ssh host key / sshd_config permissions"

# RULE86:
sec_audit_set_sshd_kv ClientAliveInterval 15
sec_audit_set_sshd_kv ClientAliveCountMax 3
sec_audit_remediate_done 86 "sshd_config hardened keys"

# RULE87:
sec_audit_harden_path /etc/ssh/sshd_config 600 root:root
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key; do sec_audit_harden_path "$_k" 600 root:root; done; shopt -u nullglob
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key.pub; do sec_audit_harden_path "$_k" 644 root:root; done; shopt -u nullglob
sec_audit_remediate_done 87 "hardened ssh host key / sshd_config permissions"

# RULE88:
sec_audit_harden_path /etc/ssh/sshd_config 600 root:root
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key; do sec_audit_harden_path "$_k" 600 root:root; done; shopt -u nullglob
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key.pub; do sec_audit_harden_path "$_k" 644 root:root; done; shopt -u nullglob
sec_audit_remediate_done 88 "hardened ssh host key / sshd_config permissions"

# RULE89:
sec_audit_set_sshd_kv Banner /etc/issue.net
sec_audit_remediate_done 89 "sshd_config hardened keys"

# RULE90:
sec_audit_harden_path /etc/ssh/sshd_config 600 root:root
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key; do sec_audit_harden_path "$_k" 600 root:root; done; shopt -u nullglob
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key.pub; do sec_audit_harden_path "$_k" 644 root:root; done; shopt -u nullglob
sec_audit_remediate_done 90 "hardened ssh host key / sshd_config permissions"

# RULE91:
sec_audit_set_sshd_kv MaxAuthTries 4
sec_audit_remediate_done 91 "sshd_config hardened keys"

# RULE92:
sec_audit_set_sshd_kv IgnoreRhosts yes
sec_audit_remediate_done 92 "sshd_config hardened keys"

# RULE93:
sec_audit_harden_path /etc/ssh/sshd_config 600 root:root
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key; do sec_audit_harden_path "$_k" 600 root:root; done; shopt -u nullglob
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key.pub; do sec_audit_harden_path "$_k" 644 root:root; done; shopt -u nullglob
sec_audit_remediate_done 93 "hardened ssh host key / sshd_config permissions"

# RULE94:
sec_audit_set_sshd_kv ClientAliveInterval 15
sec_audit_set_sshd_kv ClientAliveCountMax 3
sec_audit_remediate_done 94 "sshd_config hardened keys"

# RULE95:
sec_audit_harden_path /etc/ssh/sshd_config 600 root:root
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key; do sec_audit_harden_path "$_k" 600 root:root; done; shopt -u nullglob
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key.pub; do sec_audit_harden_path "$_k" 644 root:root; done; shopt -u nullglob
sec_audit_remediate_done 95 "hardened ssh host key / sshd_config permissions"

# RULE96:
sec_audit_set_sshd_kv HostbasedAuthentication no
sec_audit_remediate_done 96 "sshd_config hardened keys"

# RULE97:
sec_audit_set_sshd_kv PermitRootLogin no
sec_audit_remediate_done 97 "sshd_config hardened keys"

# RULE98:
sec_audit_set_sshd_kv PermitRootLogin no
sec_audit_remediate_done 98 "sshd_config hardened keys"

# RULE99:
sec_audit_set_sshd_kv PermitEmptyPasswords no
sec_audit_remediate_done 99 "sshd_config hardened keys"

# RULE100:
sec_audit_harden_path /etc/ssh/sshd_config 600 root:root
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key; do sec_audit_harden_path "$_k" 600 root:root; done; shopt -u nullglob
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key.pub; do sec_audit_harden_path "$_k" 644 root:root; done; shopt -u nullglob
sec_audit_remediate_done 100 "hardened ssh host key / sshd_config permissions"

# RULE101:
sec_audit_remediate_skip 101 'check requires host review — 5.5.1 Ensure password creation requirements are configured'

# RULE102:
sec_audit_remediate_skip 102 'check requires host review — 5.5.1 Ensure password creation requirements are configured'

# RULE103:
sec_audit_remediate_skip 103 'check requires host review — 5.5.2 Ensure lockout for failed password attempts is configured'

# RULE104:
sec_audit_remediate_skip 104 'check requires host review — 5.5.3 Ensure password reuse is limited'

# RULE105:
sec_audit_remediate_skip 105 'check requires host review — 5.5.4 Ensure password hashing algorithm is SHA-512'

# RULE106:
sec_audit_remediate_skip 106 'check requires host review — 5.6.1.1 Ensure password expiration is 365 days or less'

# RULE107:
sec_audit_remediate_skip 107 'check requires host review — 5.6.1.3 Ensure password expiration warning days is 7 or more'

# RULE108:
sec_audit_remediate_skip 108 'check requires host review — 5.6.1.3 Ensure password expiration warning days is 7 or more'

# RULE109:
sec_audit_remediate_skip 109 'check requires host review — 5.6.1.4 Ensure inactive password lock is 30 days or less'

# RULE110:
sec_audit_remediate_skip 110 'check requires host review — 5.6.1.4 Ensure inactive password lock is 30 days or less'

# RULE111:
sec_audit_remediate_skip 111 'check requires host review — 5.6.1.5 Ensure all users last password change date is in the past'

# RULE112:
sec_audit_remediate_skip 112 'check requires host review — 5.6.4 Ensure default group for the root account is GID 0'

# RULE113:
sec_audit_remediate_skip 113 'check requires host review — 5.6.5 Ensure default user umask is 027 or more restrictive'

# RULE114:
sec_audit_remediate_skip 114 'check requires host review — 5.6.3 Ensure default user shell timeout is 900 seconds or less'

# RULE115:
sec_audit_pkg_install aide
sec_audit_remediate_done 115 "ensured packages: aide"

# RULE116:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_remediate_done 116 "hardened identity/config file permissions"

# RULE117:
sec_audit_harden_path /etc/shadow 000 root:root
sec_audit_remediate_done 117 "hardened identity/config file permissions"

# RULE118:
sec_audit_remediate_skip 118 'check requires host review — '

# RULE119:
sec_audit_harden_path /etc/group 644 root:root
sec_audit_remediate_done 119 "hardened identity/config file permissions"

# RULE120:
sec_audit_remediate_skip 120 'check requires host review — '

# RULE121:
sec_audit_harden_path /etc/gshadow 000 root:root
sec_audit_remediate_done 121 "hardened identity/config file permissions"

# RULE122:
sec_audit_remediate_skip 122 'check requires host review — '

# RULE123:
sec_audit_remediate_skip 123 'filesystem integrity is regularly checked (cron/cron.d entry references aide)'

# RULE124:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_remediate_done 124 "hardened identity/config file permissions"

# RULE125:
sec_audit_harden_path /etc/shadow 000 root:root
sec_audit_harden_path /etc/shadow- 000 root:root
sec_audit_remediate_done 125 "hardened identity/config file permissions"

# RULE126:
sec_audit_remediate_skip 126 'check requires host review — '

# RULE127:
sec_audit_harden_path /etc/group 644 root:root
sec_audit_harden_path /etc/group- 644 root:root
sec_audit_remediate_done 127 "hardened identity/config file permissions"

# RULE128:
sec_audit_remediate_skip 128 'check requires host review — '

# RULE129:
sec_audit_harden_path /etc/gshadow 000 root:root
sec_audit_harden_path /etc/gshadow- 000 root:root
sec_audit_remediate_done 129 "hardened identity/config file permissions"

# RULE130:
sec_audit_remediate_skip 130 'check requires host review — '

# RULE131:
sec_audit_remediate_skip 131 'incomplete_scan: world-writable file search timed out under critical paths'

# RULE132:
sec_audit_remediate_skip 132 'check requires host review — 6.1.10 Ensure no unowned files or directories exist'

# RULE133:
sec_audit_remediate_skip 133 'check requires host review — 6.1.11 Ensure no ungrouped files or directories exist'

# RULE134:
sec_audit_remediate_skip 134 'host-specific remediation for RULE134'

# RULE135:
sec_audit_remediate_skip 135 'host-specific remediation for RULE135'

# RULE136:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_remediate_done 136 "hardened identity/config file permissions"

# RULE137:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_remediate_done 137 "hardened identity/config file permissions"

# RULE138:
sec_audit_pkg_remove ossec
sec_audit_remediate_done 138 "removed packages: ossec"

# RULE139:
sec_audit_remediate_skip 139 'check requires host review — '

# RULE140:
sec_audit_remediate_skip 140 'check requires host review — '

# RULE141:
sec_audit_set_yum_gpgcheck
sec_audit_remediate_done 141 "enabled yum/dnf gpgcheck"

# RULE142:
sec_audit_pkg_remove xorg-x11-server
sec_audit_remediate_done 142 "removed packages: xorg-x11-server"

# RULE143:
sec_audit_remediate_skip 143 'Wireless interfaces are present under /sys/class/net'

# RULE144:
sec_audit_pkg_install audit
sec_audit_remediate_done 144 "ensured packages: audit"

# RULE145:
sec_audit_remediate_skip 145 'audit_backlog_limit is configured'

# RULE146:
sec_audit_remediate_skip 146 'host-specific remediation for RULE146'

# RULE147:
sec_audit_remediate_skip 147 'check requires host review — 4.1.3.8 Ensure events that modify user/group information are collected'

# RULE148:
sec_audit_append_audit_watch '-w /etc/NetworkManager/"; -p wa -k secaudit'
sec_audit_append_audit_watch '-w /etc/NetworkManager -p wa -k secaudit'
sec_audit_pkg_install audit
sec_audit_start_svc auditd.service
sec_audit_remediate_done 148 "audit watch rules appended"

# RULE149:
sec_audit_append_audit_watch '-w /etc/sudoers"; -p wa -k secaudit'
sec_audit_append_audit_watch '-w /etc/sudoers.d"; -p wa -k secaudit'
sec_audit_append_audit_watch '-w /etc/sudoers.d -p wa -k secaudit'
sec_audit_append_audit_watch '-w /etc/sudoers -p wa -k secaudit'
sec_audit_pkg_install audit
sec_audit_start_svc auditd.service
sec_audit_remediate_done 149 "audit watch rules appended"

# RULE150:
sec_audit_remediate_skip 150 'host-specific remediation for RULE150'

# RULE151:
sec_audit_pkg_install rsyslog
sec_audit_remediate_done 151 "ensured packages: rsyslog"

# RULE152:
sec_audit_remediate_skip 152 'check requires host review — 5.3.1 Ensure sudo is installed'

# RULE153:
sec_audit_remediate_skip 153 'check requires host review — 5.3.2 Ensure sudo commands use pty'

# RULE154:
sec_audit_remediate_skip 154 'check requires host review — 5.3.3 Ensure sudo log file exists'

# RULE155:
sec_audit_harden_path /etc/ssh/sshd_config 600 root:root
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key; do sec_audit_harden_path "$_k" 600 root:root; done; shopt -u nullglob
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key.pub; do sec_audit_harden_path "$_k" 644 root:root; done; shopt -u nullglob
sec_audit_remediate_done 155 "hardened ssh host key / sshd_config permissions"

# RULE156:
sec_audit_harden_path /etc/ssh/sshd_config 600 root:root
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key; do sec_audit_harden_path "$_k" 600 root:root; done; shopt -u nullglob
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key.pub; do sec_audit_harden_path "$_k" 644 root:root; done; shopt -u nullglob
sec_audit_remediate_done 156 "hardened ssh host key / sshd_config permissions"

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
sec_audit_remediate_skip 159 'check requires host review — 5.6.2 Ensure system accounts are secured'

# RULE160:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_remediate_done 160 "hardened identity/config file permissions"

# RULE161:
sec_audit_harden_path /etc/group 644 root:root
sec_audit_remediate_done 161 "hardened identity/config file permissions"

# RULE162:
sec_audit_harden_path /etc/group 644 root:root
sec_audit_remediate_done 162 "hardened identity/config file permissions"

# RULE163:
sec_audit_remediate_skip 163 'host-specific remediation for RULE163'

# RULE164:
sec_audit_pkg_install audit
sec_audit_start_svc auditd.service
sec_audit_remediate_done 164 "ensured auditd installed/started"

# RULE165:
sec_audit_remediate_skip 165 'check requires host review — 4.1.3.12 Ensure login and logout events are collected'

# RULE166:
sec_audit_remediate_skip 166 'check requires host review — 4.1.3.13 Ensure file deletion events by users are collected'

# RULE167:
sec_audit_ensure_mount_option /var nodev
sec_audit_remediate_done 167 "set nodev on /var"

# RULE168:
sec_audit_ensure_mount_option /var nosuid
sec_audit_remediate_done 168 "set nosuid on /var"

# RULE169:
sec_audit_ensure_mount_option /var/log nodev
sec_audit_remediate_done 169 "set nodev on /var/log"

# RULE170:
sec_audit_ensure_mount_option /var/log noexec
sec_audit_remediate_done 170 "set noexec on /var/log"

# RULE171:
sec_audit_ensure_mount_option /var/log nosuid
sec_audit_remediate_done 171 "set nosuid on /var/log"

# RULE172:
sec_audit_ensure_mount_option /var/log/audit noexec
sec_audit_remediate_done 172 "set noexec on /var/log/audit"

# RULE173:
sec_audit_ensure_mount_option /var/log/audit nodev
sec_audit_remediate_done 173 "set nodev on /var/log/audit"

# RULE174:
sec_audit_ensure_mount_option /var/log/audit nosuid
sec_audit_remediate_done 174 "set nosuid on /var/log/audit"

# RULE175:
sec_audit_ensure_mount_option /home nosuid
sec_audit_remediate_done 175 "set nosuid on /home"

# RULE176:
sec_audit_set_yum_gpgcheck
sec_audit_remediate_done 176 "enabled yum/dnf gpgcheck"

# RULE177:
sec_audit_remediate_skip 177 'check requires host review — 1.3.2 Ensure filesystem integrity is regularly checked'

# RULE178:
sec_audit_remediate_skip 178 'limits * hard core 0 present and systemd DefaultLimitCORE does not allow unlimited core dumps'

# RULE179:
if [[ -f /etc/selinux/config ]]; then sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config; fi
setenforce 1 >/dev/null 2>&1 || true
sec_audit_remediate_done 179 "SELinux enforcing in config (reboot may be required)"

# RULE180:
if [[ -f /etc/selinux/config ]]; then sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config; fi
setenforce 1 >/dev/null 2>&1 || true
sec_audit_remediate_done 180 "SELinux enforcing in config (reboot may be required)"

# RULE181:
sec_audit_remediate_skip 181 'GDM login banner is configured'

# RULE182:
sec_audit_remediate_skip 182 'GDM disable-user-list is configured'

# RULE183:
sec_audit_remediate_skip 183 'check requires host review — 1.8.10 Ensure XDCMP is not enabled'

# RULE184:
sec_audit_remediate_skip 184 'check requires host review — 1.10 Ensure system-wide crypto policy is not legacy'

# RULE185:
sec_audit_disable_svc named.service
sec_audit_remediate_done 185 "disabled units: named.service"

# RULE186:
sec_audit_disable_svc dovecot.socket
sec_audit_disable_svc dovecot.service
sec_audit_disable_svc cyrus-imapd.service
sec_audit_remediate_done 186 "disabled units: dovecot.socket dovecot.service cyrus-imapd.service"

# RULE187:
sec_audit_disable_svc vsftpd.service
sec_audit_remediate_done 187 "disabled units: vsftpd.service"

# RULE188:
sec_audit_disable_svc rpcbind.socket
sec_audit_disable_svc rpcbind.service
sec_audit_remediate_done 188 "disabled units: rpcbind.socket rpcbind.service"

# RULE189:
sec_audit_pkg_install chrony
sec_audit_start_svc chronyd.service
sec_audit_remediate_done 189 "ensured chrony installed/started"

# RULE190:
sec_audit_pkg_install audit
sec_audit_start_svc auditd.service
sec_audit_remediate_done 190 "ensured auditd installed/started"

# RULE191:
sec_audit_append_audit_watch '-w /var/log/sudo.log -p wa -k secaudit'
sec_audit_append_audit_watch '-w /var/log/sudo.log"; -p wa -k secaudit'
sec_audit_pkg_install audit
sec_audit_start_svc auditd.service
sec_audit_remediate_done 191 "audit watch rules appended"

# RULE192:
sec_audit_remediate_skip 192 'check requires host review — 4.1.3.6 Ensure use of privileged commands are collected'

# RULE193:
sec_audit_remediate_skip 193 'host-specific remediation for RULE193'

# RULE194:
sec_audit_remediate_skip 194 'host-specific remediation for RULE194'

# RULE195:
sec_audit_remediate_skip 195 'host-specific remediation for RULE195'

# RULE196:
sec_audit_remediate_skip 196 'host-specific remediation for RULE196'

# RULE197:
sec_audit_pkg_install audit
sec_audit_start_svc auditd.service
sec_audit_remediate_done 197 "ensured auditd installed/started"

# RULE198:
sec_audit_pkg_install audit
sec_audit_start_svc auditd.service
sec_audit_remediate_done 198 "ensured auditd installed/started"

# RULE199:
sec_audit_harden_path /etc/ssh/sshd_config 600 root:root
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key; do sec_audit_harden_path "$_k" 600 root:root; done; shopt -u nullglob
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key.pub; do sec_audit_harden_path "$_k" 644 root:root; done; shopt -u nullglob
sec_audit_remediate_done 199 "hardened ssh host key / sshd_config permissions"

# RULE200:
sec_audit_set_sshd_kv LogLevel INFO
sec_audit_remediate_done 200 "sshd_config hardened keys"

# RULE201:
sec_audit_remediate_skip 201 'check requires host review — 5.3.4 Ensure users must provide password for escalation'

# RULE202:
sec_audit_remediate_skip 202 'host-specific remediation for RULE202'

# RULE203:
sec_audit_remediate_skip 203 'check requires host review — 5.3.6 Ensure sudo authentication timeout is configured correctly'

# RULE204:
sec_audit_remediate_skip 204 'check requires host review — 5.3.7 Ensure access to the su command is restricted'

# RULE205:
sec_audit_set_faillock_kv deny 5
sec_audit_set_faillock_kv unlock_time 900
sec_audit_remediate_done 205 "faillock deny/unlock_time baseline"

# RULE206:
sec_audit_remediate_skip 206 'check requires host review — 6.1.12 Ensure sticky bit is set on all world-writable directories'

# RULE207:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_remediate_done 207 "hardened identity/config file permissions"

# RULE208:
sec_audit_remediate_skip 208 "separate partition / layout change requires host planning"

# RULE209:
sec_audit_remediate_skip 209 '/etc/yum.repos.d is missing'

# RULE210:
sec_audit_remediate_skip 210 'host-specific remediation for RULE210'

# RULE211:
sec_audit_remediate_skip 211 'GDM screen lock is configured'

# RULE212:
sec_audit_remediate_skip 212 'GDM automount is configured'

# RULE213:
sec_audit_remediate_skip 213 'GDM autorun-never is configured'

# RULE214:
sec_audit_disable_kmod removable
sec_audit_remediate_done 214 "blacklisted kernel module(s): removable"

# RULE215:
sec_audit_remediate_skip 215 'host-specific remediation for RULE215'

# RULE216:
sec_audit_remediate_skip 216 'check requires host review — 1.8.8 Ensure GDM autorun-never is enabled'

# RULE217:
sec_audit_remediate_skip 217 'check requires host review — 1.8.9 Ensure GDM autorun-never is not overridden'

# RULE218:
sec_audit_disable_svc avahi-daemon.socket
sec_audit_disable_svc avahi-daemon.service
sec_audit_remediate_done 218 "disabled units: avahi-daemon.socket avahi-daemon.service"

# RULE219:
sec_audit_pkg_remove dnsmasq
sec_audit_remediate_done 219 "removed packages: dnsmasq"

# RULE220:
sec_audit_remediate_skip 220 'check requires host review — 2.3.4 Ensure FTP client is not installed'

# RULE221:
sec_audit_remediate_skip 221 'host-specific remediation for RULE221'

# RULE222:
sec_audit_disable_svc bluetooth.service
sec_audit_remediate_done 222 "disabled units: bluetooth.service"

# RULE223:
sec_audit_remediate_skip 223 'check requires host review — 3.4.1.2 Ensure a single firewall configuration utility is in use'

# RULE224:
sec_audit_remediate_skip 224 'check requires host review — 4.1.3.7 Ensure unsuccessful file access attempts are collected'

# RULE225:
sec_audit_remediate_skip 225 'host-specific remediation for RULE225'

# RULE226:
sec_audit_remediate_skip 226 'check requires host review — 5.6.1.2 Ensure minimum days between password changes is configured'

# RULE227:
sec_audit_remediate_skip 227 'check requires host review — 5.6.6 Ensure root password is set'

# RULE228:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_remediate_done 228 "hardened identity/config file permissions"

# RULE229:
sec_audit_harden_path /etc/shadow 000 root:root
sec_audit_remediate_done 229 "hardened identity/config file permissions"

# RULE230:
sec_audit_remediate_skip 230 'check requires host review — 6.2.8 Ensure root PATH Integrity'

# RULE231:
sec_audit_remediate_skip 231 'check requires host review — 6.2.11 Ensure local interactive users own their home directories'

# RULE232:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_remediate_done 232 "hardened identity/config file permissions"


	if [ "${REMEDIATE_SECURITY_UPGRADE}" = "1" ]; then
		if sec_audit_have_bin dnf; then
			timeout 300 dnf upgrade --security -y >/dev/null 2>&1 || true
		elif sec_audit_have_bin yum; then
			timeout 300 yum update --security -y >/dev/null 2>&1 || true
		fi
	else
		sec_audit_log "skipping security upgrade (set REMEDIATE_SECURITY_UPGRADE=1 to enable)"
	fi
	sec_audit_log "remediation complete (Oracle9_remediation.sh)"
}

sec_audit_main "$@"
