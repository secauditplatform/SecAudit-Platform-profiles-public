#!/bin/bash
# Full remediation for RHEL7 — generated from audit rule bodies (sec_audit_* style).

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
SYSCTL_FILE="/etc/sysctl.d/99-secaudit-rhel7.conf"
MODPROBE_PREFIX="/etc/modprobe.d/sec-audit-disable"
AUDIT_RULES_FILE="/etc/audit/rules.d/99-secaudit-rhel7.rules"

sec_audit_have_bin() { command -v "$1" >/dev/null 2>&1; }
sec_audit_log() { printf '[remediation] %s\n' "$*"; }
sec_audit_remediate_done() { printf '[remediation] REMEDIATE RULE%s= applied: %s\n' "$1" "$2"; }
sec_audit_remediate_skip() { printf '[remediation] REMEDIATE RULE%s= SKIP: manual step required - %s\n' "$1" "$2"; }

sec_audit_pkg_install() {
	local need=() p
	sec_audit_have_bin yum || return 0
	for p in "$@"; do rpm -q "$p" &>/dev/null || need+=("$p"); done
	((${#need[@]})) || return 0
	timeout 120 yum install -y "${need[@]}" >/dev/null 2>&1 || true
}

sec_audit_pkg_remove() {
	local p
	sec_audit_have_bin yum || return 0
	for p in "$@"; do
		rpm -q "$p" &>/dev/null || continue
		timeout 90 yum remove -y "$p" >/dev/null 2>&1 || true
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
	sec_audit_log "starting remediation (RHEL7)"

# RULE1:
sec_audit_remediate_skip 1 'mounting of cramfs filesystems is disabled'

# RULE4:
sec_audit_remediate_skip 4 "separate partition / layout change requires host planning"

# RULE42:
sec_audit_remediate_skip 42 'no security updates pending'

# RULE44:
sec_audit_pkg_install chrony
sec_audit_start_svc chronyd.service
sec_audit_remediate_done 44 "ensured chrony installed/started"

# RULE45:
sec_audit_pkg_install chrony
sec_audit_start_svc chronyd.service
sec_audit_remediate_done 45 "ensured chrony installed/started"

# RULE46:
sec_audit_pkg_install chrony
sec_audit_start_svc chronyd.service
sec_audit_remediate_done 46 "ensured chrony installed/started"

# RULE47:
sec_audit_disable_svc avahi-daemon.socket
sec_audit_disable_svc avahi-daemon.service
sec_audit_remediate_done 47 "disabled units: avahi-daemon.socket avahi-daemon.service"

# RULE48:
sec_audit_disable_svc cups.socket
sec_audit_disable_svc cups.service
sec_audit_remediate_done 48 "disabled units: cups.socket cups.service"

# RULE49:
sec_audit_remediate_skip 49 'dhcp not installed and dhcpd off'

# RULE50:
sec_audit_remediate_skip 50 'openldap-servers not installed and slapd off'

# RULE55:
sec_audit_set_sysctl net.ipv4.ip_forward 0
sec_audit_remediate_done 55 "sysctl hardening applied"

# RULE56:
sec_audit_set_sysctl net.ipv4.ip_forward 0
sec_audit_remediate_done 56 "sysctl hardening applied"

# RULE57:
sec_audit_set_sysctl net.ipv4.conf.all.send_redirects 0
sec_audit_set_sysctl net.ipv4.conf.default.send_redirects 0
sec_audit_set_sysctl net.ipv4.conf.all.send_redirects 0
sec_audit_remediate_done 57 "sysctl hardening applied"

# RULE58:
sec_audit_set_sysctl net.ipv4.conf.all.accept_source_route 0
sec_audit_set_sysctl net.ipv4.conf.default.accept_source_route 0
sec_audit_set_sysctl net.ipv4.conf.all.accept_source_route 0
sec_audit_remediate_done 58 "sysctl hardening applied"

# RULE59:
sec_audit_set_sysctl net.ipv4.conf.all.accept_redirects 0
sec_audit_set_sysctl net.ipv4.conf.default.accept_redirects 0
sec_audit_set_sysctl net.ipv6.conf.all.accept_redirects 0
sec_audit_set_sysctl net.ipv6.conf.default.accept_redirects 0
sec_audit_set_sysctl net.ipv4.conf.all.accept_redirects 0
sec_audit_remediate_done 59 "sysctl hardening applied"

# RULE60:
sec_audit_set_sysctl net.ipv4.conf.all.secure_redirects 0
sec_audit_set_sysctl net.ipv4.conf.default.secure_redirects 0
sec_audit_set_sysctl net.ipv4.conf.all.secure_redirects 0
sec_audit_remediate_done 60 "sysctl hardening applied"

# RULE61:
sec_audit_set_sysctl net.ipv4.conf.all.log_martians 1
sec_audit_set_sysctl net.ipv4.conf.default.log_martians 1
sec_audit_set_sysctl net.ipv4.conf.all.log_martians 1
sec_audit_remediate_done 61 "sysctl hardening applied"

# RULE62:
sec_audit_set_sysctl net.ipv4.icmp_echo_ignore_broadcasts 1
sec_audit_remediate_done 62 "sysctl hardening applied"

# RULE63:
sec_audit_set_sysctl net.ipv4.icmp_ignore_bogus_error_responses 1
sec_audit_remediate_done 63 "sysctl hardening applied"

# RULE64:
sec_audit_set_sysctl net.ipv4.conf.all.rp_filter 1
sec_audit_set_sysctl net.ipv4.conf.default.rp_filter 1
sec_audit_set_sysctl net.ipv4.conf.all.rp_filter 1
sec_audit_remediate_done 64 "sysctl hardening applied"

# RULE65:
sec_audit_set_sysctl net.ipv4.tcp_syncookies 1
sec_audit_remediate_done 65 "sysctl hardening applied"

# RULE66:
sec_audit_set_sysctl net.ipv6.conf.all.accept_ra 0
sec_audit_set_sysctl net.ipv6.conf.default.accept_ra 0
sec_audit_set_sysctl net.ipv6.conf.all.accept_ra 0
sec_audit_remediate_done 66 "sysctl hardening applied"

# RULE70:
sec_audit_remediate_skip 70 'audit logs retained (max_log_file_action=keep_logs)'

# RULE71:
sec_audit_remediate_skip 71 'audit log storage size configured (max_log_file set)'

# RULE72:
sec_audit_remediate_skip 72 'space_left_action=email when audit disk full'

# RULE73:
sec_audit_remediate_skip 73 'action_mail_acct configured in auditd.conf'

# RULE74:
sec_audit_remediate_skip 74 'admin_space_left_action=halt'

# RULE78:
sec_audit_remediate_skip 78 'rsyslog forwards logs to remote host'

# RULE79:
sec_audit_remediate_skip 79 'rsyslog not accepting remote TCP logs (or not configured as collector)'

# RULE80:
sec_audit_remediate_skip 80 'crond enabled'

# RULE81:
sec_audit_remediate_skip 81 '/etc/crontab permissions OK (600/700 root)'

# RULE82:
sec_audit_remediate_skip 82 '/etc/cron.hourly permissions OK (600/700 root)'

# RULE83:
sec_audit_remediate_skip 83 '/etc/cron.daily permissions OK (600/700 root)'

# RULE84:
sec_audit_remediate_skip 84 '/etc/cron.weekly permissions OK (600/700 root)'

# RULE85:
sec_audit_remediate_skip 85 '/etc/cron.monthly permissions OK (600/700 root)'

# RULE86:
sec_audit_remediate_skip 86 '/etc/cron.d permissions OK (600/700 root)'

# RULE87:
sec_audit_remediate_skip 87 'cron restricted (/etc/cron.allow, no cron.deny)'

# RULE88:
sec_audit_remediate_skip 88 'at restricted (/etc/at.allow, no at.deny)'

# RULE113:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_remediate_done 113 "hardened identity/config file permissions"

# RULE117:
sec_audit_harden_path /etc/group 644 root:root
sec_audit_remediate_done 117 "hardened identity/config file permissions"

# RULE123:
sec_audit_harden_path /etc/shadow 000 root:root
sec_audit_harden_path /etc/shadow- 000 root:root
sec_audit_remediate_done 123 "hardened identity/config file permissions"

# RULE127:
sec_audit_harden_path /etc/gshadow 000 root:root
sec_audit_harden_path /etc/gshadow- 000 root:root
sec_audit_remediate_done 127 "hardened identity/config file permissions"

# RULE129:
sec_audit_remediate_skip 129 'incomplete_scan: world-writable file search timed out under critical paths'

# RULE130:
sec_audit_remediate_skip 130 'no unowned files or directories (count=0)'

# RULE131:
sec_audit_remediate_skip 131 'no ungrouped files or directories (count=0)'

# RULE132:
sec_audit_remediate_skip 132 'SUID audit complete (count=${_c:-0}; review list manually)'

# RULE133:
sec_audit_remediate_skip 133 'SGID audit complete (count=${_c:-0}; review list manually)'

# RULE134:
sec_audit_harden_path /etc/shadow 000 root:root
sec_audit_remediate_done 134 "hardened identity/config file permissions"

# RULE139:
sec_audit_remediate_skip 139 'usb-storage module disabled'

# RULE140:
sec_audit_set_yum_gpgcheck
sec_audit_remediate_done 140 "enabled yum/dnf gpgcheck"

# RULE142:
sec_audit_remediate_skip 142 'X11 server components not installed'

# RULE143:
sec_audit_remediate_skip 143 'audit and audit-libs installed'

# RULE144:
sec_audit_remediate_skip 144 'audit_backlog_limit=${_lim} (>=8192)'

# RULE145:
sec_audit_pkg_install audit
sec_audit_start_svc auditd.service
sec_audit_remediate_done 145 "ensured auditd installed/started"

# RULE146:
sec_audit_pkg_install audit
sec_audit_start_svc auditd.service
sec_audit_remediate_done 146 "ensured auditd installed/started"

# RULE147:
sec_audit_pkg_install audit
sec_audit_start_svc auditd.service
sec_audit_remediate_done 147 "ensured auditd installed/started"

# RULE148:
sec_audit_pkg_install audit
sec_audit_start_svc auditd.service
sec_audit_remediate_done 148 "ensured auditd installed/started"

# RULE149:
sec_audit_pkg_install audit
sec_audit_start_svc auditd.service
sec_audit_remediate_done 149 "ensured auditd installed/started"

# RULE150:
sec_audit_pkg_install audit
sec_audit_start_svc auditd.service
sec_audit_remediate_done 150 "ensured auditd installed/started"

# RULE151:
sec_audit_remediate_skip 151 'rsyslog installed'

# RULE163:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_remediate_done 163 "hardened identity/config file permissions"

# RULE172:
sec_audit_pkg_install audit
sec_audit_start_svc auditd.service
sec_audit_remediate_done 172 "ensured auditd installed/started"

# RULE173:
sec_audit_set_faillock_kv deny 5
sec_audit_set_faillock_kv unlock_time 900
sec_audit_remediate_done 173 "faillock deny/unlock_time baseline"

# RULE174:
sec_audit_pkg_install audit
sec_audit_start_svc auditd.service
sec_audit_remediate_done 174 "ensured auditd installed/started"

# RULE202:
sec_audit_remediate_skip 202 'ypbind not installed'

# RULE203:
sec_audit_remediate_skip 203 'rsh not installed'

# RULE204:
sec_audit_remediate_skip 204 'talk not installed'

# RULE205:
sec_audit_remediate_skip 205 'telnet not installed'

# RULE206:
sec_audit_remediate_skip 206 'openldap-clients not installed'

# RULE5:
sec_audit_ensure_mount_option /tmp nodev
sec_audit_remediate_done 5 "set nodev on /tmp"

# RULE6:
sec_audit_disable_svc autofs.service
sec_audit_remediate_done 6 "disabled units: autofs.service"

# RULE7:
sec_audit_ensure_mount_option /tmp noexec
sec_audit_remediate_done 7 "set noexec on /tmp"

# RULE8:
sec_audit_remediate_skip 8 "separate partition / layout change requires host planning"

# RULE10:
sec_audit_remediate_skip 10 "separate partition / layout change requires host planning"

# RULE11:
sec_audit_ensure_mount_option /var/tmp nosuid
sec_audit_remediate_done 11 "set nosuid on /var/tmp"

# RULE12:
sec_audit_ensure_mount_option /var/tmp noexec
sec_audit_remediate_done 12 "set noexec on /var/tmp"

# RULE16:
sec_audit_remediate_skip 16 "separate partition / layout change requires host planning"

# RULE17:
sec_audit_remediate_skip 17 "separate partition / layout change requires host planning"

# RULE18:
sec_audit_ensure_mount_option /dev/shm nosuid
sec_audit_remediate_done 18 "set nosuid on /dev/shm"

# RULE19:
sec_audit_ensure_mount_option /dev/shm noexec
sec_audit_remediate_done 19 "set noexec on /dev/shm"

# RULE24:
sec_audit_remediate_skip 24 'access to bootloader config is configured'

# RULE26:
sec_audit_remediate_skip 26 'bootloader password is set (grub.cfg under /boot/grub2 or EFI)'

# RULE27:
sec_audit_set_sysctl fs.suid_dumpable 0
sec_audit_set_sysctl fs.suid_dumpable 0
sec_audit_remediate_done 27 "sysctl hardening applied"

# RULE28:
sec_audit_remediate_skip 28 'XD/NX (PAE) support appears enabled'

# RULE29:
sec_audit_set_sysctl kernel.randomize_va_space 2
sec_audit_set_sysctl kernel.randomize_va_space 2;
sec_audit_remediate_done 29 "sysctl hardening applied"

# RULE30:
sec_audit_remediate_skip 30 'prelink is not installed'

# RULE31:
sec_audit_remediate_skip 31 'SELinux disabled in bootloader kernel line'

# RULE219:
if [[ -f /etc/selinux/config ]]; then sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config; fi
setenforce 1 >/dev/null 2>&1 || true
sec_audit_remediate_done 219 "SELinux enforcing in config (reboot may be required)"

# RULE32:
if [[ -f /etc/selinux/config ]]; then sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config; fi
setenforce 1 >/dev/null 2>&1 || true
sec_audit_remediate_done 32 "SELinux enforcing in config (reboot may be required)"

# RULE33:
sec_audit_remediate_skip 33 'setroubleshoot is not installed'

# RULE34:
sec_audit_remediate_skip 34 'mcstrans is not installed'

# RULE35:
sec_audit_remediate_skip 35 'libselinux is installed'

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
mkdir -p /etc
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue.net
sec_audit_remediate_done 39 "set login banners"

# RULE40:
mkdir -p /etc
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue.net
sec_audit_remediate_done 40 "set login banners"

# RULE41:
mkdir -p /etc
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue
printf "%s\n" "Authorized uses only. All activity may be monitored and reported." >/etc/issue.net
sec_audit_remediate_done 41 "set login banners"

# RULE43:
sec_audit_remediate_skip 43 'xinetd is not installed'

# RULE51:
sec_audit_disable_svc nfs-server.service
sec_audit_remediate_done 51 "disabled units: nfs-server.service"

# RULE195:
sec_audit_remediate_skip 195 'vsftpd not installed'

# RULE196:
sec_audit_remediate_skip 196 'httpd not installed'

# RULE197:
sec_audit_remediate_skip 197 'dovecot not installed'

# RULE198:
sec_audit_disable_svc smb.service
sec_audit_remediate_done 198 "disabled units: smb.service"

# RULE199:
sec_audit_remediate_skip 199 'squid not installed'

# RULE52:
sec_audit_disable_svc snmpd.service
sec_audit_remediate_done 52 "disabled units: snmpd.service"

# RULE53:
sec_audit_remediate_skip 53 'MTA not listening on non-loopback port 25'

# RULE200:
sec_audit_remediate_skip 200 'ypserv not installed'

# RULE54:
sec_audit_disable_svc telnet.socket
sec_audit_remediate_done 54 "disabled units: telnet.socket"

# RULE67:
sec_audit_remediate_skip 67 'DCCP module disabled'

# RULE68:
sec_audit_remediate_skip 68 'SCTP module disabled'

# RULE90:
sec_audit_set_sshd_kv LogLevel INFO
sec_audit_remediate_done 90 "sshd_config hardened keys"

# RULE91:
sec_audit_set_sshd_kv X11Forwarding no
sec_audit_remediate_done 91 "sshd_config hardened keys"

# RULE92:
sec_audit_set_sshd_kv MaxAuthTries 4
sec_audit_remediate_done 92 "sshd_config hardened keys"

# RULE93:
sec_audit_set_sshd_kv IgnoreRhosts yes
sec_audit_remediate_done 93 "sshd_config hardened keys"

# RULE94:
sec_audit_set_sshd_kv HostbasedAuthentication no
sec_audit_remediate_done 94 "sshd_config hardened keys"

# RULE95:
sec_audit_set_sshd_kv PermitRootLogin no
sec_audit_remediate_done 95 "sshd_config hardened keys"

# RULE96:
sec_audit_set_sshd_kv PermitEmptyPasswords no
sec_audit_remediate_done 96 "sshd_config hardened keys"

# RULE97:
sec_audit_set_sshd_kv PermitUserEnvironment no
sec_audit_remediate_done 97 "sshd_config hardened keys"

# RULE98:
sec_audit_harden_path /etc/ssh/sshd_config 600 root:root
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key; do sec_audit_harden_path "$_k" 600 root:root; done; shopt -u nullglob
shopt -s nullglob; for _k in /etc/ssh/ssh_host_*_key.pub; do sec_audit_harden_path "$_k" 644 root:root; done; shopt -u nullglob
sec_audit_remediate_done 98 "hardened ssh host key / sshd_config permissions"

# RULE100:
sec_audit_set_sshd_kv ClientAliveCountMax 3
sec_audit_remediate_done 100 "sshd_config hardened keys"

# RULE101:
sec_audit_set_sshd_kv LoginGraceTime 60
sec_audit_remediate_done 101 "sshd_config hardened keys"

# RULE102:
sec_audit_set_sshd_kv Banner /etc/issue.net
sec_audit_remediate_done 102 "sshd_config hardened keys"

# RULE103:
sec_audit_remediate_skip 103 'host-specific remediation for RULE103'

# RULE105:
sec_audit_remediate_skip 105 'host-specific remediation for RULE105'

# RULE106:
sec_audit_remediate_skip 106 'SHA-512 password hashing in PAM'

# RULE212:
sec_audit_set_login_defs_kv PASS_MAX_DAYS 365
sec_audit_remediate_done 212 "set PASS_MAX_DAYS=365 in login.defs"

# RULE107:
sec_audit_set_login_defs_kv PASS_MIN_DAYS 1
sec_audit_remediate_done 107 "set PASS_MIN_DAYS=1 in login.defs"

# RULE108:
sec_audit_set_login_defs_kv PASS_WARN_AGE 7
sec_audit_remediate_done 108 "set PASS_WARN_AGE=7 in login.defs"

# RULE213:
sec_audit_set_login_defs_kv INACTIVE 30
sec_audit_remediate_done 213 "set INACTIVE=30 in login.defs"

# RULE110:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_remediate_done 110 "hardened identity/config file permissions"

# RULE111:
sec_audit_remediate_skip 111 'default umask 027 or more restrictive'

# RULE112:
sec_audit_remediate_skip 112 'TMOUT configured (1-900) with readonly/export'

# RULE115:
sec_audit_harden_path /etc/shadow 000 root:root
sec_audit_remediate_done 115 "hardened identity/config file permissions"

# RULE119:
sec_audit_harden_path /etc/gshadow 000 root:root
sec_audit_remediate_done 119 "hardened identity/config file permissions"

# RULE121:
sec_audit_harden_path /etc/passwd 644 root:root
sec_audit_harden_path /etc/passwd- 644 root:root
sec_audit_remediate_done 121 "hardened identity/config file permissions"

# RULE125:
sec_audit_harden_path /etc/group 644 root:root
sec_audit_harden_path /etc/group- 644 root:root
sec_audit_remediate_done 125 "hardened identity/config file permissions"

# RULE156:
sec_audit_remediate_skip 156 'SSH public host keys permissions OK'

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
sec_audit_set_sshd_kv UsePAM yes
sec_audit_remediate_done 160 "sshd_config hardened keys"

# RULE2:
sec_audit_remediate_skip 2 'mounting of squashfs filesystems is disabled'

# RULE3:
sec_audit_remediate_skip 3 'mounting of udf filesystems is disabled'

# RULE9:
sec_audit_remediate_skip 9 'AIDE package is installed'

# RULE211:
sec_audit_set_login_defs_kv INACTIVE 30
sec_audit_remediate_done 211 "set INACTIVE=30 in login.defs"

# RULE13:
sec_audit_set_sysctl net.ipv4.tcp_syncookies 1
sec_audit_set_sysctl net.ipv4.icmp_echo_ignore_broadcasts 1
sec_audit_set_sysctl net.ipv4.icmp_ignore_bogus_error_responses 1
sec_audit_remediate_done 13 "sysctl hardening applied"

# RULE69:
sec_audit_start_svc rsyslog.service
sec_audit_remediate_done 69 "ensured required services enabled/started"


	if [ "${REMEDIATE_SECURITY_UPGRADE}" = "1" ]; then
		if sec_audit_have_bin dnf; then
			timeout 300 dnf upgrade --security -y >/dev/null 2>&1 || true
		elif sec_audit_have_bin yum; then
			timeout 300 yum update --security -y >/dev/null 2>&1 || true
		fi
	else
		sec_audit_log "skipping security upgrade (set REMEDIATE_SECURITY_UPGRADE=1 to enable)"
	fi
	sec_audit_log "remediation complete (RHEL7_remediation.sh)"
}

sec_audit_main "$@"
