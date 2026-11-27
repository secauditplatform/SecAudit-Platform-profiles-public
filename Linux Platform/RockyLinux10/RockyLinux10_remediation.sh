#!/bin/bash

# SecAudit rule allowlist — source or paste into audit/remediation shell scripts.
# Unset/empty SECAUDIT_RULES and SECAUDIT_REMEDIATE_RULES => all rules enabled.
secaudit_rule_enabled() {
    local raw="${SECAUDIT_RULES:-${SECAUDIT_REMEDIATE_RULES:-}}" id="$1" token n want
    [ -z "$raw" ] && return 0
    n="${id#RULE}"; n="${n#rule}"; n="${n#Rule}"
    case "$n" in (*[!0-9]*|"") want=$(printf '%s' "$id" | tr '[:lower:]' '[:upper:]') ;;
        *) want="RULE$((10#$n))" ;;
    esac
    local IFS=','
    for token in $raw; do
        token=$(printf '%s' "$token" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')
        [ -z "$token" ] && continue
        local tn="${token#RULE}"
        case "$tn" in (*[!0-9]*|"") ;;
            *) token="RULE$((10#$tn))" ;;
        esac
        [ "$token" = "$want" ] && return 0
    done
    return 1
}

# --- bootstrap / reporting ---
sec_audit_report_pass() { secaudit_rule_enabled "$1" || return 0; printf 'RULE%s= PASS: %s\n' "$1" "$2"; }
sec_audit_report_fail() { secaudit_rule_enabled "$1" || return 0; printf 'RULE%s= FAIL: %s\n' "$1" "${3:-$2}"; }
sec_audit_report_skip() { secaudit_rule_enabled "$1" || return 0; printf 'RULE%s= SKIP: %s\n' "$1" "$2"; }
sec_audit_report_error() { secaudit_rule_enabled "$1" || return 0; printf 'RULE%s= ERROR: %s\n' "$1" "$2"; }
sec_audit_report_review() { secaudit_rule_enabled "$1" || return 0; printf 'RULE%s= REVIEW: %s\n' "$1" "$2"; }
sec_audit_report_warn() { secaudit_rule_enabled "$1" || return 0; printf 'RULE%s= WARN: %s\n' "$1" "$2"; }

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

sec_audit_disable_kmod() {
	local mod="$1" f
	[ -n "$mod" ] || return 0
	mkdir -p /etc/modprobe.d
	f="/etc/modprobe.d/sec-audit-disable-${mod}.conf"
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
	local key="$1" val="$2" f="/etc/sysctl.d/99-rocky10-cre-.conf"
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

sec_audit_remediate_done() { secaudit_rule_enabled "$1" || return 0; printf '[remediation] REMEDIATE RULE%s= applied: %s\n' "$1" "$2"; }
sec_audit_remediate_skip() { secaudit_rule_enabled "$1" || return 0; printf '[remediation] REMEDIATE RULE%s= SKIP: manual step required - %s\n' "$1" "$2"; }

# =============================================================================
# Section runners
# =============================================================================

sec_audit_remediate_kernel_modules() {
# RULE1-11
if secaudit_rule_enabled 1; then
sec_audit_disable_kmod cramfs
sec_audit_remediate_done 1 "blacklisted kernel module cramfs"

fi
if secaudit_rule_enabled 2; then
sec_audit_disable_kmod freevxfs
sec_audit_remediate_done 2 "blacklisted kernel module freevxfs"

fi
if secaudit_rule_enabled 3; then
sec_audit_disable_kmod hfs
sec_audit_remediate_done 3 "blacklisted kernel module hfs"

fi
if secaudit_rule_enabled 4; then
sec_audit_disable_kmod hfsplus
sec_audit_remediate_done 4 "blacklisted kernel module hfsplus"

fi
if secaudit_rule_enabled 5; then
sec_audit_disable_kmod jffs2
sec_audit_remediate_done 5 "blacklisted kernel module jffs2"

fi
if secaudit_rule_enabled 6; then
sec_audit_disable_kmod overlay
sec_audit_remediate_done 6 "blacklisted kernel module overlay"

fi
if secaudit_rule_enabled 7; then
sec_audit_disable_kmod squashfs
sec_audit_remediate_done 7 "blacklisted kernel module squashfs"

fi
if secaudit_rule_enabled 8; then
sec_audit_disable_kmod udf
sec_audit_remediate_done 8 "blacklisted kernel module udf"

fi
if secaudit_rule_enabled 9; then
sec_audit_disable_kmod firewire-core
sec_audit_remediate_done 9 "blacklisted kernel module firewire-core"

fi
if secaudit_rule_enabled 10; then
sec_audit_disable_kmod usb-storage
sec_audit_remediate_done 10 "blacklisted kernel module usb-storage"

fi
if secaudit_rule_enabled 11; then
sec_audit_remediate_skip 11 "Ensure unused filesystems kernel modules are not available"

fi
}

sec_audit_remediate_filesystem_partitions() {
# RULE12-37
if secaudit_rule_enabled 12; then
sec_audit_remediate_skip 12 "Ensure /tmp is tmpfs or a separate partition"

fi
if secaudit_rule_enabled 13; then
sec_audit_ensure_mount_option /tmp nodev
sec_audit_remediate_done 13 "set nodev on /tmp"

fi
if secaudit_rule_enabled 14; then
sec_audit_remediate_skip 14 "Ensure nosuid option set on /tmp partition"

fi
if secaudit_rule_enabled 15; then
sec_audit_ensure_mount_option /tmp noexec
sec_audit_remediate_done 15 "set noexec on /tmp"

fi
if secaudit_rule_enabled 16; then
sec_audit_remediate_skip 16 "Ensure /dev/shm is tmpfs or a separate partition"

fi
if secaudit_rule_enabled 17; then
sec_audit_ensure_mount_option /dev/shm nodev
sec_audit_remediate_done 17 "set nodev on /dev/shm"

fi
if secaudit_rule_enabled 18; then
sec_audit_remediate_skip 18 "Ensure nosuid option set on /dev/shm partition"

fi
if secaudit_rule_enabled 19; then
sec_audit_ensure_mount_option /dev/shm noexec
sec_audit_remediate_done 19 "set noexec on /dev/shm"

fi
if secaudit_rule_enabled 20; then
sec_audit_remediate_skip 20 "Ensure separate partition exists for /home"

fi
if secaudit_rule_enabled 21; then
sec_audit_ensure_mount_option /home nodev
sec_audit_remediate_done 21 "set nodev on /home"

fi
if secaudit_rule_enabled 22; then
sec_audit_remediate_skip 22 "Ensure nosuid option set on /home partition"

fi
if secaudit_rule_enabled 23; then
sec_audit_remediate_skip 23 "Ensure separate partition exists for /var"

fi
if secaudit_rule_enabled 24; then
sec_audit_ensure_mount_option /var nodev
sec_audit_remediate_done 24 "set nodev on /var"

fi
if secaudit_rule_enabled 25; then
sec_audit_remediate_skip 25 "Ensure nosuid option set on /var partition"

fi
if secaudit_rule_enabled 26; then
sec_audit_remediate_skip 26 "Ensure separate partition exists for /var/tmp"

fi
if secaudit_rule_enabled 27; then
sec_audit_ensure_mount_option /var/tmp nodev
sec_audit_remediate_done 27 "set nodev on /var/tmp"

fi
if secaudit_rule_enabled 28; then
sec_audit_remediate_skip 28 "Ensure nosuid option set on /var/tmp partition"

fi
if secaudit_rule_enabled 29; then
sec_audit_ensure_mount_option /var/tmp noexec
sec_audit_remediate_done 29 "set noexec on /var/tmp"

fi
if secaudit_rule_enabled 30; then
sec_audit_remediate_skip 30 "Ensure separate partition exists for /var/log"

fi
if secaudit_rule_enabled 31; then
sec_audit_ensure_mount_option /var/log nodev
sec_audit_remediate_done 31 "set nodev on /var/log"

fi
if secaudit_rule_enabled 32; then
sec_audit_remediate_skip 32 "Ensure nosuid option set on /var/log partition"

fi
if secaudit_rule_enabled 33; then
sec_audit_ensure_mount_option /var/log noexec
sec_audit_remediate_done 33 "set noexec on /var/log"

fi
if secaudit_rule_enabled 34; then
sec_audit_remediate_skip 34 "Ensure separate partition exists for /var/log/audit"

fi
if secaudit_rule_enabled 35; then
sec_audit_ensure_mount_option /var/log/audit nodev
sec_audit_remediate_done 35 "set nodev on /var/log/audit"

fi
if secaudit_rule_enabled 36; then
sec_audit_remediate_skip 36 "Ensure nosuid option set on /var/log/audit partition"

fi
if secaudit_rule_enabled 37; then
sec_audit_ensure_mount_option /var/log/audit noexec
sec_audit_remediate_done 37 "set noexec on /var/log/audit"

fi
}

sec_audit_remediate_package_security() {
# RULE38-43
if secaudit_rule_enabled 38; then
sec_audit_remediate_skip 38 "Ensure GPG keys are configured"

fi
if secaudit_rule_enabled 39; then
sec_audit_set_dnf_main_kv gpgcheck 1
sec_audit_set_dnf_main_kv localpkg_gpgcheck 1
sec_audit_remediate_done 39 "enabled gpgcheck"

fi
if secaudit_rule_enabled 40; then
sec_audit_remediate_skip 40 "Ensure repo_gpgcheck is globally activated"

fi
if secaudit_rule_enabled 41; then
sec_audit_remediate_skip 41 "Ensure package manager repositories are configured"

fi
if secaudit_rule_enabled 42; then
sec_audit_remediate_skip 42 "Ensure weak dependencies are configured (: disable installing weak deps by default)"

fi
if secaudit_rule_enabled 43; then
sec_audit_remediate_skip 43 "Ensure updates, patches, and additional security software are installed"

fi
}

sec_audit_remediate_selinux() {
# RULE44-51
if secaudit_rule_enabled 44; then
sec_audit_pkg_install libselinux
sec_audit_remediate_done 44 "installed SELinux"

fi
if secaudit_rule_enabled 45; then
if sec_audit_have_bin grubby; then
	grubby --update-kernel=ALL --remove-args="selinux=0 enforcing=0" >/dev/null 2>&1 || true
fi
sec_audit_remediate_done 45 "removed selinux=0 from bootloader"

fi
if secaudit_rule_enabled 46; then
[[ -f /etc/selinux/config ]] && {
	sed -i "s/^SELINUXTYPE=.*/SELINUXTYPE=targeted/" /etc/selinux/config 2>/dev/null || true
	grep -q "^SELINUXTYPE=" /etc/selinux/config || echo "SELINUXTYPE=targeted" >>/etc/selinux/config
}
sec_audit_remediate_done 46 "SELINUXTYPE=targeted"

fi
if secaudit_rule_enabled 47; then
[[ -f /etc/selinux/config ]] && sed -i "s/^SELINUX=.*/SELINUX=enforcing/" /etc/selinux/config 2>/dev/null || true
sec_audit_have_bin setenforce && setenforce 1 >/dev/null 2>&1 || true
sec_audit_remediate_done 47 "SELinux not disabled"

fi
if secaudit_rule_enabled 48; then
[[ -f /etc/selinux/config ]] && sed -i "s/^SELINUX=.*/SELINUX=enforcing/" /etc/selinux/config 2>/dev/null || true
sec_audit_have_bin setenforce && setenforce 1 >/dev/null 2>&1 || true
sec_audit_remediate_done 48 "SELinux enforcing"

fi
if secaudit_rule_enabled 49; then
sec_audit_remediate_skip 49 "Ensure no unconfined services exist"

fi
if secaudit_rule_enabled 50; then
sec_audit_remediate_skip 50 "review  remediation: Ensure the MCS Translation Service"

fi
if secaudit_rule_enabled 51; then
sec_audit_pkg_remove setroubleshoot
sec_audit_disable_svc setroubleshoot.service
sec_audit_remediate_done 51 "removed setroubleshoot"

fi
}

sec_audit_remediate_bootloader() {
# RULE52-54
if secaudit_rule_enabled 52; then
sec_audit_remediate_skip 52 "Ensure bootloader password is set"

fi
if secaudit_rule_enabled 53; then
sec_audit_harden_file /boot/grub2/grub.cfg 600 root:root
sec_audit_harden_file /boot/grub2/user.cfg 600 root:root
sec_audit_remediate_done 53 "hardened grub permissions"

fi
if secaudit_rule_enabled 54; then
grep -q "hard core" /etc/security/limits.conf 2>/dev/null || echo "* hard core 0" >>/etc/security/limits.conf
mkdir -p /etc/systemd/coredump.conf.d
cat >/etc/systemd/coredump.conf.d/99-cre-.conf <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
sec_audit_have_bin systemctl && systemctl daemon-reload >/dev/null 2>&1 || true
sec_audit_remediate_done 54 "disabled core dumps"

fi
}

sec_audit_remediate_process_hardening() {
# RULE55-63
if secaudit_rule_enabled 55; then
sec_audit_set_sysctl fs.protected_hardlinks 1
sec_audit_remediate_done 55 "set fs.protected_hardlinks=1"

fi
if secaudit_rule_enabled 56; then
sec_audit_set_sysctl fs.protected_symlinks 1
sec_audit_remediate_done 56 "set fs.protected_symlinks=1"

fi
if secaudit_rule_enabled 57; then
sec_audit_remediate_skip 57 "Ensure fs.suid_dumpable is configured"

fi
if secaudit_rule_enabled 58; then
sec_audit_set_sysctl kernel.dmesg_restrict 1
sec_audit_remediate_done 58 "set kernel.dmesg_restrict=1"

fi
if secaudit_rule_enabled 59; then
sec_audit_set_sysctl kernel.kptr_restrict 2
sec_audit_remediate_done 59 "set kernel.kptr_restrict=2"

fi
if secaudit_rule_enabled 60; then
sec_audit_set_sysctl kernel.yama.ptrace_scope 1
sec_audit_remediate_done 60 "set kernel.yama.ptrace_scope=1"

fi
if secaudit_rule_enabled 61; then
sec_audit_set_sysctl kernel.randomize_va_space 2
sec_audit_remediate_done 61 "set kernel.randomize_va_space=2"

fi
if secaudit_rule_enabled 62; then
sec_audit_set_sysctl fs.suid_dumpable 0
sec_audit_remediate_done 62 "coredump limits via sysctl/coredump.conf"

fi
if secaudit_rule_enabled 63; then
mkdir -p /etc/systemd/coredump.conf.d
cat >/etc/systemd/coredump.conf.d/99-cre-.conf <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
sec_audit_remediate_done 63 "systemd-coredump Storage=none"

fi
}

sec_audit_remediate_crypto_policy() {
# RULE64-67
if secaudit_rule_enabled 64; then
sec_audit_have_bin update-crypto-policies && update-crypto-policies --set DEFAULT >/dev/null 2>&1 || true
sec_audit_remediate_done 64 "crypto policy not LEGACY"

fi
if secaudit_rule_enabled 65; then
sec_audit_have_bin update-crypto-policies && update-crypto-policies --set DEFAULT:NO-SHA1:NO-SSHCBC >/dev/null 2>&1 || update-crypto-policies --set DEFAULT >/dev/null 2>&1 || true
sec_audit_remediate_done 65 "applied DEFAULT crypto policy modules"

fi
if secaudit_rule_enabled 66; then
sec_audit_have_bin update-crypto-policies && update-crypto-policies --set DEFAULT:NO-SHA1:NO-SSHCBC >/dev/null 2>&1 || update-crypto-policies --set DEFAULT >/dev/null 2>&1 || true
sec_audit_remediate_done 66 "applied DEFAULT crypto policy modules"

fi
if secaudit_rule_enabled 67; then
sec_audit_remediate_skip 67 "Ensure system wide crypto policy disables cbc for ssh"

fi
}

sec_audit_remediate_banners() {
# RULE68-74
if secaudit_rule_enabled 68; then
[[ -f /etc/motd ]] || echo "Authorized use only." >/etc/motd
sed -i 's/\\[vVrms]//g' /etc/motd 2>/dev/null || true
sec_audit_remediate_done 68 "sanitized banner /etc/motd"

fi
if secaudit_rule_enabled 69; then
[[ -f /etc/issue ]] || echo "Authorized use only." >/etc/issue
sed -i 's/\\[vVrms]//g' /etc/issue 2>/dev/null || true
sec_audit_remediate_done 69 "sanitized banner /etc/issue"

fi
if secaudit_rule_enabled 70; then
[[ -f /etc/issue.net ]] || echo "Authorized use only." >/etc/issue.net
sed -i 's/\\[vVrms]//g' /etc/issue.net 2>/dev/null || true
sec_audit_remediate_done 70 "sanitized banner /etc/issue.net"

fi
if secaudit_rule_enabled 71; then
sec_audit_harden_file /etc/motd 644 root:root
sec_audit_remediate_done 71 "permissions /etc/motd"

fi
if secaudit_rule_enabled 72; then
sec_audit_harden_file /etc/issue 644 root:root
sec_audit_remediate_done 72 "permissions /etc/issue"

fi
if secaudit_rule_enabled 73; then
sec_audit_harden_file /etc/issue.net 644 root:root
sec_audit_remediate_done 73 "permissions /etc/issue.net"

fi
if secaudit_rule_enabled 74; then
mkdir -p /etc/dconf/db/gdm.d
sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
sec_audit_remediate_done 74 "configured GDM hardening"

fi
}

sec_audit_remediate_gdm() {
# RULE75-79
if secaudit_rule_enabled 75; then
mkdir -p /etc/dconf/db/gdm.d
sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
sec_audit_remediate_done 75 "configured GDM hardening"

fi
if secaudit_rule_enabled 76; then
mkdir -p /etc/dconf/db/gdm.d
sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
sec_audit_remediate_done 76 "configured GDM hardening"

fi
if secaudit_rule_enabled 77; then
mkdir -p /etc/dconf/db/gdm.d
sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
sec_audit_remediate_done 77 "configured GDM hardening"

fi
if secaudit_rule_enabled 78; then
mkdir -p /etc/dconf/db/gdm.d
sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
sec_audit_remediate_done 78 "configured GDM hardening"

fi
if secaudit_rule_enabled 79; then
mkdir -p /etc/dconf/db/gdm.d
sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
sec_audit_remediate_done 79 "configured GDM hardening"

fi

}

sec_audit_remediate_unused_services() {
# RULE80-101
if secaudit_rule_enabled 80; then
sec_audit_disable_svc autofs.service
sec_audit_pkg_remove autofs
sec_audit_remediate_done 80 "disabled autofs"

fi
if secaudit_rule_enabled 81; then
sec_audit_disable_svc avahi-daemon.socket
sec_audit_disable_svc avahi-daemon.service
sec_audit_pkg_remove avahi
sec_audit_remediate_done 81 "disabled avahi"

fi
if secaudit_rule_enabled 82; then
sec_audit_disable_svc cockpit.socket
sec_audit_disable_svc cockpit.service
sec_audit_pkg_remove cockpit-ws
sec_audit_remediate_done 82 "disabled cockpit-ws"

fi
if secaudit_rule_enabled 83; then
sec_audit_disable_svc dhcpd.service
sec_audit_disable_svc dhcpd6.service
sec_audit_pkg_remove dhcp-server
sec_audit_remediate_done 83 "disabled dhcp-server"

fi
if secaudit_rule_enabled 84; then
sec_audit_disable_svc named.service
sec_audit_pkg_remove bind
sec_audit_remediate_done 84 "disabled bind"

fi
if secaudit_rule_enabled 85; then
sec_audit_disable_svc dnsmasq.service
sec_audit_pkg_remove dnsmasq
sec_audit_remediate_done 85 "disabled dnsmasq"

fi
if secaudit_rule_enabled 86; then
sec_audit_disable_svc vsftpd.service
sec_audit_pkg_remove vsftpd
sec_audit_remediate_done 86 "disabled vsftpd"

fi
if secaudit_rule_enabled 87; then
sec_audit_remediate_skip 87 "review  remediation: Ensure message access server services are not in use"

fi
if secaudit_rule_enabled 88; then
sec_audit_remediate_skip 88 "review  remediation: Ensure network file system services are not in use"

fi
if secaudit_rule_enabled 89; then
sec_audit_remediate_skip 89 "review  remediation: Ensure print server services are not in use"

fi
if secaudit_rule_enabled 90; then
sec_audit_disable_svc rpcbind.socket
sec_audit_disable_svc rpcbind.service
sec_audit_pkg_remove rpcbind
sec_audit_remediate_done 90 "disabled rpcbind"

fi
if secaudit_rule_enabled 91; then
sec_audit_disable_svc rsyncd.socket
sec_audit_disable_svc rsyncd.service
sec_audit_pkg_remove rsync-daemon
sec_audit_remediate_done 91 "disabled rsync-daemon"

fi
if secaudit_rule_enabled 92; then
sec_audit_disable_svc smb.service
sec_audit_disable_svc smbd.service
sec_audit_pkg_remove samba
sec_audit_remediate_done 92 "disabled samba"

fi
if secaudit_rule_enabled 93; then
sec_audit_disable_svc snmpd.service
sec_audit_pkg_remove net-snmp
sec_audit_remediate_done 93 "disabled net-snmp"

fi
if secaudit_rule_enabled 94; then
sec_audit_disable_svc telnet.socket
sec_audit_pkg_remove telnet-server
sec_audit_remediate_done 94 "disabled telnet-server"

fi
if secaudit_rule_enabled 95; then
sec_audit_disable_svc vsftpd.service
sec_audit_pkg_remove vsftpd
sec_audit_remediate_done 95 "disabled vsftpd"

fi
if secaudit_rule_enabled 96; then
sec_audit_remediate_skip 96 "review  remediation: Ensure web proxy server services are not in use"

fi
if secaudit_rule_enabled 97; then
sec_audit_remediate_skip 97 "review  remediation: Ensure web server services are not in use"

fi
if secaudit_rule_enabled 98; then
sec_audit_remediate_skip 98 "review  remediation: Ensure GNOME Display Manager is removed"

fi
if secaudit_rule_enabled 99; then
sec_audit_remediate_skip 99 "review  remediation: Ensure X window server services are not in use"

fi
if secaudit_rule_enabled 100; then
sec_audit_remediate_skip 100 "review  remediation: Ensure mail transfer agents are configured for local-only mode"

fi
if secaudit_rule_enabled 101; then
sec_audit_remediate_skip 101 "Ensure only approved services are listening on a network interface"

fi
}

sec_audit_remediate_client_tools() {
# RULE102-105
if secaudit_rule_enabled 102; then
sec_audit_pkg_remove ftp
sec_audit_remediate_done 102 "removed ftp"

fi
if secaudit_rule_enabled 103; then
sec_audit_pkg_remove ldap-utils
sec_audit_remediate_done 103 "removed ldap-utils"

fi
if secaudit_rule_enabled 104; then
sec_audit_pkg_remove telnet
sec_audit_remediate_done 104 "removed telnet"

fi
if secaudit_rule_enabled 105; then
sec_audit_pkg_remove tftp
sec_audit_remediate_done 105 "removed tftp"

fi
}

sec_audit_remediate_chrony() {
# RULE106-108
if secaudit_rule_enabled 106; then
sec_audit_pkg_install chrony
sec_audit_start_svc chronyd
sec_audit_remediate_done 106 "installed chrony"

fi
if secaudit_rule_enabled 107; then
sec_audit_pkg_install chrony
grep -q "^pool \|^server " /etc/chrony.conf 2>/dev/null || echo "pool 2.pool.ntp.org iburst" >>/etc/chrony.conf
sec_audit_start_svc chronyd
sec_audit_remediate_done 107 "configured chrony"

fi
if secaudit_rule_enabled 108; then
sec_audit_remediate_skip 108 "review  remediation: Ensure chrony is not run as the root user"

fi
}

sec_audit_remediate_cron_at() {
# RULE109-118
if secaudit_rule_enabled 109; then
sec_audit_pkg_install cronie
sec_audit_start_svc crond
sec_audit_remediate_done 109 "enabled crond"

fi
if secaudit_rule_enabled 110; then
chmod 600 /etc/crontab 2>/dev/null || true
chown root:root /etc/crontab 2>/dev/null || true
sec_audit_remediate_done 110 "restricted /etc/crontab"

fi
if secaudit_rule_enabled 111; then
sec_audit_remediate_skip 111 "review  remediation: Ensure access to /etc/cron.hourly is configured"

fi
if secaudit_rule_enabled 112; then
sec_audit_remediate_skip 112 "review  remediation: Ensure access to /etc/cron.daily is configured"

fi
if secaudit_rule_enabled 113; then
sec_audit_remediate_skip 113 "review  remediation: Ensure access to /etc/cron.weekly is configured"

fi
if secaudit_rule_enabled 114; then
sec_audit_remediate_skip 114 "review  remediation: Ensure access to /etc/cron.monthly is configured"

fi
if secaudit_rule_enabled 115; then
sec_audit_remediate_skip 115 "review  remediation: Ensure access to /etc/cron.yearly is configured"

fi
if secaudit_rule_enabled 116; then
sec_audit_remediate_skip 116 "review  remediation: Ensure access to /etc/cron.d is configured"

fi
if secaudit_rule_enabled 117; then
sec_audit_remediate_skip 117 "review  remediation: Ensure access to crontab is configured"

fi
if secaudit_rule_enabled 118; then
sec_audit_remediate_skip 118 "review  remediation: Ensure access to at is configured"

fi

}

sec_audit_remediate_network_stack() {
# RULE119-120
if secaudit_rule_enabled 119; then
sec_audit_remediate_skip 119 "Ensure IPv6 status is identified"

fi
if secaudit_rule_enabled 120; then
sec_audit_disable_kmod bluetooth
sec_audit_remediate_done 120 "disabled wireless interfaces"

fi
}

sec_audit_remediate_unused_services_2() {
# RULE121-121
if secaudit_rule_enabled 121; then
sec_audit_disable_svc bluetooth.service
sec_audit_pkg_remove bluez
sec_audit_remediate_done 121 "disabled bluez"

fi
}

sec_audit_remediate_kernel_modules_2() {
# RULE122-130
if secaudit_rule_enabled 122; then
sec_audit_disable_kmod is
sec_audit_remediate_done 122 "blacklisted is"

fi
if secaudit_rule_enabled 123; then
sec_audit_disable_kmod is
sec_audit_remediate_done 123 "blacklisted is"

fi
if secaudit_rule_enabled 124; then
sec_audit_disable_kmod is
sec_audit_remediate_done 124 "blacklisted is"

fi
if secaudit_rule_enabled 125; then
sec_audit_disable_kmod is
sec_audit_remediate_done 125 "blacklisted is"

fi
if secaudit_rule_enabled 126; then
sec_audit_disable_kmod is
sec_audit_remediate_done 126 "blacklisted is"

fi
if secaudit_rule_enabled 127; then
sec_audit_disable_kmod is
sec_audit_remediate_done 127 "blacklisted is"

fi
if secaudit_rule_enabled 128; then
sec_audit_set_sysctl net.ipv4.ip_forward 0
sec_audit_remediate_done 128 "set net.ipv4.ip_forward=0"

fi
if secaudit_rule_enabled 129; then
sec_audit_remediate_skip 129 "review  remediation: Ensure net.ipv4.conf.all.forwarding is configured"

fi
if secaudit_rule_enabled 130; then
sec_audit_remediate_skip 130 "review  remediation: Ensure net.ipv4.conf.default.forwarding is configured"

fi
}

sec_audit_remediate_network_stack_2() {
# RULE131-153
if secaudit_rule_enabled 131; then
sec_audit_set_sysctl net.ipv4.conf.all.send_redirects 0
sec_audit_remediate_done 131 "set net.ipv4.conf.all.send_redirects=0"

fi
if secaudit_rule_enabled 132; then
sec_audit_set_sysctl net.ipv4.conf.all.send_redirects 0
sec_audit_remediate_done 132 "set net.ipv4.conf.all.send_redirects=0"

fi
if secaudit_rule_enabled 133; then
sec_audit_set_sysctl net.ipv4.icmp_ignore_bogus_error_responses 1
sec_audit_remediate_done 133 "set net.ipv4.icmp_ignore_bogus_error_responses=1"

fi
if secaudit_rule_enabled 134; then
sec_audit_remediate_skip 134 "review  remediation: Ensure net.ipv4.icmp_echo_ignore_broadcasts is configured"

fi
if secaudit_rule_enabled 135; then
sec_audit_set_sysctl net.ipv4.conf.all.accept_redirects 0
sec_audit_remediate_done 135 "set net.ipv4.conf.all.accept_redirects=0"

fi
if secaudit_rule_enabled 136; then
sec_audit_set_sysctl net.ipv4.conf.all.accept_redirects 0
sec_audit_remediate_done 136 "set net.ipv4.conf.all.accept_redirects=0"

fi
if secaudit_rule_enabled 137; then
sec_audit_set_sysctl net.ipv4.conf.all.secure_redirects 0
sec_audit_remediate_done 137 "set net.ipv4.conf.all.secure_redirects=0"

fi
if secaudit_rule_enabled 138; then
sec_audit_set_sysctl net.ipv4.conf.all.secure_redirects 0
sec_audit_remediate_done 138 "set net.ipv4.conf.all.secure_redirects=0"

fi
if secaudit_rule_enabled 139; then
sec_audit_set_sysctl net.ipv4.conf.all.rp_filter 1
sec_audit_remediate_done 139 "set net.ipv4.conf.all.rp_filter=1"

fi
if secaudit_rule_enabled 140; then
sec_audit_set_sysctl net.ipv4.conf.all.rp_filter 1
sec_audit_remediate_done 140 "set net.ipv4.conf.all.rp_filter=1"

fi
if secaudit_rule_enabled 141; then
sec_audit_remediate_skip 141 "review  remediation: Ensure net.ipv4.conf.all.accept_source_route is configured"

fi
if secaudit_rule_enabled 142; then
sec_audit_remediate_skip 142 "review  remediation: Ensure net.ipv4.conf.default.accept_source_route is configured"

fi
if secaudit_rule_enabled 143; then
sec_audit_set_sysctl net.ipv4.conf.all.log_martians 1
sec_audit_remediate_done 143 "set net.ipv4.conf.all.log_martians=1"

fi
if secaudit_rule_enabled 144; then
sec_audit_set_sysctl net.ipv4.conf.all.log_martians 1
sec_audit_remediate_done 144 "set net.ipv4.conf.all.log_martians=1"

fi
if secaudit_rule_enabled 145; then
sec_audit_set_sysctl net.ipv4.tcp_syncookies 1
sec_audit_remediate_done 145 "set net.ipv4.tcp_syncookies=1"

fi
if secaudit_rule_enabled 146; then
sec_audit_remediate_skip 146 "Ensure net.ipv6.conf.all.forwarding is configured"

fi
if secaudit_rule_enabled 147; then
sec_audit_remediate_skip 147 "Ensure net.ipv6.conf.default.forwarding is configured"

fi
if secaudit_rule_enabled 148; then
sec_audit_remediate_skip 148 "Ensure net.ipv6.conf.all.accept_redirects is configured"

fi
if secaudit_rule_enabled 149; then
sec_audit_remediate_skip 149 "Ensure net.ipv6.conf.default.accept_redirects is configured"

fi
if secaudit_rule_enabled 150; then
sec_audit_remediate_skip 150 "Ensure net.ipv6.conf.all.accept_source_route is configured"

fi
if secaudit_rule_enabled 151; then
sec_audit_remediate_skip 151 "Ensure net.ipv6.conf.default.accept_source_route is configured"

fi
if secaudit_rule_enabled 152; then
sec_audit_remediate_skip 152 "Ensure net.ipv6.conf.all.accept_ra is configured"

fi
if secaudit_rule_enabled 153; then
sec_audit_remediate_skip 153 "Ensure net.ipv6.conf.default.accept_ra is configured"

fi

}

sec_audit_remediate_firewalld() {
# RULE154-159
if secaudit_rule_enabled 154; then
sec_audit_pkg_install firewalld
sec_audit_start_svc firewalld
sec_audit_remediate_done 154 "installed firewalld"

fi
if secaudit_rule_enabled 155; then
sec_audit_remediate_skip 155 "review  remediation: Ensure firewalld backend is configured"

fi
if secaudit_rule_enabled 156; then
sec_audit_remediate_skip 156 "review  remediation: Ensure firewalld.service is configured"

fi
if secaudit_rule_enabled 157; then
sec_audit_remediate_skip 157 "review  remediation: Ensure firewalld active zone target is configured"

fi
if secaudit_rule_enabled 158; then
sec_audit_remediate_skip 158 "Ensure firewalld loopback traffic is configured"

fi
if secaudit_rule_enabled 159; then
sec_audit_remediate_skip 159 "Ensure firewalld loopback source address traffic is configured"

fi
}

sec_audit_remediate_unused_services_3() {
# RULE160-160
if secaudit_rule_enabled 160; then
sec_audit_remediate_skip 160 "Ensure firewalld services and ports are configured"

fi

}

sec_audit_remediate_sshd() {
# RULE161-182
if secaudit_rule_enabled 161; then
sec_audit_remediate_skip 161 "review  remediation: Ensure access to /etc/ssh/sshd_config is configured"

fi
if secaudit_rule_enabled 162; then
sec_audit_remediate_skip 162 "review  remediation: Ensure access to SSH private host key files is configured"

fi
if secaudit_rule_enabled 163; then
sec_audit_remediate_skip 163 "review  remediation: Ensure access to SSH public host key files is configured"

fi
if secaudit_rule_enabled 164; then
sec_audit_remediate_skip 164 "review  remediation: Ensure sshd access is configured"

fi
if secaudit_rule_enabled 165; then
sec_audit_set_sshd_kv Banner /etc/issue.net
sec_audit_remediate_done 165 "sshd Banner"

fi
if secaudit_rule_enabled 166; then
sec_audit_remediate_skip 166 "review  remediation: Ensure sshd Ciphers are configured"

fi
if secaudit_rule_enabled 167; then
sec_audit_set_sshd_kv ClientAliveInterval 300
sec_audit_remediate_done 167 "sshd ClientAliveInterval"

fi
if secaudit_rule_enabled 168; then
sec_audit_set_sshd_kv DisableForwarding yes
sec_audit_remediate_done 168 "sshd DisableForwarding"

fi
if secaudit_rule_enabled 169; then
sec_audit_set_sshd_kv GSSAPIAuthentication no
sec_audit_remediate_done 169 "sshd GSSAPIAuthentication"

fi
if secaudit_rule_enabled 170; then
sec_audit_set_sshd_kv HostbasedAuthentication no
sec_audit_remediate_done 170 "sshd HostbasedAuthentication"

fi
if secaudit_rule_enabled 171; then
sec_audit_set_sshd_kv IgnoreRhosts yes
sec_audit_remediate_done 171 "sshd IgnoreRhosts"

fi
if secaudit_rule_enabled 172; then
sec_audit_remediate_skip 172 "review  remediation: Ensure sshd KexAlgorithms is configured"

fi
if secaudit_rule_enabled 173; then
sec_audit_set_sshd_kv LoginGraceTime 60
sec_audit_remediate_done 173 "sshd LoginGraceTime"

fi
if secaudit_rule_enabled 174; then
sec_audit_set_sshd_kv LogLevel VERBOSE
sec_audit_remediate_done 174 "sshd LogLevel"

fi
if secaudit_rule_enabled 175; then
sec_audit_remediate_skip 175 "review  remediation: Ensure sshd MACs are configured"

fi
if secaudit_rule_enabled 176; then
sec_audit_set_sshd_kv MaxAuthTries 4
sec_audit_remediate_done 176 "sshd MaxAuthTries"

fi
if secaudit_rule_enabled 177; then
sec_audit_set_sshd_kv MaxStartups 10:30:60
sec_audit_remediate_done 177 "sshd MaxStartups"

fi
if secaudit_rule_enabled 178; then
sec_audit_set_sshd_kv MaxSessions 10
sec_audit_remediate_done 178 "sshd MaxSessions"

fi
if secaudit_rule_enabled 179; then
sec_audit_set_sshd_kv PermitEmptyPasswords no
sec_audit_remediate_done 179 "sshd PermitEmptyPasswords"

fi
if secaudit_rule_enabled 180; then
sec_audit_set_sshd_kv PermitRootLogin no
sec_audit_remediate_done 180 "sshd PermitRootLogin"

fi
if secaudit_rule_enabled 181; then
sec_audit_set_sshd_kv PermitUserEnvironment no
sec_audit_remediate_done 181 "sshd PermitUserEnvironment"

fi
if secaudit_rule_enabled 182; then
sec_audit_set_sshd_kv UsePAM yes
sec_audit_remediate_done 182 "sshd UsePAM"

fi
}

sec_audit_remediate_sudo_su() {
# RULE183-189
if secaudit_rule_enabled 183; then
sec_audit_pkg_install sudo
sec_audit_remediate_done 183 "sudo installed"

fi
if secaudit_rule_enabled 184; then
sec_audit_remediate_skip 184 "review  remediation: Ensure sudo commands use pty"

fi
if secaudit_rule_enabled 185; then
sec_audit_remediate_skip 185 "review  remediation: Ensure sudo log file exists"

fi
if secaudit_rule_enabled 186; then
sec_audit_remediate_skip 186 "review  remediation: Ensure users must provide password for escalation"

fi
if secaudit_rule_enabled 187; then
sec_audit_remediate_skip 187 "review  remediation: Ensure re-authentication for privilege escalation is not disabled globally"

fi
if secaudit_rule_enabled 188; then
echo "Defaults timestamp_timeout=5" >/etc/sudoers.d/99-cre-timeout
chmod 440 /etc/sudoers.d/99-cre-timeout
sec_audit_remediate_done 188 "sudo timestamp_timeout=5"

fi
if secaudit_rule_enabled 189; then
sec_audit_remediate_skip 189 "review  remediation: Ensure access to the su command is restricted"

fi
}

sec_audit_remediate_pam_auth() {
# RULE190-196
if secaudit_rule_enabled 190; then
sec_audit_remediate_skip 190 "review  remediation: Ensure active authselect profile includes pam modules"

fi
if secaudit_rule_enabled 191; then
sec_audit_authselect_enable with-faillock
authselect apply-changes >/dev/null 2>&1 || true
sec_audit_remediate_done 191 "pam faillock"

fi
if secaudit_rule_enabled 192; then
sec_audit_authselect_enable with-pwquality
sec_audit_set_pwquality_kv minlen 14
sec_audit_remediate_done 192 "password quality"

fi
if secaudit_rule_enabled 193; then
sec_audit_authselect_enable with-pwhistory
grep -q '^remember' /etc/security/pwhistory.conf 2>/dev/null || echo 'remember = 24' >>/etc/security/pwhistory.conf
sec_audit_remediate_done 193 "password history"

fi
if secaudit_rule_enabled 194; then
sec_audit_remediate_skip 194 "review  remediation: Ensure pam_unix module is enabled"

fi
if secaudit_rule_enabled 195; then
sec_audit_authselect_enable with-faillock
authselect apply-changes >/dev/null 2>&1 || true
sec_audit_remediate_done 195 "pam faillock"

fi
if secaudit_rule_enabled 196; then
sec_audit_remediate_skip 196 "review  remediation: Ensure password unlock time is configured"

fi
}

sec_audit_remediate_accounts() {
# RULE197-198
if secaudit_rule_enabled 197; then
sec_audit_remediate_skip 197 "Ensure password failed attempts lockout includes root account"

fi
if secaudit_rule_enabled 198; then
sec_audit_remediate_skip 198 "review  remediation: Ensure password number of changed characters is configured"

fi
}

sec_audit_remediate_pam_auth_2() {
# RULE199-211
if secaudit_rule_enabled 199; then
sec_audit_remediate_skip 199 "review  remediation: Ensure password length is configured"

fi
if secaudit_rule_enabled 200; then
sec_audit_remediate_skip 200 "Ensure password complexity is configured"

fi
if secaudit_rule_enabled 201; then
sec_audit_remediate_skip 201 "review  remediation: Ensure password same consecutive characters is configured"

fi
if secaudit_rule_enabled 202; then
sec_audit_remediate_skip 202 "review  remediation: Ensure password maximum sequential characters is configured"

fi
if secaudit_rule_enabled 203; then
sec_audit_remediate_skip 203 "review  remediation: Ensure password dictionary check is enabled"

fi
if secaudit_rule_enabled 204; then
sec_audit_authselect_enable with-pwquality
sec_audit_set_pwquality_kv minlen 14
sec_audit_remediate_done 204 "password quality"

fi
if secaudit_rule_enabled 205; then
sec_audit_authselect_enable with-pwhistory
grep -q '^remember' /etc/security/pwhistory.conf 2>/dev/null || echo 'remember = 24' >>/etc/security/pwhistory.conf
sec_audit_remediate_done 205 "password history"

fi
if secaudit_rule_enabled 206; then
sec_audit_authselect_enable with-pwhistory
grep -q '^remember' /etc/security/pwhistory.conf 2>/dev/null || echo 'remember = 24' >>/etc/security/pwhistory.conf
sec_audit_remediate_done 206 "password history"

fi
if secaudit_rule_enabled 207; then
sec_audit_authselect_enable with-pwhistory
grep -q '^remember' /etc/security/pwhistory.conf 2>/dev/null || echo 'remember = 24' >>/etc/security/pwhistory.conf
sec_audit_remediate_done 207 "password history"

fi
if secaudit_rule_enabled 208; then
sec_audit_remediate_skip 208 "review  remediation: Ensure pam_unix does not include nullok"

fi
if secaudit_rule_enabled 209; then
sec_audit_authselect_enable with-pwhistory
grep -q '^remember' /etc/security/pwhistory.conf 2>/dev/null || echo 'remember = 24' >>/etc/security/pwhistory.conf
sec_audit_remediate_done 209 "password history"

fi
if secaudit_rule_enabled 210; then
sec_audit_set_login_defs_kv ENCRYPT_METHOD SHA512
sec_audit_remediate_done 210 "ENCRYPT_METHOD SHA512"

fi
if secaudit_rule_enabled 211; then
sec_audit_remediate_skip 211 "review  remediation: Ensure pam_unix includes use_authtok"

fi
}

sec_audit_remediate_accounts_2() {
# RULE212-225
if secaudit_rule_enabled 212; then
sec_audit_remediate_skip 212 "review  remediation: Ensure password expiration is configured"

fi
if secaudit_rule_enabled 213; then
sec_audit_remediate_skip 213 "Ensure minimum password days is configured"

fi
if secaudit_rule_enabled 214; then
sec_audit_remediate_skip 214 "review  remediation: Ensure password expiration warning days is configured"

fi
if secaudit_rule_enabled 215; then
sec_audit_set_login_defs_kv ENCRYPT_METHOD SHA512
sec_audit_remediate_done 215 "ENCRYPT_METHOD SHA512"

fi
if secaudit_rule_enabled 216; then
sec_audit_remediate_skip 216 "Ensure inactive password lock is configured"

fi
if secaudit_rule_enabled 217; then
sec_audit_remediate_skip 217 "Ensure all users last password change date is in the past"

fi
if secaudit_rule_enabled 218; then
sec_audit_remediate_skip 218 "Ensure root is the only UID 0 account"

fi
if secaudit_rule_enabled 219; then
sec_audit_remediate_skip 219 "Ensure root is the only GID 0 account"

fi
if secaudit_rule_enabled 220; then
sec_audit_remediate_skip 220 "Ensure group root is the only GID 0 group"

fi
if secaudit_rule_enabled 221; then
sec_audit_remediate_skip 221 "Ensure root account access is controlled"

fi
if secaudit_rule_enabled 222; then
sec_audit_remediate_skip 222 "Ensure root path integrity"

fi
if secaudit_rule_enabled 223; then
sec_audit_set_login_defs_kv UMASK 027
cat >/etc/profile.d/99-cre-umask.sh <<'EOF'
umask 027
EOF
sec_audit_remediate_done 223 "default umask 027"

fi
if secaudit_rule_enabled 224; then
sec_audit_remediate_skip 224 "Ensure system accounts do not have a valid login shell"

fi
if secaudit_rule_enabled 225; then
sec_audit_remediate_skip 225 "Ensure accounts without a valid login shell are locked"

fi
}

sec_audit_remediate_identity_files() {
# RULE226-227
if secaudit_rule_enabled 226; then
sec_audit_remediate_skip 226 "review  remediation: Ensure nologin is not listed in /etc/shells"

fi
if secaudit_rule_enabled 227; then
cat >/etc/profile.d/99-cre-timeout.sh <<'EOF'
TMOUT=600
readonly TMOUT
export TMOUT
EOF
sec_audit_remediate_done 227 "TMOUT=600"

fi
}

sec_audit_remediate_accounts_3() {
# RULE228-228
if secaudit_rule_enabled 228; then
sec_audit_set_login_defs_kv UMASK 027
cat >/etc/profile.d/99-cre-umask.sh <<'EOF'
umask 027
EOF
sec_audit_remediate_done 228 "default umask 027"

fi

}

sec_audit_remediate_aide() {
# RULE229-230
if secaudit_rule_enabled 229; then
sec_audit_pkg_install aide
sec_audit_remediate_done 229 "installed AIDE"

fi
if secaudit_rule_enabled 230; then
sec_audit_pkg_install aide afick
sec_audit_remediate_done 230 "integrity tooling"

fi
}

sec_audit_remediate_crypto_policy_2() {
# RULE231-231
if secaudit_rule_enabled 231; then
sec_audit_remediate_skip 231 "review  remediation: Ensure cryptographic mechanisms are used to protect the integrity of audit tools"

fi
}

sec_audit_remediate_unused_services_4() {
# RULE232-232
if secaudit_rule_enabled 232; then
sec_audit_start_svc systemd-journald
sec_audit_remediate_done 232 "journald active"

fi
}

sec_audit_remediate_logging() {
# RULE233-251
if secaudit_rule_enabled 233; then
sec_audit_remediate_skip 233 "Ensure journald log file access is configured"

fi
if secaudit_rule_enabled 234; then
sec_audit_remediate_skip 234 "Ensure journald log file rotation is configured"

fi
if secaudit_rule_enabled 235; then
sec_audit_remediate_skip 235 "review  remediation: Ensure only one logging system is in use"

fi
if secaudit_rule_enabled 236; then
sec_audit_remediate_skip 236 "Ensure systemd-journal-remote is installed"

fi
if secaudit_rule_enabled 237; then
sec_audit_remediate_skip 237 "Ensure systemd-journal-upload authentication is configured"

fi
if secaudit_rule_enabled 238; then
sec_audit_remediate_skip 238 "Ensure systemd-journal-upload is enabled and active"

fi
if secaudit_rule_enabled 239; then
sec_audit_remediate_skip 239 "Ensure systemd-journal-remote service is not in use"

fi
if secaudit_rule_enabled 240; then
sec_audit_remediate_skip 240 "configure central logging per site policy before enabling journal remote/upload"

fi
if secaudit_rule_enabled 241; then
mkdir -p /etc/systemd/journald.conf.d
cat >/etc/systemd/journald.conf.d/99-rocky10-cre.conf <<'EOF'
[Journal]
ForwardToSyslog=no
Compress=yes
Storage=persistent
EOF
systemctl restart systemd-journald >/dev/null 2>&1 || true
sec_audit_remediate_done 241 "journald configuration"

fi
if secaudit_rule_enabled 242; then
mkdir -p /etc/systemd/journald.conf.d
cat >/etc/systemd/journald.conf.d/99-rocky10-cre.conf <<'EOF'
[Journal]
ForwardToSyslog=no
Compress=yes
Storage=persistent
EOF
systemctl restart systemd-journald >/dev/null 2>&1 || true
sec_audit_remediate_done 242 "journald configuration"

fi
if secaudit_rule_enabled 243; then
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
sec_audit_remediate_done 243 "rsyslog installed"

fi
if secaudit_rule_enabled 244; then
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
sec_audit_remediate_done 244 "rsyslog installed"

fi
if secaudit_rule_enabled 245; then
sec_audit_start_svc systemd-journald
sec_audit_remediate_done 245 "journald active"

fi
if secaudit_rule_enabled 246; then
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
sec_audit_remediate_done 246 "rsyslog installed"

fi
if secaudit_rule_enabled 247; then
sec_audit_remediate_skip 247 "Ensure rsyslog logging is configured"

fi
if secaudit_rule_enabled 248; then
sec_audit_remediate_skip 248 "Ensure rsyslog is configured to send logs to a remote log host"

fi
if secaudit_rule_enabled 249; then
sec_audit_remediate_skip 249 "Ensure rsyslog is not configured to receive logs from a remote client"

fi
if secaudit_rule_enabled 250; then
sec_audit_remediate_skip 250 "Ensure rsyslog logrotate is configured"

fi
if secaudit_rule_enabled 251; then
sec_audit_remediate_skip 251 "review  remediation: Ensure access to all logfiles has been configured"

fi
}

sec_audit_remediate_auditd() {
# RULE252-261
if secaudit_rule_enabled 252; then
sec_audit_pkg_install audit
sec_audit_start_svc auditd
sec_audit_remediate_done 252 "auditd running"

fi
if secaudit_rule_enabled 253; then
sec_audit_pkg_install audit
sec_audit_start_svc auditd
sec_audit_remediate_done 253 "auditd running"

fi
if secaudit_rule_enabled 254; then
sec_audit_pkg_install audit auditd 2>/dev/null || true
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-rocky10-cre.rules <<'EOF'
-D
-b 8192
-f 1
-w /etc/sudoers -p wa -k scope
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /var/log/audit/ -p wa -k audit_log
EOF
sec_audit_have_bin augenrules && augenrules --load >/dev/null 2>&1 || true
sec_audit_start_svc auditd
sec_audit_remediate_done 254 "audit rules baseline"

fi
if secaudit_rule_enabled 255; then
sec_audit_pkg_install audit
sec_audit_start_svc auditd
sec_audit_remediate_done 255 "auditd running"

fi
if secaudit_rule_enabled 256; then
sec_audit_pkg_install audit auditd 2>/dev/null || true
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-rocky10-cre.rules <<'EOF'
-D
-b 8192
-f 1
-w /etc/sudoers -p wa -k scope
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /var/log/audit/ -p wa -k audit_log
EOF
sec_audit_have_bin augenrules && augenrules --load >/dev/null 2>&1 || true
sec_audit_start_svc auditd
sec_audit_remediate_done 256 "audit rules baseline"

fi
if secaudit_rule_enabled 257; then
sec_audit_remediate_skip 257 "review  remediation: Ensure audit logs are not automatically deleted"

fi
if secaudit_rule_enabled 258; then
sec_audit_remediate_skip 258 "review  remediation: Ensure system is disabled when audit logs are full"

fi
if secaudit_rule_enabled 259; then
sec_audit_remediate_skip 259 "review  remediation: Ensure system warns when audit logs are low on space"

fi
if secaudit_rule_enabled 260; then
sec_audit_remediate_skip 260 "review  remediation: Ensure modification of the /etc/sudoers file is collected"

fi
if secaudit_rule_enabled 261; then
sec_audit_remediate_skip 261 "review  remediation: Ensure actions as another user are always logged"

fi
}

sec_audit_remediate_sudo_su_2() {
# RULE262-264
if secaudit_rule_enabled 262; then
sec_audit_remediate_skip 262 "review  remediation: Ensure events that modify the sudo log file are collected"

fi
if secaudit_rule_enabled 263; then
sec_audit_remediate_skip 263 "review  remediation: Ensure events that modify date and time information are collected"

fi
if secaudit_rule_enabled 264; then
sec_audit_remediate_skip 264 "review  remediation: Ensure events that modify the system's network environment are collected"

fi
}

sec_audit_remediate_banners_2() {
# RULE265-270
if secaudit_rule_enabled 265; then
sec_audit_remediate_skip 265 "review  remediation: Ensure use of privileged commands are collected"

fi
if secaudit_rule_enabled 266; then
sec_audit_remediate_skip 266 "review  remediation: Ensure unsuccessful file access attempts are collected"

fi
if secaudit_rule_enabled 267; then
sec_audit_remediate_skip 267 "Ensure events that modify user/group information are collected"

fi
if secaudit_rule_enabled 268; then
sec_audit_remediate_skip 268 "review  remediation: Ensure events that modify /etc/NetworkManager directory are collected"

fi
if secaudit_rule_enabled 269; then
sec_audit_remediate_skip 269 "review  remediation: Ensure use of privileged commands are collected"

fi
if secaudit_rule_enabled 270; then
sec_audit_remediate_skip 270 "review  remediation: Ensure unsuccessful file access attempts are collected"

fi
}

sec_audit_remediate_identity_files_2() {
# RULE271-289
if secaudit_rule_enabled 271; then
sec_audit_remediate_skip 271 "review  remediation: Ensure login and logout events are collected"

fi
if secaudit_rule_enabled 272; then
sec_audit_remediate_skip 272 "review  remediation: Ensure file deletion events by users are collected"

fi
if secaudit_rule_enabled 273; then
sec_audit_remediate_skip 273 "review  remediation: Ensure events that modify /etc/shadow and /etc/gshadow are collected"

fi
if secaudit_rule_enabled 274; then
sec_audit_remediate_skip 274 "review  remediation: Ensure chcon command attempts are collected"

fi
if secaudit_rule_enabled 275; then
sec_audit_remediate_skip 275 "review  remediation: Ensure setfacl command attempts are collected"

fi
if secaudit_rule_enabled 276; then
sec_audit_remediate_skip 276 "review  remediation: Ensure chacl command attempts are collected"

fi
if secaudit_rule_enabled 277; then
sec_audit_remediate_skip 277 "review  remediation: Ensure usermod command attempts are collected"

fi
if secaudit_rule_enabled 278; then
sec_audit_disable_kmod events
sec_audit_remediate_done 278 "blacklisted events"

fi
if secaudit_rule_enabled 279; then
sec_audit_remediate_skip 279 "review  remediation: Ensure the audit configuration is immutable"

fi
if secaudit_rule_enabled 280; then
sec_audit_remediate_skip 280 "review  remediation: Ensure successful file system mounts are collected"

fi
if secaudit_rule_enabled 281; then
sec_audit_remediate_skip 281 "review  remediation: Ensure session initiation information is collected"

fi
if secaudit_rule_enabled 282; then
sec_audit_remediate_skip 282 "review  remediation: Ensure login and logout events are collected"

fi
if secaudit_rule_enabled 283; then
sec_audit_remediate_skip 283 "review  remediation: Ensure unlink file deletion events by users are collected"

fi
if secaudit_rule_enabled 284; then
sec_audit_remediate_skip 284 "review  remediation: Ensure rename file deletion events by users are collected"

fi
if secaudit_rule_enabled 285; then
sec_audit_remediate_skip 285 "review  remediation: Ensure events that modify the system's Mandatory Access Controls are collected"

fi
if secaudit_rule_enabled 286; then
sec_audit_remediate_skip 286 "review  remediation: Ensure successful and unsuccessful attempts to use the chcon command are collected"

fi
if secaudit_rule_enabled 287; then
sec_audit_remediate_skip 287 "review  remediation: Ensure successful and unsuccessful attempts to use the setfacl command are collected"

fi
if secaudit_rule_enabled 288; then
sec_audit_remediate_skip 288 "review  remediation: Ensure successful and unsuccessful attempts to use the chacl command are collected"

fi
if secaudit_rule_enabled 289; then
sec_audit_remediate_skip 289 "review  remediation: Ensure successful and unsuccessful attempts to use the usermod command are collected"

fi
}

sec_audit_remediate_kernel_modules_3() {
# RULE290-293
if secaudit_rule_enabled 290; then
sec_audit_disable_kmod loading
sec_audit_remediate_done 290 "blacklisted loading"

fi
if secaudit_rule_enabled 291; then
sec_audit_remediate_skip 291 "review  remediation: Ensure kernel 'init_module' and 'finit_module' loading unloading and modification is collected"

fi
if secaudit_rule_enabled 292; then
sec_audit_remediate_skip 292 "review  remediation: Ensure kernel 'delete_module' loading unloading and modification is collected"

fi
if secaudit_rule_enabled 293; then
sec_audit_remediate_skip 293 "review  remediation: Ensure kernel query_module loading unloading and modification is collected"

fi
}

sec_audit_remediate_auditd_2() {
# RULE294-296
if secaudit_rule_enabled 294; then
sec_audit_remediate_skip 294 "review  remediation: Ensure the audit configuration is loaded regardless of errors"

fi
if secaudit_rule_enabled 295; then
sec_audit_remediate_skip 295 "review  remediation: Ensure the audit configuration is immutable"

fi
if secaudit_rule_enabled 296; then
sec_audit_remediate_skip 296 "Ensure the running and on disk configuration is the same"

fi
}

sec_audit_remediate_logging_2() {
# RULE297-300
if secaudit_rule_enabled 297; then
sec_audit_pkg_install audit auditd 2>/dev/null || true
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-rocky10-cre.rules <<'EOF'
-D
-b 8192
-f 1
-w /etc/sudoers -p wa -k scope
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /var/log/audit/ -p wa -k audit_log
EOF
sec_audit_have_bin augenrules && augenrules --load >/dev/null 2>&1 || true
sec_audit_start_svc auditd
sec_audit_remediate_done 297 "audit rules baseline"

fi
if secaudit_rule_enabled 298; then
sec_audit_pkg_install audit auditd 2>/dev/null || true
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-rocky10-cre.rules <<'EOF'
-D
-b 8192
-f 1
-w /etc/sudoers -p wa -k scope
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /var/log/audit/ -p wa -k audit_log
EOF
sec_audit_have_bin augenrules && augenrules --load >/dev/null 2>&1 || true
sec_audit_start_svc auditd
sec_audit_remediate_done 298 "audit rules baseline"

fi
if secaudit_rule_enabled 299; then
sec_audit_pkg_install audit auditd 2>/dev/null || true
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-rocky10-cre.rules <<'EOF'
-D
-b 8192
-f 1
-w /etc/sudoers -p wa -k scope
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /var/log/audit/ -p wa -k audit_log
EOF
sec_audit_have_bin augenrules && augenrules --load >/dev/null 2>&1 || true
sec_audit_start_svc auditd
sec_audit_remediate_done 299 "audit rules baseline"

fi
if secaudit_rule_enabled 300; then
sec_audit_remediate_skip 300 "Ensure audit log files group owner is configured"

fi
}

sec_audit_remediate_auditd_3() {
# RULE301-306
if secaudit_rule_enabled 301; then
sec_audit_pkg_install audit auditd 2>/dev/null || true
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-rocky10-cre.rules <<'EOF'
-D
-b 8192
-f 1
-w /etc/sudoers -p wa -k scope
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /var/log/audit/ -p wa -k audit_log
EOF
sec_audit_have_bin augenrules && augenrules --load >/dev/null 2>&1 || true
sec_audit_start_svc auditd
sec_audit_remediate_done 301 "audit rules baseline"

fi
if secaudit_rule_enabled 302; then
sec_audit_pkg_install audit auditd 2>/dev/null || true
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-rocky10-cre.rules <<'EOF'
-D
-b 8192
-f 1
-w /etc/sudoers -p wa -k scope
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /var/log/audit/ -p wa -k audit_log
EOF
sec_audit_have_bin augenrules && augenrules --load >/dev/null 2>&1 || true
sec_audit_start_svc auditd
sec_audit_remediate_done 302 "audit rules baseline"

fi
if secaudit_rule_enabled 303; then
sec_audit_remediate_skip 303 "Ensure audit configuration files group owner is configured"

fi
if secaudit_rule_enabled 304; then
sec_audit_pkg_install audit auditd 2>/dev/null || true
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-rocky10-cre.rules <<'EOF'
-D
-b 8192
-f 1
-w /etc/sudoers -p wa -k scope
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /var/log/audit/ -p wa -k audit_log
EOF
sec_audit_have_bin augenrules && augenrules --load >/dev/null 2>&1 || true
sec_audit_start_svc auditd
sec_audit_remediate_done 304 "audit rules baseline"

fi
if secaudit_rule_enabled 305; then
sec_audit_pkg_install audit auditd 2>/dev/null || true
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-rocky10-cre.rules <<'EOF'
-D
-b 8192
-f 1
-w /etc/sudoers -p wa -k scope
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /var/log/audit/ -p wa -k audit_log
EOF
sec_audit_have_bin augenrules && augenrules --load >/dev/null 2>&1 || true
sec_audit_start_svc auditd
sec_audit_remediate_done 305 "audit rules baseline"

fi
if secaudit_rule_enabled 306; then
sec_audit_remediate_skip 306 "Ensure audit tools group owner is configured"

fi

}

sec_audit_remediate_identity_files_3() {
# RULE307-322
if secaudit_rule_enabled 307; then
sec_audit_remediate_skip 307 "review  remediation: Ensure access to /etc/passwd is configured"

fi
if secaudit_rule_enabled 308; then
sec_audit_remediate_skip 308 "review  remediation: Ensure access to /etc/passwd- is configured"

fi
if secaudit_rule_enabled 309; then
sec_audit_remediate_skip 309 "Ensure access to /etc/group is configured"

fi
if secaudit_rule_enabled 310; then
sec_audit_remediate_skip 310 "Ensure access to /etc/group- is configured"

fi
if secaudit_rule_enabled 311; then
sec_audit_remediate_skip 311 "review  remediation: Ensure access to /etc/shadow is configured"

fi
if secaudit_rule_enabled 312; then
sec_audit_remediate_skip 312 "review  remediation: Ensure access to /etc/shadow- is configured"

fi
if secaudit_rule_enabled 313; then
sec_audit_remediate_skip 313 "review  remediation: Ensure access to /etc/gshadow is configured"

fi
if secaudit_rule_enabled 314; then
sec_audit_remediate_skip 314 "review  remediation: Ensure access to /etc/gshadow- is configured"

fi
if secaudit_rule_enabled 315; then
sec_audit_remediate_skip 315 "review  remediation: Ensure access to /etc/shells is configured"

fi
if secaudit_rule_enabled 316; then
sec_audit_remediate_skip 316 "review  remediation: Ensure access to /etc/security/opasswd is configured"

fi
if secaudit_rule_enabled 317; then
sec_audit_remediate_skip 317 "review  remediation: Ensure world writable files and directories are secured"

fi
if secaudit_rule_enabled 318; then
sec_audit_remediate_skip 318 "Ensure no files or directories without an owner and a group exist"

fi
if secaudit_rule_enabled 319; then
sec_audit_remediate_skip 319 "Ensure SUID and SGID files are reviewed"

fi
if secaudit_rule_enabled 320; then
sec_audit_remediate_skip 320 "Ensure accounts in /etc/passwd use shadowed passwords"

fi
if secaudit_rule_enabled 321; then
sec_audit_remediate_skip 321 "review  remediation: Ensure /etc/shadow password fields are not empty"

fi
if secaudit_rule_enabled 322; then
sec_audit_remediate_skip 322 "Ensure all groups in /etc/passwd exist in /etc/group"

fi
}

sec_audit_remediate_filesystem_integrity() {
# RULE323-328
if secaudit_rule_enabled 323; then
sec_audit_remediate_skip 323 "Ensure no duplicate UIDs exist"

fi
if secaudit_rule_enabled 324; then
sec_audit_remediate_skip 324 "Ensure no duplicate GIDs exist"

fi
if secaudit_rule_enabled 325; then
sec_audit_remediate_skip 325 "Ensure no duplicate user names exist"

fi
if secaudit_rule_enabled 326; then
sec_audit_remediate_skip 326 "Ensure no duplicate group names exist"

fi
if secaudit_rule_enabled 327; then
sec_audit_remediate_skip 327 "Ensure local interactive user home directories are configured"

fi
if secaudit_rule_enabled 328; then
sec_audit_remediate_skip 328 "Ensure local interactive user dot files access is configured"

fi

}

sec_audit_maybe_security_upgrade() {
    if [ "${RL10_REMEDIATE_SECURITY_UPGRADE}" != "1" ]; then
        sec_audit_log "skipping package security upgrade (set RL10_REMEDIATE_SECURITY_UPGRADE=1 to enable)"
        return 0
    fi
    if sec_audit_have_bin dnf; then
        if sec_audit_have_bin timeout; then
            timeout 300 dnf upgrade --security -y >/dev/null 2>&1 || true
        else
            dnf upgrade --security -y >/dev/null 2>&1 || true
        fi
    elif sec_audit_have_bin yum; then
        if sec_audit_have_bin timeout; then
            timeout 300 yum update --security -y >/dev/null 2>&1 || true
        else
            yum update --security -y >/dev/null 2>&1 || true
        fi
    fi
}

sec_audit_main() {
    sec_audit_log "starting remediation"
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
    sec_audit_remediate_unused_services_2
    sec_audit_remediate_kernel_modules_2
    sec_audit_remediate_network_stack_2
    sec_audit_remediate_firewalld
    sec_audit_remediate_unused_services_3
    sec_audit_remediate_sshd
    sec_audit_remediate_sudo_su
    sec_audit_remediate_pam_auth
    sec_audit_remediate_accounts
    sec_audit_remediate_pam_auth_2
    sec_audit_remediate_accounts_2
    sec_audit_remediate_identity_files
    sec_audit_remediate_accounts_3
    sec_audit_remediate_aide
    sec_audit_remediate_crypto_policy_2
    sec_audit_remediate_unused_services_4
    sec_audit_remediate_logging
    sec_audit_remediate_auditd
    sec_audit_remediate_sudo_su_2
    sec_audit_remediate_banners_2
    sec_audit_remediate_identity_files_2
    sec_audit_remediate_kernel_modules_3
    sec_audit_remediate_auditd_2
    sec_audit_remediate_logging_2
    sec_audit_remediate_auditd_3
    sec_audit_remediate_identity_files_3
    sec_audit_remediate_filesystem_integrity
    sec_audit_maybe_security_upgrade
    exit 0
}

# secaudit-restore-journal: paired with RockyLinux10_remediation.sh
SECAUDIT_JOURNAL="${SECAUDIT_JOURNAL:-/var/backups/secaudit-rockylinux10.journal}"
SECAUDIT_PKG="${SECAUDIT_PKG:-dnf}"

sec_audit_journal_once() {
	local kind="$1" id="$2"
	shift 2
	mkdir -p "$(dirname "$SECAUDIT_JOURNAL")" 2>/dev/null || return 0
	touch "$SECAUDIT_JOURNAL" 2>/dev/null || return 0
	grep -q "^${kind} ${id} " "$SECAUDIT_JOURNAL" 2>/dev/null && return 0
	grep -qxF "${kind} ${id}" "$SECAUDIT_JOURNAL" 2>/dev/null && return 0
	if [ $# -eq 0 ]; then
		printf '%s %s\n' "$kind" "$id" >>"$SECAUDIT_JOURNAL"
	else
		printf '%s %s %s\n' "$kind" "$id" "$*" >>"$SECAUDIT_JOURNAL"
	fi
}

sec_audit_guard_file() {
	local f="$1"
	[ -n "$f" ] || return 0
	case "$f" in *.secaudit.bak) return 0 ;; esac
	if [ -e "$f" ]; then
		[ -e "${f}.secaudit.bak" ] && return 0
		cp -p "$f" "${f}.secaudit.bak" 2>/dev/null || true
	else
		sec_audit_journal_once created "$f"
	fi
}

sec_audit_pkg_table() {
	case "$SECAUDIT_PKG" in
		apt) dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null | sort -u ;;
		zypper|dnf|yum) rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' 2>/dev/null | sort -u ;;
	esac
}

sec_audit_journal_pkg_diff() {
	local kind="$1" before="$2" after="$3" name ver
	comm -13 "$before" "$after" | while read -r name ver; do
		[ -n "${name:-}" ] || continue
		sec_audit_journal_once "$kind" "$name" "$ver"
	done
}

sec_audit_remember_unit() {
	local u="$1" state
	command -v systemctl >/dev/null 2>&1 || return 0
	[ -n "$u" ] || return 0
	state=$(systemctl is-enabled "$u" 2>/dev/null || true)
	case "$state" in
		enabled|enabled-runtime) state=enabled ;;
		disabled|masked|static|indirect|absent) ;;
		*) state=absent ;;
	esac
	sec_audit_journal_once unit "$u" "$state"
}

sec_audit_remember_mount() {
	local mp="$1" opts
	[ -n "$mp" ] || return 0
	mountpoint -q "$mp" 2>/dev/null || return 0
	opts=$(findmnt -kn -T "$mp" -o OPTIONS -n 2>/dev/null | head -n1)
	[ -n "$opts" ] && sec_audit_journal_once mount "$mp" "$opts"
}

sec_audit_rename_fn() {
	local src="$1" dst="${1}_raw" body
	declare -f "$src" >/dev/null 2>&1 || return 1
	declare -f "$dst" >/dev/null 2>&1 && return 0
	body=$(declare -f "$src") || return 1
	eval "${body/#"$src"/"$dst"}"
}

sed() {
	local arg
	for arg in "$@"; do
		case "$arg" in
			/etc/*|/boot/*|/usr/*|/var/*) sec_audit_guard_file "$arg" ;;
		esac
	done
	command sed "$@"
}

chmod() {
	local path="${!#}" mode owner
	if [ -n "${path:-}" ] && [ -e "$path" ]; then
		mode=$(stat -c '%a' "$path" 2>/dev/null || true)
		owner=$(stat -c '%U:%G' "$path" 2>/dev/null || true)
		[ -n "$mode" ] && sec_audit_journal_once mode "$path" "$mode ${owner:-root:root}"
	fi
	command chmod "$@"
}

chown() {
	local path="${!#}" mode owner
	if [ -n "${path:-}" ] && [ -e "$path" ]; then
		mode=$(stat -c '%a' "$path" 2>/dev/null || true)
		owner=$(stat -c '%U:%G' "$path" 2>/dev/null || true)
		[ -n "$mode" ] && sec_audit_journal_once mode "$path" "$mode ${owner:-root:root}"
	fi
	command chown "$@"
}


if sec_audit_rename_fn sec_audit_pkg_install; then
sec_audit_pkg_install() {
	local before after
	before=$(mktemp)
	after=$(mktemp)
	sec_audit_pkg_table >"$before"
	sec_audit_pkg_install_raw "$@"
	sec_audit_pkg_table >"$after"
	sec_audit_journal_pkg_diff pkg_add "$before" "$after"
	rm -f "$before" "$after"
}
fi


if sec_audit_rename_fn sec_audit_pkg_remove; then
sec_audit_pkg_remove() {
	local before after
	before=$(mktemp)
	after=$(mktemp)
	sec_audit_pkg_table >"$before"
	sec_audit_pkg_remove_raw "$@"
	sec_audit_pkg_table >"$after"
	sec_audit_journal_pkg_diff pkg_del "$before" "$after"
	rm -f "$before" "$after"
}
fi


if sec_audit_rename_fn sec_audit_start_svc; then
sec_audit_start_svc() {
	local u
	for u in "$@"; do
		sec_audit_remember_unit "$u"
	done
	sec_audit_start_svc_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_disable_svc; then
sec_audit_disable_svc() {
	local u
	for u in "$@"; do
		sec_audit_remember_unit "$u"
	done
	sec_audit_disable_svc_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_disable_kmod; then
sec_audit_disable_kmod() {
	local mod="$1" before after name
	if awk '{print $1}' /proc/modules 2>/dev/null | grep -qx "$mod"; then
		sec_audit_journal_once kmod "$mod"
	fi
	before=$(mktemp)
	after=$(mktemp)
	find /etc/modprobe.d -type f -printf '%f\n' 2>/dev/null | sort >"$before"
	sec_audit_disable_kmod_raw "$@"
	find /etc/modprobe.d -type f -printf '%f\n' 2>/dev/null | sort >"$after"
	comm -13 "$before" "$after" | while read -r name; do
		[ -n "${name:-}" ] || continue
		sec_audit_journal_once created "/etc/modprobe.d/$name"
	done
	rm -f "$before" "$after"
}
fi


if sec_audit_rename_fn sec_audit_ensure_fstab_mount; then
sec_audit_ensure_fstab_mount() {
		sec_audit_guard_file /etc/fstab
	sec_audit_remember_mount "$1"
	sec_audit_ensure_fstab_mount_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_ensure_mount_option; then
sec_audit_ensure_mount_option() {
		sec_audit_guard_file /etc/fstab
	sec_audit_remember_mount "$1"
	sec_audit_ensure_mount_option_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_set_sysctl; then
sec_audit_set_sysctl() {
	local key="$1" old
		sec_audit_guard_file /etc/sysctl.d/99-rocky10-cre-.conf
	sec_audit_guard_file /etc/sysctl.d
	old=$(sysctl -n "$key" 2>/dev/null || true)
	[ -n "$old" ] && sec_audit_journal_once sysctl "$key" "$old"
	sec_audit_set_sysctl_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_set_dnf_main_kv; then
sec_audit_set_dnf_main_kv() {
		sec_audit_guard_file /etc/dnf/dnf.conf
	sec_audit_set_dnf_main_kv_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_set_sshd_kv; then
sec_audit_set_sshd_kv() {
		sec_audit_guard_file /etc/ssh/sshd_config
	sec_audit_set_sshd_kv_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_set_login_defs_kv; then
sec_audit_set_login_defs_kv() {
		sec_audit_guard_file /etc/login.defs
	sec_audit_set_login_defs_kv_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_set_pwquality_kv; then
sec_audit_set_pwquality_kv() {
		sec_audit_guard_file /etc/security/pwquality.conf
	sec_audit_guard_file /etc/security/pwquality.conf.d
	sec_audit_set_pwquality_kv_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_set_faillock_kv; then
sec_audit_set_faillock_kv() {
		sec_audit_guard_file /etc/security/faillock.conf
	sec_audit_guard_file /etc/security
	sec_audit_set_faillock_kv_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_authselect_enable; then
sec_audit_authselect_enable() {
		sec_audit_guard_file /etc/authselect/authselect.conf
	sec_audit_guard_file /etc/pam.d/system-auth
	sec_audit_guard_file /etc/pam.d/password-auth
	sec_audit_guard_file /etc/pam.d/common-auth
	sec_audit_guard_file /etc/pam.d/common-password
	sec_audit_authselect_enable_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_remediate_selinux; then
sec_audit_remediate_selinux() {
		sec_audit_guard_file /etc/selinux/config
	sec_audit_remediate_selinux_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_remediate_bootloader; then
sec_audit_remediate_bootloader() {
		sec_audit_guard_file /boot/grub2/grub.cfg
	sec_audit_guard_file /boot/grub2/user.cfg
	sec_audit_guard_file /etc/security/limits.conf
	sec_audit_guard_file /etc/systemd/coredump.conf.d
	sec_audit_guard_file /etc/systemd/coredump.conf.d/99-cre-.conf
	sec_audit_remediate_bootloader_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_remediate_process_hardening; then
sec_audit_remediate_process_hardening() {
		sec_audit_guard_file /etc/systemd/coredump.conf.d
	sec_audit_guard_file /etc/systemd/coredump.conf.d/99-cre-.conf
	sec_audit_remediate_process_hardening_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_remediate_banners; then
sec_audit_remediate_banners() {
		sec_audit_guard_file /etc/motd
	sec_audit_guard_file /etc/issue
	sec_audit_guard_file /etc/issue.net
	sec_audit_guard_file /etc/dconf/db/gdm.d
	sec_audit_remediate_banners_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_remediate_chrony; then
sec_audit_remediate_chrony() {
		sec_audit_guard_file /etc/chrony.conf
	sec_audit_remediate_chrony_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_remediate_cron_at; then
sec_audit_remediate_cron_at() {
		sec_audit_guard_file /etc/crontab
	sec_audit_guard_file /etc/cron.hourly
	sec_audit_guard_file /etc/cron.daily
	sec_audit_guard_file /etc/cron.weekly
	sec_audit_guard_file /etc/cron.monthly
	sec_audit_guard_file /etc/cron.yearly
	sec_audit_guard_file /etc/cron.d
	sec_audit_remediate_cron_at_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_remediate_sudo_su; then
sec_audit_remediate_sudo_su() {
		sec_audit_guard_file /etc/sudoers.d/99-cre-timeout
	sec_audit_remediate_sudo_su_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_remediate_pam_auth; then
sec_audit_remediate_pam_auth() {
		sec_audit_guard_file /etc/security/pwhistory.conf
	sec_audit_remediate_pam_auth_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_remediate_pam_auth_2; then
sec_audit_remediate_pam_auth_2() {
		sec_audit_guard_file /etc/security/pwhistory.conf
	sec_audit_remediate_pam_auth_2_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_remediate_accounts_2; then
sec_audit_remediate_accounts_2() {
		sec_audit_guard_file /etc/profile.d/99-cre-umask.sh
	sec_audit_remediate_accounts_2_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_remediate_identity_files; then
sec_audit_remediate_identity_files() {
		sec_audit_guard_file /etc/shells
	sec_audit_guard_file /etc/profile.d/99-cre-timeout.sh
	sec_audit_remediate_identity_files_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_remediate_accounts_3; then
sec_audit_remediate_accounts_3() {
		sec_audit_guard_file /etc/profile.d/99-cre-umask.sh
	sec_audit_remediate_accounts_3_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_remediate_logging; then
sec_audit_remediate_logging() {
		sec_audit_guard_file /etc/systemd/journald.conf.d
	sec_audit_guard_file /etc/systemd/journald.conf.d/99-rocky10-cre.conf
	sec_audit_remediate_logging_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_remediate_auditd; then
sec_audit_remediate_auditd() {
		sec_audit_guard_file /etc/audit/rules.d
	sec_audit_guard_file /etc/audit/rules.d/99-rocky10-cre.rules
	sec_audit_guard_file /etc/sudoers
	sec_audit_guard_file /etc/passwd
	sec_audit_guard_file /etc/shadow
	sec_audit_guard_file /var/log/audit
	sec_audit_remediate_auditd_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_remediate_logging_2; then
sec_audit_remediate_logging_2() {
		sec_audit_guard_file /etc/audit/rules.d
	sec_audit_guard_file /etc/audit/rules.d/99-rocky10-cre.rules
	sec_audit_guard_file /etc/sudoers
	sec_audit_guard_file /etc/passwd
	sec_audit_guard_file /etc/shadow
	sec_audit_guard_file /var/log/audit
	sec_audit_remediate_logging_2_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_remediate_auditd_3; then
sec_audit_remediate_auditd_3() {
		sec_audit_guard_file /etc/audit/rules.d
	sec_audit_guard_file /etc/audit/rules.d/99-rocky10-cre.rules
	sec_audit_guard_file /etc/sudoers
	sec_audit_guard_file /etc/passwd
	sec_audit_guard_file /etc/shadow
	sec_audit_guard_file /var/log/audit
	sec_audit_remediate_auditd_3_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_main; then
sec_audit_main() {
		if command -v getenforce >/dev/null 2>&1; then
		sec_audit_journal_once selinux getenforce "$(getenforce 2>/dev/null || true)"
	fi
	sec_audit_guard_file /etc/selinux/config
	if command -v update-crypto-policies >/dev/null 2>&1; then
		sec_audit_journal_once crypto policy "$(update-crypto-policies --show 2>/dev/null || true)"
	fi
	sec_audit_main_raw "$@"
}
fi

sec_audit_main "$@"
