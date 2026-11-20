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
	local key="$1" val="$2" f="/etc/sysctl.d/99-rocky9-cre-.conf"
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
	local feat="$1" profile features
	sec_audit_have_bin authselect || return 0
	profile=$(head -1 /etc/authselect/authselect.conf 2>/dev/null)
	[[ -n $profile ]] || profile=sssd
	features=$(authselect current 2>/dev/null | sed -n 's/^- //p' | tr '\n' ' ')
	if ! authselect current 2>/dev/null | grep -q "$feat"; then
		authselect select "$profile" $features "$feat" --force >/dev/null 2>&1 || true
	fi
	authselect apply-changes >/dev/null 2>&1 || true
}

sec_audit_remediate_done() { secaudit_rule_enabled "$1" || return 0; printf '[remediation] REMEDIATE RULE%s= applied: %s\n' "$1" "$2"; }
sec_audit_remediate_skip() { secaudit_rule_enabled "$1" || return 0; printf '[remediation] REMEDIATE RULE%s= SKIP: manual step required - %s\n' "$1" "$2"; }

# =============================================================================
# Section runners
# =============================================================================

sec_audit_remediate_initial_setup() {
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
if secaudit_rule_enabled 38; then
sec_audit_remediate_skip 38 "Ensure GPG keys are configured"

fi
if secaudit_rule_enabled 39; then
sec_audit_set_dnf_main_kv gpgcheck 1
sec_audit_set_dnf_main_kv localpkg_gpgcheck 1
sec_audit_remediate_done 39 "enabled gpgcheck"

fi
if secaudit_rule_enabled 40; then
sec_audit_remediate_skip 40 "Ensure repo_gpgcheck is configured"

fi
if secaudit_rule_enabled 41; then
sec_audit_remediate_skip 41 "Ensure package manager repositories are configured"

fi
if secaudit_rule_enabled 42; then
sec_audit_remediate_skip 42 "Ensure weak dependencies are configured"

fi
if secaudit_rule_enabled 43; then
sec_audit_remediate_skip 43 "Ensure updates, patches, and additional security software are installed"

fi
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
sec_audit_pkg_remove mcstrans
sec_audit_disable_svc mcstrans.service
sec_audit_remediate_done 50 "removed mcstrans"

fi
if secaudit_rule_enabled 51; then
sec_audit_pkg_remove setroubleshoot
sec_audit_disable_svc setroubleshoot.service
sec_audit_remediate_done 51 "removed setroubleshoot"

fi
if secaudit_rule_enabled 52; then
sec_audit_remediate_skip 52 "Ensure bootloader password is set"

fi
if secaudit_rule_enabled 53; then
sec_audit_harden_file /boot/grub2/grub.cfg 600 root:root
sec_audit_harden_file /boot/grub2/user.cfg 600 root:root
sec_audit_remediate_done 53 "hardened grub permissions"

fi
if secaudit_rule_enabled 54; then
sec_audit_remediate_skip 54 "review  remediation: Ensure authentication is required when booting into rescue mode"

fi
if secaudit_rule_enabled 55; then
sec_audit_remediate_skip 55 "review  remediation: Ensure authentication is required when booting into emergency mode"

fi
if secaudit_rule_enabled 56; then
sec_audit_remediate_skip 56 "review  remediation: Ensure systemd ability to spawn an interactive boot process is disabled"

fi
if secaudit_rule_enabled 57; then
sec_audit_set_sysctl fs.protected_hardlinks 1
sec_audit_remediate_done 57 "set fs.protected_hardlinks=1"

fi
if secaudit_rule_enabled 58; then
sec_audit_set_sysctl fs.protected_symlinks 1
sec_audit_remediate_done 58 "set fs.protected_symlinks=1"

fi
if secaudit_rule_enabled 59; then
sec_audit_remediate_skip 59 "Ensure fs.suid_dumpable is configured"

fi
if secaudit_rule_enabled 60; then
sec_audit_set_sysctl kernel.dmesg_restrict 1
sec_audit_remediate_done 60 "set kernel.dmesg_restrict=1"

fi
if secaudit_rule_enabled 61; then
sec_audit_set_sysctl kernel.kptr_restrict 2
sec_audit_remediate_done 61 "set kernel.kptr_restrict=2"

fi
if secaudit_rule_enabled 62; then
sec_audit_set_sysctl kernel.randomize_va_space 2
sec_audit_remediate_done 62 "set kernel.randomize_va_space=2"

fi
if secaudit_rule_enabled 63; then
sec_audit_set_sysctl kernel.yama.ptrace_scope 1
sec_audit_remediate_done 63 "set kernel.yama.ptrace_scope=1"

fi
if secaudit_rule_enabled 64; then
grep -q "hard core" /etc/security/limits.conf 2>/dev/null || echo "* hard core 0" >>/etc/security/limits.conf
mkdir -p /etc/systemd/coredump.conf.d
cat >/etc/systemd/coredump.conf.d/99-cre-.conf <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
sec_audit_have_bin systemctl && systemctl daemon-reload >/dev/null 2>&1 || true
sec_audit_remediate_done 64 "disabled core dumps"

fi
if secaudit_rule_enabled 65; then
sec_audit_set_sysctl fs.suid_dumpable 0
sec_audit_remediate_done 65 "coredump limits via sysctl/coredump.conf"

fi
if secaudit_rule_enabled 66; then
mkdir -p /etc/systemd/coredump.conf.d
cat >/etc/systemd/coredump.conf.d/99-cre-.conf <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
sec_audit_remediate_done 66 "systemd-coredump Storage=none"

fi
if secaudit_rule_enabled 67; then
sec_audit_have_bin update-crypto-policies && update-crypto-policies --set DEFAULT >/dev/null 2>&1 || true
sec_audit_remediate_done 67 "crypto policy not LEGACY"

fi
if secaudit_rule_enabled 68; then
sec_audit_have_bin update-crypto-policies && update-crypto-policies --set DEFAULT:NO-SHA1:NO-SSHCBC >/dev/null 2>&1 || update-crypto-policies --set DEFAULT >/dev/null 2>&1 || true
sec_audit_remediate_done 68 "applied DEFAULT crypto policy modules"

fi
if secaudit_rule_enabled 69; then
sec_audit_have_bin update-crypto-policies && update-crypto-policies --set DEFAULT:NO-SHA1:NO-SSHCBC >/dev/null 2>&1 || update-crypto-policies --set DEFAULT >/dev/null 2>&1 || true
sec_audit_remediate_done 69 "applied DEFAULT crypto policy modules"

fi
if secaudit_rule_enabled 70; then
sec_audit_remediate_skip 70 "Ensure system wide crypto policy disables cbc for ssh"

fi
if secaudit_rule_enabled 71; then
sec_audit_remediate_skip 71 "Ensure system wide crypto policy disables chacha20-poly1305 for ssh"

fi
if secaudit_rule_enabled 72; then
sec_audit_remediate_skip 72 "Ensure system wide crypto policy disables EtM for ssh"

fi
if secaudit_rule_enabled 73; then
sec_audit_have_bin update-crypto-policies && update-crypto-policies --set DEFAULT:NO-SHA1:NO-SSHCBC >/dev/null 2>&1 || update-crypto-policies --set DEFAULT >/dev/null 2>&1 || true
sec_audit_remediate_done 73 "applied DEFAULT crypto policy modules"

fi
if secaudit_rule_enabled 74; then
[[ -f /etc/motd ]] || echo "Authorized use only." >/etc/motd
sed -i 's/\\[vVrms]//g' /etc/motd 2>/dev/null || true
sec_audit_remediate_done 74 "sanitized banner /etc/motd"

fi
if secaudit_rule_enabled 75; then
[[ -f /etc/issue ]] || echo "Authorized use only." >/etc/issue
sed -i 's/\\[vVrms]//g' /etc/issue 2>/dev/null || true
sec_audit_remediate_done 75 "sanitized banner /etc/issue"

fi
if secaudit_rule_enabled 76; then
[[ -f /etc/issue.net ]] || echo "Authorized use only." >/etc/issue.net
sed -i 's/\\[vVrms]//g' /etc/issue.net 2>/dev/null || true
sec_audit_remediate_done 76 "sanitized banner /etc/issue.net"

fi
if secaudit_rule_enabled 77; then
sec_audit_harden_file /etc/motd 644 root:root
sec_audit_remediate_done 77 "permissions /etc/motd"

fi
if secaudit_rule_enabled 78; then
sec_audit_harden_file /etc/issue 644 root:root
sec_audit_remediate_done 78 "permissions /etc/issue"

fi
if secaudit_rule_enabled 79; then
sec_audit_harden_file /etc/issue.net 644 root:root
sec_audit_remediate_done 79 "permissions /etc/issue.net"

fi
if secaudit_rule_enabled 80; then
mkdir -p /etc/dconf/db/gdm.d
sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
sec_audit_remediate_done 80 "configured GDM hardening"

fi
if secaudit_rule_enabled 81; then
mkdir -p /etc/dconf/db/gdm.d
sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
sec_audit_remediate_done 81 "configured GDM hardening"

fi
if secaudit_rule_enabled 82; then
mkdir -p /etc/dconf/db/gdm.d
sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
sec_audit_remediate_done 82 "configured GDM hardening"

fi
if secaudit_rule_enabled 83; then
mkdir -p /etc/dconf/db/gdm.d
sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
sec_audit_remediate_done 83 "configured GDM hardening"

fi
if secaudit_rule_enabled 84; then
mkdir -p /etc/dconf/db/gdm.d
sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
sec_audit_remediate_done 84 "configured GDM hardening"

fi
if secaudit_rule_enabled 85; then
mkdir -p /etc/dconf/db/gdm.d
sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
sec_audit_remediate_done 85 "configured GDM hardening"

fi
if secaudit_rule_enabled 86; then
mkdir -p /etc/dconf/db/gdm.d
sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
sec_audit_remediate_done 86 "configured GDM hardening"

fi
}

sec_audit_remediate_services() {
if secaudit_rule_enabled 87; then
sec_audit_disable_svc autofs.service
sec_audit_pkg_remove autofs
sec_audit_remediate_done 87 "disabled autofs"

fi
if secaudit_rule_enabled 88; then
sec_audit_disable_svc avahi-daemon.socket
sec_audit_disable_svc avahi-daemon.service
sec_audit_pkg_remove avahi
sec_audit_remediate_done 88 "disabled avahi"

fi
if secaudit_rule_enabled 89; then
sec_audit_disable_svc cockpit.socket
sec_audit_disable_svc cockpit.service
sec_audit_pkg_remove cockpit-ws
sec_audit_remediate_done 89 "disabled cockpit-ws"

fi
if secaudit_rule_enabled 90; then
sec_audit_disable_svc dhcpd.service
sec_audit_disable_svc dhcpd6.service
sec_audit_pkg_remove dhcp-server
sec_audit_remediate_done 90 "disabled dhcp-server"

fi
if secaudit_rule_enabled 91; then
sec_audit_disable_svc named.service
sec_audit_pkg_remove bind
sec_audit_remediate_done 91 "disabled bind"

fi
if secaudit_rule_enabled 92; then
sec_audit_disable_svc dnsmasq.service
sec_audit_pkg_remove dnsmasq
sec_audit_remediate_done 92 "disabled dnsmasq"

fi
if secaudit_rule_enabled 93; then
sec_audit_disable_svc smb.service
sec_audit_disable_svc smbd.service
sec_audit_pkg_remove samba
sec_audit_remediate_done 93 "disabled samba"

fi
if secaudit_rule_enabled 94; then
sec_audit_disable_svc vsftpd.service
sec_audit_pkg_remove vsftpd
sec_audit_remediate_done 94 "disabled vsftpd"

fi
if secaudit_rule_enabled 95; then
sec_audit_remediate_skip 95 "review  remediation: Ensure message access server services are not in use"

fi
if secaudit_rule_enabled 96; then
sec_audit_remediate_skip 96 "review  remediation: Ensure network file system services are not in use"

fi
if secaudit_rule_enabled 97; then
sec_audit_remediate_skip 97 "review  remediation: Ensure print server services are not in use"

fi
if secaudit_rule_enabled 98; then
sec_audit_disable_svc rpcbind.socket
sec_audit_disable_svc rpcbind.service
sec_audit_pkg_remove rpcbind
sec_audit_remediate_done 98 "disabled rpcbind"

fi
if secaudit_rule_enabled 99; then
sec_audit_disable_svc rsyncd.socket
sec_audit_disable_svc rsyncd.service
sec_audit_pkg_remove rsync-daemon
sec_audit_remediate_done 99 "disabled rsync-daemon"

fi
if secaudit_rule_enabled 100; then
sec_audit_disable_svc snmpd.service
sec_audit_pkg_remove net-snmp
sec_audit_remediate_done 100 "disabled net-snmp"

fi
if secaudit_rule_enabled 101; then
sec_audit_disable_svc telnet.socket
sec_audit_pkg_remove telnet-server
sec_audit_remediate_done 101 "disabled telnet-server"

fi
if secaudit_rule_enabled 102; then
sec_audit_disable_svc vsftpd.service
sec_audit_pkg_remove vsftpd
sec_audit_remediate_done 102 "disabled vsftpd"

fi
if secaudit_rule_enabled 103; then
sec_audit_remediate_skip 103 "review  remediation: Ensure web proxy server services are not in use"

fi
if secaudit_rule_enabled 104; then
sec_audit_remediate_skip 104 "review  remediation: Ensure web server services are not in use"

fi
if secaudit_rule_enabled 105; then
sec_audit_remediate_skip 105 "review  remediation: Ensure mail transfer agents are configured for local-only mode"

fi
if secaudit_rule_enabled 106; then
sec_audit_remediate_skip 106 "review  remediation: Ensure a graphical user interface is not in use"

fi
if secaudit_rule_enabled 107; then
sec_audit_remediate_skip 107 "review  remediation: Ensure X window server services are not in use"

fi
if secaudit_rule_enabled 108; then
mkdir -p /etc/dconf/db/gdm.d
sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
sec_audit_remediate_done 108 "configured GDM hardening"

fi
if secaudit_rule_enabled 109; then
sec_audit_remediate_skip 109 "Ensure only approved services are listening on a network interface"

fi
if secaudit_rule_enabled 110; then
sec_audit_pkg_remove ftp
sec_audit_remediate_done 110 "removed ftp"

fi
if secaudit_rule_enabled 111; then
sec_audit_pkg_remove ldap-utils
sec_audit_remediate_done 111 "removed ldap-utils"

fi
if secaudit_rule_enabled 112; then
sec_audit_pkg_remove telnet
sec_audit_remediate_done 112 "removed telnet"

fi
if secaudit_rule_enabled 113; then
sec_audit_pkg_remove tftp
sec_audit_remediate_done 113 "removed tftp"

fi
if secaudit_rule_enabled 114; then
sec_audit_pkg_install chrony
sec_audit_start_svc chronyd
sec_audit_remediate_done 114 "installed chrony"

fi
if secaudit_rule_enabled 115; then
sec_audit_pkg_install chrony
grep -q "^pool \|^server " /etc/chrony.conf 2>/dev/null || echo "pool 2.pool.ntp.org iburst" >>/etc/chrony.conf
sec_audit_start_svc chronyd
sec_audit_remediate_done 115 "configured chrony"

fi
if secaudit_rule_enabled 116; then
sec_audit_remediate_skip 116 "review  remediation: Ensure chrony is not run as the root user"

fi
if secaudit_rule_enabled 117; then
sec_audit_pkg_install cronie
sec_audit_start_svc crond
sec_audit_remediate_done 117 "enabled crond"

fi
if secaudit_rule_enabled 118; then
chmod 600 /etc/crontab 2>/dev/null || true
chown root:root /etc/crontab 2>/dev/null || true
sec_audit_remediate_done 118 "restricted /etc/crontab"

fi
if secaudit_rule_enabled 119; then
sec_audit_remediate_skip 119 "review  remediation: Ensure access to /etc/cron.hourly is configured"

fi
if secaudit_rule_enabled 120; then
sec_audit_remediate_skip 120 "review  remediation: Ensure access to /etc/cron.daily is configured"

fi
if secaudit_rule_enabled 121; then
sec_audit_remediate_skip 121 "review  remediation: Ensure access to /etc/cron.weekly is configured"

fi
if secaudit_rule_enabled 122; then
sec_audit_remediate_skip 122 "review  remediation: Ensure access to /etc/cron.monthly is configured"

fi
if secaudit_rule_enabled 123; then
sec_audit_remediate_skip 123 "review  remediation: Ensure access to /etc/cron.yearly is configured"

fi
if secaudit_rule_enabled 124; then
sec_audit_remediate_skip 124 "review  remediation: Ensure access to /etc/cron.d is configured"

fi
if secaudit_rule_enabled 125; then
sec_audit_remediate_skip 125 "review  remediation: Ensure access to crontab is configured"

fi
if secaudit_rule_enabled 126; then
sec_audit_remediate_skip 126 "review  remediation: Ensure access to at is configured"

fi
}

sec_audit_remediate_network() {
if secaudit_rule_enabled 127; then
sec_audit_remediate_skip 127 "Ensure IPv6 status is identified"

fi
if secaudit_rule_enabled 128; then
sec_audit_disable_kmod bluetooth
sec_audit_remediate_done 128 "disabled wireless interfaces"

fi
if secaudit_rule_enabled 129; then
sec_audit_disable_svc bluetooth.service
sec_audit_pkg_remove bluez
sec_audit_remediate_done 129 "disabled bluez"

fi
if secaudit_rule_enabled 130; then
sec_audit_disable_kmod is
sec_audit_remediate_done 130 "blacklisted is"

fi
if secaudit_rule_enabled 131; then
sec_audit_disable_kmod is
sec_audit_remediate_done 131 "blacklisted is"

fi
if secaudit_rule_enabled 132; then
sec_audit_disable_kmod is
sec_audit_remediate_done 132 "blacklisted is"

fi
if secaudit_rule_enabled 133; then
sec_audit_disable_kmod is
sec_audit_remediate_done 133 "blacklisted is"

fi
if secaudit_rule_enabled 134; then
sec_audit_disable_kmod is
sec_audit_remediate_done 134 "blacklisted is"

fi
if secaudit_rule_enabled 135; then
sec_audit_disable_kmod is
sec_audit_remediate_done 135 "blacklisted is"

fi
if secaudit_rule_enabled 136; then
sec_audit_set_sysctl net.ipv4.ip_forward 0
sec_audit_remediate_done 136 "set net.ipv4.ip_forward=0"

fi
if secaudit_rule_enabled 137; then
sec_audit_remediate_skip 137 "review  remediation: Ensure net.ipv4.conf.all.forwarding is configured"

fi
if secaudit_rule_enabled 138; then
sec_audit_remediate_skip 138 "review  remediation: Ensure net.ipv4.conf.default.forwarding is configured"

fi
if secaudit_rule_enabled 139; then
sec_audit_set_sysctl net.ipv4.conf.all.send_redirects 0
sec_audit_remediate_done 139 "set net.ipv4.conf.all.send_redirects=0"

fi
if secaudit_rule_enabled 140; then
sec_audit_set_sysctl net.ipv4.conf.all.send_redirects 0
sec_audit_remediate_done 140 "set net.ipv4.conf.all.send_redirects=0"

fi
if secaudit_rule_enabled 141; then
sec_audit_set_sysctl net.ipv4.icmp_ignore_bogus_error_responses 1
sec_audit_remediate_done 141 "set net.ipv4.icmp_ignore_bogus_error_responses=1"

fi
if secaudit_rule_enabled 142; then
sec_audit_remediate_skip 142 "review  remediation: Ensure net.ipv4.icmp_echo_ignore_broadcasts is configured"

fi
if secaudit_rule_enabled 143; then
sec_audit_set_sysctl net.ipv4.conf.all.accept_redirects 0
sec_audit_remediate_done 143 "set net.ipv4.conf.all.accept_redirects=0"

fi
if secaudit_rule_enabled 144; then
sec_audit_set_sysctl net.ipv4.conf.all.accept_redirects 0
sec_audit_remediate_done 144 "set net.ipv4.conf.all.accept_redirects=0"

fi
if secaudit_rule_enabled 145; then
sec_audit_set_sysctl net.ipv4.conf.all.secure_redirects 0
sec_audit_remediate_done 145 "set net.ipv4.conf.all.secure_redirects=0"

fi
if secaudit_rule_enabled 146; then
sec_audit_set_sysctl net.ipv4.conf.all.secure_redirects 0
sec_audit_remediate_done 146 "set net.ipv4.conf.all.secure_redirects=0"

fi
if secaudit_rule_enabled 147; then
sec_audit_set_sysctl net.ipv4.conf.all.rp_filter 1
sec_audit_remediate_done 147 "set net.ipv4.conf.all.rp_filter=1"

fi
if secaudit_rule_enabled 148; then
sec_audit_set_sysctl net.ipv4.conf.all.rp_filter 1
sec_audit_remediate_done 148 "set net.ipv4.conf.all.rp_filter=1"

fi
if secaudit_rule_enabled 149; then
sec_audit_remediate_skip 149 "review  remediation: Ensure net.ipv4.conf.all.accept_source_route is configured"

fi
if secaudit_rule_enabled 150; then
sec_audit_remediate_skip 150 "review  remediation: Ensure net.ipv4.conf.default.accept_source_route is configured"

fi
if secaudit_rule_enabled 151; then
sec_audit_set_sysctl net.ipv4.conf.all.log_martians 1
sec_audit_remediate_done 151 "set net.ipv4.conf.all.log_martians=1"

fi
if secaudit_rule_enabled 152; then
sec_audit_set_sysctl net.ipv4.conf.all.log_martians 1
sec_audit_remediate_done 152 "set net.ipv4.conf.all.log_martians=1"

fi
if secaudit_rule_enabled 153; then
sec_audit_set_sysctl net.ipv4.tcp_syncookies 1
sec_audit_remediate_done 153 "set net.ipv4.tcp_syncookies=1"

fi
if secaudit_rule_enabled 154; then
sec_audit_remediate_skip 154 "review  remediation: Ensure net.ipv4.conf.all.route_localnet is configured"

fi
if secaudit_rule_enabled 155; then
sec_audit_remediate_skip 155 "review  remediation: Ensure net.ipv4.conf.default.route_localnet is configured"

fi
if secaudit_rule_enabled 156; then
sec_audit_remediate_skip 156 "Ensure net.ipv6.conf.all.forwarding is configured"

fi
if secaudit_rule_enabled 157; then
sec_audit_remediate_skip 157 "Ensure net.ipv6.conf.default.forwarding is configured"

fi
if secaudit_rule_enabled 158; then
sec_audit_remediate_skip 158 "Ensure net.ipv6.conf.all.accept_redirects is configured"

fi
if secaudit_rule_enabled 159; then
sec_audit_remediate_skip 159 "Ensure net.ipv6.conf.default.accept_redirects is configured"

fi
if secaudit_rule_enabled 160; then
sec_audit_remediate_skip 160 "Ensure net.ipv6.conf.all.accept_source_route is configured"

fi
if secaudit_rule_enabled 161; then
sec_audit_remediate_skip 161 "Ensure net.ipv6.conf.default.accept_source_route is configured"

fi
if secaudit_rule_enabled 162; then
sec_audit_remediate_skip 162 "Ensure net.ipv6.conf.all.accept_ra is configured"

fi
if secaudit_rule_enabled 163; then
sec_audit_remediate_skip 163 "Ensure net.ipv6.conf.default.accept_ra is configured"

fi
}

sec_audit_remediate_logging_and_auditing() {
if secaudit_rule_enabled 164; then
sec_audit_pkg_install firewalld
sec_audit_start_svc firewalld
sec_audit_remediate_done 164 "installed firewalld"

fi
if secaudit_rule_enabled 165; then
sec_audit_remediate_skip 165 "review  remediation: Ensure firewalld backend is configured"

fi
if secaudit_rule_enabled 166; then
sec_audit_remediate_skip 166 "review  remediation: Ensure firewalld.service is configured"

fi
if secaudit_rule_enabled 167; then
sec_audit_remediate_skip 167 "review  remediation: Ensure firewalld active zone target is configured"

fi
if secaudit_rule_enabled 168; then
sec_audit_remediate_skip 168 "Ensure firewalld loopback traffic is configured"

fi
if secaudit_rule_enabled 169; then
sec_audit_remediate_skip 169 "Ensure firewalld loopback source address traffic is configured"

fi
if secaudit_rule_enabled 170; then
sec_audit_remediate_skip 170 "Ensure firewalld services and ports are configured"

fi
if secaudit_rule_enabled 171; then
sec_audit_remediate_skip 171 "Ensure firewalld default zone is set to drop"

fi
if secaudit_rule_enabled 172; then
sec_audit_remediate_skip 172 "review  remediation: Ensure conflicting firewall utilities are not in use with firewalld"

fi
if secaudit_rule_enabled 173; then
sec_audit_remediate_skip 173 "review  remediation: Ensure firewalld logs denied packets"

fi
if secaudit_rule_enabled 174; then
sec_audit_remediate_skip 174 "review  remediation: Ensure firewalld blocks ICMP timestamp requests and replies"

fi
}

sec_audit_remediate_access_control() {
if secaudit_rule_enabled 175; then
sec_audit_remediate_skip 175 "review  remediation: Ensure access to /etc/ssh/sshd_config is configured"

fi
if secaudit_rule_enabled 176; then
sec_audit_remediate_skip 176 "review  remediation: Ensure access to /etc/ssh/sshd_config.d/ directory is configured"

fi
if secaudit_rule_enabled 177; then
sec_audit_remediate_skip 177 "review  remediation: Ensure access to SSH private host key files is configured"

fi
if secaudit_rule_enabled 178; then
sec_audit_remediate_skip 178 "review  remediation: Ensure access to SSH public host key files is configured"

fi
if secaudit_rule_enabled 179; then
sec_audit_remediate_skip 179 "review  remediation: Ensure sshd Ciphers are configured"

fi
if secaudit_rule_enabled 180; then
sec_audit_remediate_skip 180 "review  remediation: Ensure sshd KexAlgorithms is configured"

fi
if secaudit_rule_enabled 181; then
sec_audit_remediate_skip 181 "review  remediation: Ensure sshd MACs are configured"

fi
if secaudit_rule_enabled 182; then
sec_audit_remediate_skip 182 "review  remediation: Ensure sshd access is configured"

fi
if secaudit_rule_enabled 183; then
sec_audit_set_sshd_kv Banner /etc/issue.net
sec_audit_remediate_done 183 "sshd Banner"

fi
if secaudit_rule_enabled 184; then
sec_audit_set_sshd_kv ClientAliveInterval 300
sec_audit_remediate_done 184 "sshd ClientAliveInterval"

fi
if secaudit_rule_enabled 185; then
sec_audit_set_sshd_kv DisableForwarding yes
sec_audit_remediate_done 185 "sshd DisableForwarding"

fi
if secaudit_rule_enabled 186; then
sec_audit_set_sshd_kv GSSAPIAuthentication no
sec_audit_remediate_done 186 "sshd GSSAPIAuthentication"

fi
if secaudit_rule_enabled 187; then
sec_audit_set_sshd_kv HostbasedAuthentication no
sec_audit_remediate_done 187 "sshd HostbasedAuthentication"

fi
if secaudit_rule_enabled 188; then
sec_audit_set_sshd_kv IgnoreRhosts yes
sec_audit_remediate_done 188 "sshd IgnoreRhosts"

fi
if secaudit_rule_enabled 189; then
sec_audit_set_sshd_kv LoginGraceTime 60
sec_audit_remediate_done 189 "sshd LoginGraceTime"

fi
if secaudit_rule_enabled 190; then
sec_audit_set_sshd_kv LogLevel VERBOSE
sec_audit_remediate_done 190 "sshd LogLevel"

fi
if secaudit_rule_enabled 191; then
sec_audit_set_sshd_kv MaxAuthTries 4
sec_audit_remediate_done 191 "sshd MaxAuthTries"

fi
if secaudit_rule_enabled 192; then
sec_audit_set_sshd_kv MaxStartups 10:30:60
sec_audit_remediate_done 192 "sshd MaxStartups"

fi
if secaudit_rule_enabled 193; then
sec_audit_set_sshd_kv MaxSessions 10
sec_audit_remediate_done 193 "sshd MaxSessions"

fi
if secaudit_rule_enabled 194; then
sec_audit_set_sshd_kv PermitEmptyPasswords no
sec_audit_remediate_done 194 "sshd PermitEmptyPasswords"

fi
if secaudit_rule_enabled 195; then
sec_audit_set_sshd_kv PermitRootLogin no
sec_audit_remediate_done 195 "sshd PermitRootLogin"

fi
if secaudit_rule_enabled 196; then
sec_audit_set_sshd_kv PermitUserEnvironment no
sec_audit_remediate_done 196 "sshd PermitUserEnvironment"

fi
if secaudit_rule_enabled 197; then
sec_audit_set_sshd_kv UsePAM yes
sec_audit_remediate_done 197 "sshd UsePAM"

fi
if secaudit_rule_enabled 198; then
sec_audit_pkg_install sudo
sec_audit_remediate_done 198 "sudo installed"

fi
if secaudit_rule_enabled 199; then
sec_audit_remediate_skip 199 "review  remediation: Ensure access on sudoers configuration files is configured"

fi
if secaudit_rule_enabled 200; then
sec_audit_remediate_skip 200 "review  remediation: Ensure access on the /etc/sudoers.d directory is configured"

fi
if secaudit_rule_enabled 201; then
sec_audit_remediate_skip 201 "review  remediation: Ensure sudo commands use pty"

fi
if secaudit_rule_enabled 202; then
sec_audit_remediate_skip 202 "review  remediation: Ensure sudo log file exists"

fi
if secaudit_rule_enabled 203; then
sec_audit_remediate_skip 203 "review  remediation: Ensure users must provide password for escalation"

fi
if secaudit_rule_enabled 204; then
sec_audit_remediate_skip 204 "review  remediation: Ensure re-authentication for privilege escalation is not disabled globally"

fi
if secaudit_rule_enabled 205; then
sec_audit_remediate_skip 205 "review  remediation: Ensure sudo pwfeedback is configured"

fi
if secaudit_rule_enabled 206; then
sec_audit_remediate_skip 206 "review  remediation: Ensure sudo visiblepw is configured"

fi
if secaudit_rule_enabled 207; then
echo "Defaults timestamp_timeout=5" >/etc/sudoers.d/99-cre-timeout
chmod 440 /etc/sudoers.d/99-cre-timeout
sec_audit_remediate_done 207 "sudo timestamp_timeout=5"

fi
if secaudit_rule_enabled 208; then
sec_audit_remediate_skip 208 "review  remediation: Ensure sudo timestamp_type is configured"

fi
if secaudit_rule_enabled 209; then
sec_audit_remediate_skip 209 "review  remediation: Ensure access to the su command is restricted"

fi
if secaudit_rule_enabled 210; then
sec_audit_remediate_skip 210 "review  remediation: Ensure latest version of pam is installed"

fi
if secaudit_rule_enabled 211; then
sec_audit_remediate_skip 211 "review  remediation: Ensure latest version of authselect is installed"

fi
if secaudit_rule_enabled 212; then
sec_audit_authselect_enable with-pwquality
sec_audit_set_pwquality_kv minlen 14
sec_audit_remediate_done 212 "password quality"

fi
if secaudit_rule_enabled 213; then
sec_audit_remediate_skip 213 "review  remediation: Ensure PAM is managed by an active authselect profile"

fi
if secaudit_rule_enabled 214; then
sec_audit_authselect_enable with-faillock
authselect apply-changes >/dev/null 2>&1 || true
sec_audit_remediate_done 214 "pam faillock"

fi
if secaudit_rule_enabled 215; then
sec_audit_authselect_enable with-pwquality
sec_audit_set_pwquality_kv minlen 14
sec_audit_remediate_done 215 "password quality"

fi
if secaudit_rule_enabled 216; then
sec_audit_authselect_enable with-pwhistory
grep -q '^remember' /etc/security/pwhistory.conf 2>/dev/null || echo 'remember = 24' >>/etc/security/pwhistory.conf
sec_audit_remediate_done 216 "password history"

fi
if secaudit_rule_enabled 217; then
sec_audit_remediate_skip 217 "review  remediation: Ensure pam_unix module is enabled"

fi
if secaudit_rule_enabled 218; then
sec_audit_authselect_enable with-faillock
authselect apply-changes >/dev/null 2>&1 || true
sec_audit_remediate_done 218 "pam faillock"

fi
if secaudit_rule_enabled 219; then
sec_audit_remediate_skip 219 "review  remediation: Ensure password unlock time is configured"

fi
if secaudit_rule_enabled 220; then
sec_audit_remediate_skip 220 "Ensure password failed attempts lockout includes root account"

fi
if secaudit_rule_enabled 221; then
sec_audit_remediate_skip 221 "review  remediation: Ensure password number of changed characters is configured"

fi
if secaudit_rule_enabled 222; then
sec_audit_remediate_skip 222 "review  remediation: Ensure password length is configured"

fi
if secaudit_rule_enabled 223; then
sec_audit_remediate_skip 223 "Ensure password complexity is configured"

fi
if secaudit_rule_enabled 224; then
sec_audit_remediate_skip 224 "review  remediation: Ensure password same consecutive characters is configured"

fi
if secaudit_rule_enabled 225; then
sec_audit_remediate_skip 225 "review  remediation: Ensure password maximum sequential characters is configured"

fi
if secaudit_rule_enabled 226; then
sec_audit_remediate_skip 226 "review  remediation: Ensure password dictionary check is enabled"

fi
if secaudit_rule_enabled 227; then
if ! grep -Psi '^\h*enforce_for_root\b' /etc/security/pwquality.conf 2>/dev/null | grep -q .; then
    printf 'enforce_for_root\n' >> /etc/security/pwquality.conf
fi
sec_audit_remediate_done 227 "pwquality enforce_for_root"

fi
if secaudit_rule_enabled 228; then
sec_audit_authselect_enable with-pwhistory
grep -q '^remember' /etc/security/pwhistory.conf 2>/dev/null || echo 'remember = 24' >>/etc/security/pwhistory.conf
sec_audit_remediate_done 228 "password history"

fi
if secaudit_rule_enabled 229; then
sec_audit_authselect_enable with-pwhistory
grep -q '^remember' /etc/security/pwhistory.conf 2>/dev/null || echo 'remember = 24' >>/etc/security/pwhistory.conf
sec_audit_remediate_done 229 "password history"

fi
if secaudit_rule_enabled 230; then
sec_audit_authselect_enable with-pwhistory
grep -q '^remember' /etc/security/pwhistory.conf 2>/dev/null || echo 'remember = 24' >>/etc/security/pwhistory.conf
sec_audit_remediate_done 230 "password history"

fi
if secaudit_rule_enabled 231; then
sec_audit_remediate_skip 231 "review  remediation: Ensure pam_unix does not include nullok"

fi
if secaudit_rule_enabled 232; then
sec_audit_authselect_enable with-pwhistory
grep -q '^remember' /etc/security/pwhistory.conf 2>/dev/null || echo 'remember = 24' >>/etc/security/pwhistory.conf
sec_audit_remediate_done 232 "password history"

fi
if secaudit_rule_enabled 233; then
sec_audit_set_login_defs_kv ENCRYPT_METHOD SHA512
sec_audit_remediate_done 233 "ENCRYPT_METHOD SHA512"

fi
if secaudit_rule_enabled 234; then
sec_audit_remediate_skip 234 "review  remediation: Ensure pam_unix includes use_authtok"

fi
if secaudit_rule_enabled 235; then
sec_audit_remediate_skip 235 "review  remediation: Ensure password expiration is configured"

fi
if secaudit_rule_enabled 236; then
sec_audit_remediate_skip 236 "Ensure minimum password days is configured"

fi
if secaudit_rule_enabled 237; then
sec_audit_remediate_skip 237 "review  remediation: Ensure password expiration warning days is configured"

fi
if secaudit_rule_enabled 238; then
sec_audit_set_login_defs_kv ENCRYPT_METHOD SHA512
sec_audit_remediate_done 238 "ENCRYPT_METHOD SHA512"

fi
if secaudit_rule_enabled 239; then
sec_audit_remediate_skip 239 "Ensure inactive password lock is configured"

fi
if secaudit_rule_enabled 240; then
sec_audit_remediate_skip 240 "Ensure all users last password change date is in the past"

fi
if secaudit_rule_enabled 241; then
sec_audit_remediate_skip 241 "Ensure root is the only UID 0 account"

fi
if secaudit_rule_enabled 242; then
sec_audit_remediate_skip 242 "Ensure root is the only GID 0 account"

fi
if secaudit_rule_enabled 243; then
sec_audit_remediate_skip 243 "Ensure group root is the only GID 0 group"

fi
if secaudit_rule_enabled 244; then
sec_audit_remediate_skip 244 "Ensure root account access is controlled"

fi
if secaudit_rule_enabled 245; then
sec_audit_remediate_skip 245 "Ensure root path integrity"

fi
if secaudit_rule_enabled 246; then
sec_audit_set_login_defs_kv UMASK 027
cat >/etc/profile.d/99-cre-umask.sh <<'EOF'
umask 027
EOF
sec_audit_remediate_done 246 "default umask 027"

fi
if secaudit_rule_enabled 247; then
sec_audit_remediate_skip 247 "Ensure system accounts do not have a valid login shell"

fi
if secaudit_rule_enabled 248; then
sec_audit_remediate_skip 248 "Ensure accounts without a valid login shell are locked"

fi
if secaudit_rule_enabled 249; then
sec_audit_remediate_skip 249 "review  remediation: Ensure nologin is not listed in /etc/shells"

fi
if secaudit_rule_enabled 250; then
cat >/etc/profile.d/99-cre-timeout.sh <<'EOF'
TMOUT=600
readonly TMOUT
export TMOUT
EOF
sec_audit_remediate_done 250 "TMOUT=600"

fi
if secaudit_rule_enabled 251; then
sec_audit_set_login_defs_kv UMASK 027
cat >/etc/profile.d/99-cre-umask.sh <<'EOF'
umask 027
EOF
sec_audit_remediate_done 251 "default umask 027"

fi
if secaudit_rule_enabled 252; then
sec_audit_set_login_defs_kv UMASK 027
cat >/etc/profile.d/99-cre-umask.sh <<'EOF'
umask 027
EOF
sec_audit_remediate_done 252 "default umask 027"

fi
}

sec_audit_remediate_system_maintenance() {
if secaudit_rule_enabled 253; then
sec_audit_start_svc systemd-journald
sec_audit_remediate_done 253 "journald active"

fi
if secaudit_rule_enabled 254; then
sec_audit_remediate_skip 254 "Ensure systemd-journal-remote is not in use"

fi
if secaudit_rule_enabled 255; then
sec_audit_start_svc systemd-journald
sec_audit_remediate_done 255 "journald active"

fi
if secaudit_rule_enabled 256; then
sec_audit_remediate_skip 256 "Ensure journald log file rotation is configured"

fi
if secaudit_rule_enabled 257; then
sec_audit_remediate_skip 257 "Ensure journald log file access is configured"

fi
if secaudit_rule_enabled 258; then
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
sec_audit_remediate_done 258 "rsyslog installed"

fi
if secaudit_rule_enabled 259; then
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
sec_audit_remediate_done 259 "rsyslog installed"

fi
if secaudit_rule_enabled 260; then
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
sec_audit_remediate_done 260 "rsyslog installed"

fi
if secaudit_rule_enabled 261; then
sec_audit_pkg_install rsyslog
[ -f /etc/rsyslog.conf ] && chown root:root /etc/rsyslog.conf && chmod 0640 /etc/rsyslog.conf
if [ -d /etc/rsyslog.d ]; then
    chown root:root /etc/rsyslog.d && chmod 0755 /etc/rsyslog.d
    find /etc/rsyslog.d -type f -name '*.conf' -exec chown root:root {} + -exec chmod 0640 {} + 2>/dev/null || true
fi
sec_audit_remediate_done 261 "rsyslog configuration files 0640 root:root"

fi
if secaudit_rule_enabled 262; then
if [ -d /etc/rsyslog.d ]; then
    chown root:root /etc/rsyslog.d && chmod 0755 /etc/rsyslog.d
fi
sec_audit_remediate_done 262 "/etc/rsyslog.d owned by root:root with mode 0755"

fi
if secaudit_rule_enabled 263; then
_wd=$(grep -Pohsi -- '(?<=^\$WorkDirectory\h)[^[:space:]]+' /etc/rsyslog.conf 2>/dev/null | head -n1)
[ -n "$_wd" ] || _wd=/var/lib/rsyslog
mkdir -p "$_wd"
chown root:root "$_wd" && chmod 0700 "$_wd"
sec_audit_remediate_done 263 "rsyslog work directory ${_wd} 0700 root:root"

fi
if secaudit_rule_enabled 264; then
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
sec_audit_remediate_done 264 "rsyslog installed"

fi
if secaudit_rule_enabled 265; then
sec_audit_remediate_skip 265 "Ensure rsyslog logging rules are configured"

fi
if secaudit_rule_enabled 266; then
sec_audit_remediate_skip 266 "Ensure rsyslog is configured to send logs to a remote log host"

fi
if secaudit_rule_enabled 267; then
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
sec_audit_remediate_done 267 "rsyslog installed"

fi
if secaudit_rule_enabled 268; then
sec_audit_remediate_skip 268 "install/configure rsyslog remote forwarding only when log host policy exists"

fi
if secaudit_rule_enabled 269; then
sec_audit_remediate_skip 269 "Ensure rsyslog TLS CA certificate is configured"

fi
if secaudit_rule_enabled 270; then
sec_audit_remediate_skip 270 "Ensure rsyslog TLS client certificate is configured"

fi
if secaudit_rule_enabled 271; then
sec_audit_remediate_skip 271 "Ensure logrotate is configured"

fi
if secaudit_rule_enabled 272; then
sec_audit_remediate_skip 272 "review  remediation: Ensure access to all logfiles has been configured"

fi
if secaudit_rule_enabled 273; then
sec_audit_pkg_install audit
sec_audit_start_svc auditd
sec_audit_remediate_done 273 "auditd running"

fi
if secaudit_rule_enabled 274; then
sec_audit_pkg_install audit
sec_audit_start_svc auditd
sec_audit_remediate_done 274 "auditd running"

fi
if secaudit_rule_enabled 275; then
sec_audit_pkg_install audit auditd 2>/dev/null || true
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-rocky9-cre.rules <<'EOF'
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
sec_audit_remediate_done 275 "audit rules baseline"

fi
if secaudit_rule_enabled 276; then
sec_audit_pkg_install audit
sec_audit_start_svc auditd
sec_audit_remediate_done 276 "auditd running"

fi
if secaudit_rule_enabled 277; then
sec_audit_pkg_install audit auditd 2>/dev/null || true
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-rocky9-cre.rules <<'EOF'
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
sec_audit_remediate_done 277 "audit rules baseline"

fi
if secaudit_rule_enabled 278; then
sec_audit_remediate_skip 278 "review  remediation: Ensure audit logs are not automatically deleted"

fi
if secaudit_rule_enabled 279; then
sec_audit_remediate_skip 279 "review  remediation: Ensure system is disabled when audit logs are full"

fi
if secaudit_rule_enabled 280; then
sec_audit_remediate_skip 280 "review  remediation: Ensure system warns when audit logs are low on space"

fi
if secaudit_rule_enabled 281; then
sec_audit_remediate_skip 281 "review  remediation: Ensure modification of the /etc/sudoers file is collected"

fi
if secaudit_rule_enabled 282; then
sec_audit_remediate_skip 282 "review  remediation: Ensure actions as another user are always logged"

fi
if secaudit_rule_enabled 283; then
sec_audit_remediate_skip 283 "review  remediation: Ensure events that modify the sudo log file are collected"

fi
if secaudit_rule_enabled 284; then
sec_audit_remediate_skip 284 "review  remediation: Ensure events that modify date and time information are collected"

fi
if secaudit_rule_enabled 285; then
sec_audit_remediate_skip 285 "review  remediation: Ensure events that modify sethostname and setdomainname are collected"

fi
if secaudit_rule_enabled 286; then
sec_audit_remediate_skip 286 "review  remediation: Ensure events that modify /etc/issue and /etc/issue.net are collected"

fi
if secaudit_rule_enabled 287; then
sec_audit_remediate_skip 287 "review  remediation: Ensure events that modify /etc/hosts and /etc/hostname are collected"

fi
if secaudit_rule_enabled 288; then
sec_audit_remediate_skip 288 "review  remediation: Ensure events that modify /etc/sysconfig/network and /etc/NetworkManager/system-connections/ are collected"

fi
if secaudit_rule_enabled 289; then
sec_audit_remediate_skip 289 "review  remediation: Ensure events that modify /etc/NetworkManager directory are collected"

fi
if secaudit_rule_enabled 290; then
sec_audit_remediate_skip 290 "review  remediation: Ensure use of privileged commands are collected"

fi
if secaudit_rule_enabled 291; then
sec_audit_remediate_skip 291 "review  remediation: Ensure unsuccessful file access attempts are collected"

fi
if secaudit_rule_enabled 292; then
sec_audit_remediate_skip 292 "Ensure events that modify /etc/group information are collected"

fi
if secaudit_rule_enabled 293; then
sec_audit_remediate_skip 293 "review  remediation: Ensure events that modify /etc/passwd information are collected"

fi
if secaudit_rule_enabled 294; then
sec_audit_remediate_skip 294 "review  remediation: Ensure events that modify /etc/shadow and /etc/gshadow are collected"

fi
if secaudit_rule_enabled 295; then
sec_audit_remediate_skip 295 "review  remediation: Ensure events that modify /etc/security/opasswd are collected"

fi
if secaudit_rule_enabled 296; then
sec_audit_remediate_skip 296 "review  remediation: Ensure events that modify /etc/nsswitch.conf file are collected"

fi
if secaudit_rule_enabled 297; then
sec_audit_remediate_skip 297 "review  remediation: Ensure events that modify /etc/pam.conf and /etc/pam.d/ information are collected"

fi
if secaudit_rule_enabled 298; then
sec_audit_remediate_skip 298 "review  remediation: Ensure discretionary access control permission modification events chmod,fchmod,fchmodat are collected"

fi
if secaudit_rule_enabled 299; then
sec_audit_remediate_skip 299 "review  remediation: Ensure discretionary access control permission modification events chown,fchown,lchown,fchownat are collected"

fi
if secaudit_rule_enabled 300; then
sec_audit_remediate_skip 300 "review  remediation: Ensure discretionary access control permission modification events setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr collected"

fi
if secaudit_rule_enabled 301; then
sec_audit_remediate_skip 301 "review  remediation: Ensure successful file system mounts are collected"

fi
if secaudit_rule_enabled 302; then
sec_audit_remediate_skip 302 "review  remediation: Ensure session initiation information is collected"

fi
if secaudit_rule_enabled 303; then
sec_audit_remediate_skip 303 "review  remediation: Ensure login and logout events are collected"

fi
if secaudit_rule_enabled 304; then
sec_audit_remediate_skip 304 "review  remediation: Ensure unlink file deletion events by users are collected"

fi
if secaudit_rule_enabled 305; then
sec_audit_remediate_skip 305 "review  remediation: Ensure rename file deletion events by users are collected"

fi
if secaudit_rule_enabled 306; then
sec_audit_remediate_skip 306 "review  remediation: Ensure events that modify the system's Mandatory Access Controls are collected"

fi
if secaudit_rule_enabled 307; then
sec_audit_remediate_skip 307 "review  remediation: Ensure successful and unsuccessful attempts to use the chcon command are collected"

fi
if secaudit_rule_enabled 308; then
sec_audit_remediate_skip 308 "review  remediation: Ensure successful and unsuccessful attempts to use the setfacl command are collected"

fi
if secaudit_rule_enabled 309; then
sec_audit_remediate_skip 309 "review  remediation: Ensure successful and unsuccessful attempts to use the chacl command are collected"

fi
if secaudit_rule_enabled 310; then
sec_audit_remediate_skip 310 "review  remediation: Ensure successful and unsuccessful attempts to use the usermod command are collected"

fi
if secaudit_rule_enabled 311; then
sec_audit_disable_kmod loading
sec_audit_remediate_done 311 "blacklisted loading"

fi
if secaudit_rule_enabled 312; then
sec_audit_remediate_skip 312 "review  remediation: Ensure kernel 'init_module' and 'finit_module' loading unloading and modification is collected"

fi
if secaudit_rule_enabled 313; then
sec_audit_remediate_skip 313 "review  remediation: Ensure kernel 'delete_module' loading unloading and modification is collected"

fi
if secaudit_rule_enabled 314; then
sec_audit_remediate_skip 314 "review  remediation: Ensure the audit configuration is loaded regardless of errors"

fi
if secaudit_rule_enabled 315; then
sec_audit_remediate_skip 315 "review  remediation: Ensure the audit configuration is immutable"

fi
if secaudit_rule_enabled 316; then
sec_audit_remediate_skip 316 "review  remediation: Ensure the running and on disk configuration is the same"

fi
if secaudit_rule_enabled 317; then
mkdir -p /var/log/audit
chown root:root /var/log/audit && chmod 0750 /var/log/audit
sec_audit_remediate_done 317 "/var/log/audit 0750 root:root"

fi
if secaudit_rule_enabled 318; then
if [ -d /var/log/audit ]; then
    find /var/log/audit -maxdepth 1 -type f -name 'audit.log*' -exec chmod 0640 {} + 2>/dev/null || true
fi
sec_audit_remediate_done 318 "audit log files mode 0640"

fi
if secaudit_rule_enabled 319; then
if [ -d /var/log/audit ]; then
    find /var/log/audit -maxdepth 1 -type f -name 'audit.log*' -exec chown root {} + 2>/dev/null || true
fi
sec_audit_remediate_done 319 "audit log files owned by root"

fi
if secaudit_rule_enabled 320; then
if [ -d /var/log/audit ]; then
    find /var/log/audit -maxdepth 1 -type f -name 'audit.log*' -exec chgrp root {} + 2>/dev/null || true
fi
sec_audit_remediate_done 320 "audit log files group-owned by root"

fi
if secaudit_rule_enabled 321; then
sec_audit_pkg_install audit
if [ -d /etc/audit ]; then
    find /etc/audit -type f \( -name '*.conf' -o -name '*.rules' \) -exec chmod 0640 {} + 2>/dev/null || true
fi
sec_audit_remediate_done 321 "audit configuration files mode 0640"

fi
if secaudit_rule_enabled 322; then
if [ -d /etc/audit ]; then
    find /etc/audit -type f \( -name '*.conf' -o -name '*.rules' \) -exec chown root {} + 2>/dev/null || true
fi
sec_audit_remediate_done 322 "audit configuration files owned by root"

fi
if secaudit_rule_enabled 323; then
if [ -d /etc/audit ]; then
    find /etc/audit -type f \( -name '*.conf' -o -name '*.rules' \) -exec chgrp root {} + 2>/dev/null || true
fi
sec_audit_remediate_done 323 "audit configuration files group-owned by root"

fi
if secaudit_rule_enabled 324; then
for _t in auditctl ausearch aureport autrace; do
    _p=$(command -v "$_t" 2>/dev/null) && chmod 0755 "$_p"
done
sec_audit_remediate_done 324 "audit tools mode 0755"

fi
if secaudit_rule_enabled 325; then
for _t in auditctl ausearch aureport autrace; do
    _p=$(command -v "$_t" 2>/dev/null) && chown root "$_p"
done
sec_audit_remediate_done 325 "audit tools owned by root"

fi
if secaudit_rule_enabled 326; then
for _t in auditctl ausearch aureport autrace; do
    _p=$(command -v "$_t" 2>/dev/null) && chgrp root "$_p"
done
sec_audit_remediate_done 326 "audit tools group-owned by root"

fi
if secaudit_rule_enabled 327; then
sec_audit_pkg_install aide
sec_audit_remediate_done 327 "installed AIDE"

fi
if secaudit_rule_enabled 328; then
sec_audit_pkg_install aide afick
sec_audit_remediate_done 328 "integrity tooling"

fi
if secaudit_rule_enabled 329; then
sec_audit_remediate_skip 329 "review  remediation: Ensure cryptographic mechanisms are used to protect the integrity of audit tools"

fi
if secaudit_rule_enabled 330; then
sec_audit_remediate_skip 330 "review  remediation: Ensure report_url is configured"

fi
}

sec_audit_remediate_accounts() {
if secaudit_rule_enabled 331; then
sec_audit_remediate_skip 331 "review  remediation: Ensure access to /etc/passwd is configured"

fi
if secaudit_rule_enabled 332; then
sec_audit_remediate_skip 332 "review  remediation: Ensure access to /etc/passwd- is configured"

fi
if secaudit_rule_enabled 333; then
sec_audit_remediate_skip 333 "Ensure access to /etc/group is configured"

fi
if secaudit_rule_enabled 334; then
sec_audit_remediate_skip 334 "Ensure access to /etc/group- is configured"

fi
if secaudit_rule_enabled 335; then
sec_audit_remediate_skip 335 "review  remediation: Ensure access to /etc/shadow is configured"

fi
if secaudit_rule_enabled 336; then
sec_audit_remediate_skip 336 "review  remediation: Ensure access to /etc/shadow- is configured"

fi
if secaudit_rule_enabled 337; then
sec_audit_remediate_skip 337 "review  remediation: Ensure access to /etc/gshadow is configured"

fi
if secaudit_rule_enabled 338; then
sec_audit_remediate_skip 338 "review  remediation: Ensure access to /etc/gshadow- is configured"

fi
if secaudit_rule_enabled 339; then
sec_audit_remediate_skip 339 "review  remediation: Ensure access to /etc/shells is configured"

fi
if secaudit_rule_enabled 340; then
sec_audit_remediate_skip 340 "review  remediation: Ensure access to /etc/security/opasswd is configured"

fi
if secaudit_rule_enabled 341; then
sec_audit_remediate_skip 341 "review  remediation: Ensure world writable files and directories are secured"

fi
if secaudit_rule_enabled 342; then
sec_audit_remediate_skip 342 "Ensure no files or directories without an owner and a group exist"

fi
if secaudit_rule_enabled 343; then
sec_audit_remediate_skip 343 "Ensure SUID and SGID files are reviewed"

fi
if secaudit_rule_enabled 344; then
sec_audit_remediate_skip 344 "Ensure accounts in /etc/passwd use shadowed passwords"

fi
if secaudit_rule_enabled 345; then
sec_audit_remediate_skip 345 "review  remediation: Ensure /etc/shadow password fields are not empty"

fi
if secaudit_rule_enabled 346; then
sec_audit_remediate_skip 346 "Ensure all groups in /etc/passwd exist in /etc/group"

fi
if secaudit_rule_enabled 347; then
sec_audit_remediate_skip 347 "Ensure no duplicate UIDs exist"

fi
if secaudit_rule_enabled 348; then
sec_audit_remediate_skip 348 "Ensure no duplicate GIDs exist"

fi
if secaudit_rule_enabled 349; then
sec_audit_remediate_skip 349 "Ensure no duplicate user names exist"

fi
if secaudit_rule_enabled 350; then
sec_audit_remediate_skip 350 "Ensure no duplicate group names exist"

fi
if secaudit_rule_enabled 351; then
sec_audit_remediate_skip 351 "Ensure local interactive user home directories are configured"

fi
if secaudit_rule_enabled 352; then
sec_audit_remediate_skip 352 "Ensure local interactive user dot files access is configured"

fi
}

sec_audit_maybe_security_upgrade() {
    if [ "${RL9_REMEDIATE_SECURITY_UPGRADE}" != "1" ]; then
        sec_audit_log "skipping package security upgrade (set RL9_REMEDIATE_SECURITY_UPGRADE=1 to enable)"
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
    sec_audit_log "starting remediation" 2>/dev/null || true
    sec_audit_remediate_initial_setup
    sec_audit_remediate_services
    sec_audit_remediate_network
    sec_audit_remediate_logging_and_auditing
    sec_audit_remediate_access_control
    sec_audit_remediate_system_maintenance
    sec_audit_remediate_accounts
    sec_audit_maybe_security_upgrade
    exit 0
}

sec_audit_main "$@"
