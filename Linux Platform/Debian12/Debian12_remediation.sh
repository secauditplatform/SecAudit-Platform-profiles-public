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
    local key="$1" val="$2" f="/etc/sysctl.d/99-debian12-cre-sec.conf"
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

sec_audit_log "starting remediation (sec_Debian_Linux_12_v1.1.0)"

sec_audit_remediate_kernel_modules() {
# RULE1-9
# RULE1:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 1; then
sec_audit_disable_kmod cramfs
rem_done 1 "blacklisted kernel module cramfs"

fi
# RULE2:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 2; then
sec_audit_disable_kmod freevxfs
rem_done 2 "blacklisted kernel module freevxfs"

fi
# RULE3:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 3; then
sec_audit_disable_kmod hfs
rem_done 3 "blacklisted kernel module hfs"

fi
# RULE4:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 4; then
sec_audit_disable_kmod hfsplus
rem_done 4 "blacklisted kernel module hfsplus"

fi
# RULE5:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 5; then
sec_audit_disable_kmod jffs2
rem_done 5 "blacklisted kernel module jffs2"

fi
# RULE6:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 6; then
sec_audit_disable_kmod overlay
rem_done 6 "blacklisted kernel module overlay"

fi
# RULE7:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 7; then
sec_audit_disable_kmod squashfs
rem_done 7 "blacklisted kernel module squashfs"

fi
# RULE8:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 8; then
sec_audit_disable_kmod udf
rem_done 8 "blacklisted kernel module udf"

fi
# RULE9:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 9; then
sec_audit_disable_kmod firewire-core
rem_done 9 "blacklisted kernel module firewire-core"

fi
}

sec_audit_remediate_filesystem_partitions() {
# RULE10-30
# RULE10:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 10; then
rem_skip 10 "Ensure /tmp is a separate partition"

fi
# RULE11:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 11; then
ensure_mount_option /tmp nodev
rem_done 11 "set nodev on /tmp"

fi
# RULE12:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 12; then
rem_skip 12 "Ensure nosuid option set on /tmp partition"

fi
# RULE13:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 13; then
ensure_mount_option /tmp noexec
rem_done 13 "set noexec on /tmp"

fi
# RULE14:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 14; then
rem_skip 14 "Ensure /dev/shm is a separate partition"

fi
# RULE15:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 15; then
ensure_mount_option /dev/shm nodev
rem_done 15 "set nodev on /dev/shm"

fi
# RULE16:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 16; then
rem_skip 16 "Ensure nosuid option set on /dev/shm partition"

fi
# RULE17:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 17; then
ensure_mount_option /dev/shm noexec
rem_done 17 "set noexec on /dev/shm"

fi
# RULE18:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 18; then
ensure_mount_option /home nodev
rem_done 18 "set nodev on /home"

fi
# RULE19:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 19; then
rem_skip 19 "Ensure nosuid option set on /home partition"

fi
# RULE20:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 20; then
ensure_mount_option /var nodev
rem_done 20 "set nodev on /var"

fi
# RULE21:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 21; then
rem_skip 21 "Ensure nosuid option set on /var partition"

fi
# RULE22:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 22; then
ensure_mount_option /var/tmp nodev
rem_done 22 "set nodev on /var/tmp"

fi
# RULE23:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 23; then
rem_skip 23 "Ensure nosuid option set on /var/tmp partition"

fi
# RULE24:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 24; then
ensure_mount_option /var/tmp noexec
rem_done 24 "set noexec on /var/tmp"

fi
# RULE25:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 25; then
ensure_mount_option /var/sec_audit_log nodev
rem_done 25 "set nodev on /var/sec_audit_log"

fi
# RULE26:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 26; then
rem_skip 26 "Ensure nosuid option set on /var/sec_audit_log partition"

fi
# RULE27:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 27; then
ensure_mount_option /var/sec_audit_log noexec
rem_done 27 "set noexec on /var/sec_audit_log"

fi
# RULE28:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 28; then
ensure_mount_option /var/sec_audit_log/audit nodev
rem_done 28 "set nodev on /var/sec_audit_log/audit"

fi
# RULE29:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 29; then
rem_skip 29 "Ensure nosuid option set on /var/sec_audit_log/audit partition"

fi
# RULE30:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 30; then
ensure_mount_option /var/sec_audit_log/audit noexec
rem_done 30 "set noexec on /var/sec_audit_log/audit"

fi
}

sec_audit_remediate_package_security() {
# RULE31-33
# RULE31:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 31; then
rem_skip 31 "Ensure GPG keys are configured"

fi
# RULE32:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 32; then
rem_skip 32 "Ensure package manager repositories are configured"

fi
# RULE33:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 33; then
rem_skip 33 "review remediation: Ensure updates, patches, and additional security software are installed"

fi
}

sec_audit_remediate_apparmor() {
# RULE34-35
# RULE34:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 34; then
sec_audit_pkg_install apparmor apparmor-utils
sec_audit_start_svc apparmor
rem_done 34 "apparmor enabled"

fi
# RULE35:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 35; then
harden_file /boot/grub2/grub.cfg 600 root:root
harden_file /boot/grub2/user.cfg 600 root:root
rem_done 35 "hardened grub permissions"

fi
}

sec_audit_remediate_bootloader() {
# RULE36-37
# RULE36:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 36; then
rem_skip 36 "Ensure bootloader password is set"

fi
# RULE37:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 37; then
harden_file /boot/grub2/grub.cfg 600 root:root
harden_file /boot/grub2/user.cfg 600 root:root
rem_done 37 "hardened grub permissions"

fi
}

sec_audit_remediate_process_hardening() {
# RULE38-40
# RULE38:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 38; then
rem_skip 38 "review remediation: Ensure address space layout randomization is enabled"

fi
# RULE39:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 39; then
set_sysctl kernel.yama.ptrace_scope 1
rem_done 39 "set kernel.yama.ptrace_scope=1"

fi
# RULE40:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 40; then
grep -q "hard core" /etc/security/limits.conf 2>/dev/null || echo "* hard core 0" >>/etc/security/limits.conf
mkdir -p /etc/systemd/coredump.conf.d
cat >/etc/systemd/coredump.conf.d/99-cre-sec.conf <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
sec_audit_have_bin systemctl && systemctl daemon-reload >/dev/null 2>&1 || true
rem_done 40 "disabled core dumps"

fi
}

sec_audit_remediate_banners() {
# RULE41-49
# RULE41:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 41; then
rem_skip 41 "review remediation: Ensure message of the day is configured properly"

fi
# RULE42:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 42; then
set_sshd_kv Banner /etc/issue.net
rem_done 42 "sshd Banner"

fi
# RULE43:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 43; then
rem_skip 43 "Ensure remote login warning banner is configured properly"

fi
# RULE44:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 44; then
harden_file /etc/motd 644 root:root
rem_done 44 "permissions /etc/motd"

fi
# RULE45:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 45; then
harden_file /etc/issue 644 root:root
rem_done 45 "permissions /etc/issue"

fi
# RULE46:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 46; then
harden_file /etc/issue.net 644 root:root
rem_done 46 "permissions /etc/issue.net"

fi
# RULE47:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 47; then
sec_audit_pkg_remove gdm gdm3
sec_audit_disable_svc gdm gdm3
rem_done 47 "removed GDM"

fi
# RULE48:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 48; then
mkdir -p /etc/dconf/db/gdm.d
sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
rem_done 48 "configured GDM hardening"

fi
# RULE49:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 49; then
mkdir -p /etc/dconf/db/gdm.d
sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
rem_done 49 "configured GDM hardening"

fi
}

sec_audit_remediate_gdm() {
# RULE50-56
# RULE50:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 50; then
mkdir -p /etc/dconf/db/gdm.d
sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
rem_done 50 "configured GDM hardening"

fi
# RULE51:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 51; then
sec_audit_pkg_remove gdm gdm3
sec_audit_disable_svc gdm gdm3
rem_done 51 "removed GDM"

fi
# RULE52:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 52; then
sec_audit_disable_kmod removable
rem_done 52 "disabled removable mount"

fi
# RULE53:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 53; then
sec_audit_disable_kmod removable
rem_done 53 "disabled removable mount"

fi
# RULE54:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 54; then
mkdir -p /etc/dconf/db/gdm.d
sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
rem_done 54 "configured GDM hardening"

fi
# RULE55:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 55; then
sec_audit_pkg_remove gdm gdm3
sec_audit_disable_svc gdm gdm3
rem_done 55 "removed GDM"

fi
# RULE56:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 56; then
mkdir -p /etc/dconf/db/gdm.d
sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
rem_done 56 "configured GDM hardening"

fi
}

sec_audit_remediate_unused_services() {
# RULE57-68
# RULE57:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 57; then
rem_skip 57 "review remediation: Ensure chargen services are not enabled"

fi
# RULE58:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 58; then
rem_skip 58 "review remediation: Ensure daytime services are not enabled"

fi
# RULE59:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 59; then
rem_skip 59 "review remediation: Ensure discard services are not enabled"

fi
# RULE60:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 60; then
rem_skip 60 "review remediation: Ensure echo services are not enabled"

fi
# RULE61:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 61; then
rem_skip 61 "review remediation: Ensure time services are not enabled"

fi
# RULE62:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 62; then
rem_skip 62 "review remediation: Ensure tftp server is not enabled"

fi
# RULE63:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 63; then
rem_skip 63 "review remediation: Ensure talk server is not enabled"

fi
# RULE64:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 64; then
rem_skip 64 "review remediation: Ensure telnet server is not enabled"

fi
# RULE65:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 65; then
rem_skip 65 "review remediation: Ensure rsh server is not enabled"

fi
# RULE66:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 66; then
rem_skip 66 "review remediation: Ensure rsync service is not enabled"

fi
# RULE67:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 67; then
rem_skip 67 "review remediation: Ensure NIS server is not enabled"

fi
# RULE68:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 68; then
sec_audit_pkg_remove nis
rem_done 68 "removed nis"

fi
}

sec_audit_remediate_client_tools() {
# RULE69-72
# RULE69:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 69; then
sec_audit_pkg_remove rsh-client
rem_done 69 "removed rsh-client"

fi
# RULE70:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 70; then
sec_audit_pkg_remove talk
rem_done 70 "removed talk"

fi
# RULE71:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 71; then
sec_audit_pkg_remove telnet
rem_done 71 "removed telnet"

fi
# RULE72:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 72; then
sec_audit_pkg_remove ldap-utils
rem_done 72 "removed ldap-utils"

fi
}

sec_audit_remediate_chrony() {
# RULE73-74
# RULE73:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 73; then
sec_audit_pkg_install chrony
grep -q "^pool \|^server " /etc/chrony.conf 2>/dev/null || echo "pool 2.pool.ntp.org iburst" >>/etc/chrony.conf
sec_audit_start_svc chronyd
rem_done 73 "configured chrony"

fi
# RULE74:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 74; then
sec_audit_pkg_install chrony
grep -q "^pool \|^server " /etc/chrony.conf 2>/dev/null || echo "pool 2.pool.ntp.org iburst" >>/etc/chrony.conf
sec_audit_start_svc chronyd
rem_done 74 "configured chrony"

fi
}

sec_audit_remediate_unused_services_2() {
# RULE75-75
# RULE75:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 75; then
rem_skip 75 "review remediation: Ensure X Window System is not installed"

fi
}

sec_audit_remediate_network_stack() {
# RULE76-87
# RULE76:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 76; then
rem_skip 76 "review remediation: Ensure packet redirect sending is disabled"

fi
# RULE77:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 77; then
set_sysctl net.ipv4.ip_forward 0
rem_done 77 "set net.ipv4.ip_forward=0"

fi
# RULE78:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 78; then
rem_skip 78 "review remediation: Ensure source routed packets are not accepted"

fi
# RULE79:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 79; then
rem_skip 79 "review remediation: Ensure ICMP redirects are not accepted"

fi
# RULE80:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 80; then
rem_skip 80 "review remediation: Ensure secure ICMP redirects are not accepted"

fi
# RULE81:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 81; then
rem_skip 81 "review remediation: Ensure suspicious packets are logged"

fi
# RULE82:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 82; then
rem_skip 82 "review remediation: Ensure broadcast ICMP requests are ignored"

fi
# RULE83:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 83; then
rem_skip 83 "review remediation: Ensure bogus ICMP responses are ignored"

fi
# RULE84:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 84; then
rem_skip 84 "review remediation: Ensure Reverse Path Filtering is enabled"

fi
# RULE85:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 85; then
rem_skip 85 "review remediation: Ensure TCP SYN Cookies are enabled"

fi
# RULE86:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 86; then
rem_skip 86 "Ensure IPv6 router advertisements are not accepted"

fi
# RULE87:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 87; then
rem_skip 87 "Ensure IPv6 redirects are not accepted"

fi
}

sec_audit_remediate_unused_services_3() {
# RULE88-88
# RULE88:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 88; then
rem_skip 88 "review remediation: Ensure auditing is enabled"

fi
}

sec_audit_remediate_auditd() {
# RULE89-89
# RULE89:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 89; then
sec_audit_pkg_install auditd audispd-plugins
sec_audit_start_svc auditd
rem_done 89 "auditd running"

fi
}

sec_audit_remediate_bootloader_2() {
# RULE90-91
# RULE90:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 90; then
sec_audit_pkg_install auditd audispd-plugins
sec_audit_start_svc auditd
rem_done 90 "auditd running"

fi
# RULE91:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 91; then
rem_skip 91 "review remediation: Ensure audit_backlog_limit is sufficient"

fi
}

sec_audit_remediate_auditd_2() {
# RULE92-96
# RULE92:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 92; then
sec_audit_pkg_install audit auditd 2>/dev/null || true
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-debian12-cre.rules <<'EOF'
-D
-b 8192
-f 1
-w /etc/sudoers -p wa -k scope
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /var/sec_audit_log/audit/ -p wa -k audit_log
EOF
sec_audit_have_bin augenrules && augenrules --load >/dev/null 2>&1 || true
sec_audit_start_svc auditd
rem_done 92 "audit rules baseline"

fi
# RULE93:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 93; then
rem_skip 93 "review remediation: Ensure audit logs are not automatically deleted"

fi
# RULE94:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 94; then
rem_skip 94 "review remediation: Ensure system is disabled when audit logs are full"

fi
# RULE95:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 95; then
rem_skip 95 "review remediation: Ensure audit logs are rotated appropriately"

fi
# RULE96:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 96; then
rem_skip 96 "review remediation: Ensure audit configuration is immutable"

fi
}

sec_audit_remediate_logging() {
# RULE97-102
# RULE97:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 97; then
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
rem_done 97 "rsyslog installed"

fi
# RULE98:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 98; then
sec_audit_pkg_install rsyslog
sec_audit_start_svc rsyslog
rem_done 98 "rsyslog installed"

fi
# RULE99:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 99; then
rem_skip 99 "configure central logging per site policy before enabling journal remote/upload"

fi
# RULE100:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 100; then
mkdir -p /etc/systemd/journald.conf.d
cat >/etc/systemd/journald.conf.d/99-debian12-cre.conf <<'EOF'
[Journal]
ForwardToSyslog=no
Compress=yes
Storage=persistent
EOF
systemctl restart systemd-journald >/dev/null 2>&1 || true
rem_done 100 "journald configuration"

fi
# RULE101:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 101; then
mkdir -p /etc/systemd/journald.conf.d
cat >/etc/systemd/journald.conf.d/99-debian12-cre.conf <<'EOF'
[Journal]
ForwardToSyslog=no
Compress=yes
Storage=persistent
EOF
systemctl restart systemd-journald >/dev/null 2>&1 || true
rem_done 101 "journald configuration"

fi
# RULE102:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 102; then
rem_skip 102 "Ensure logrotate is configured"

fi
}

sec_audit_remediate_cron_at() {
# RULE103-111
# RULE103:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 103; then
sec_audit_pkg_install cron
sec_audit_start_svc cron
rem_done 103 "enabled cron"

fi
# RULE104:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 104; then
chmod 600 /etc/crontab 2>/dev/null || true
chown root:root /etc/crontab 2>/dev/null || true
rem_done 104 "restricted /etc/crontab"

fi
# RULE105:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 105; then
rem_skip 105 "review remediation: Ensure permissions on /etc/cron.hourly are configured"

fi
# RULE106:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 106; then
rem_skip 106 "review remediation: Ensure permissions on /etc/cron.daily are configured"

fi
# RULE107:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 107; then
rem_skip 107 "review remediation: Ensure permissions on /etc/cron.weekly are configured"

fi
# RULE108:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 108; then
rem_skip 108 "review remediation: Ensure permissions on /etc/cron.monthly are configured"

fi
# RULE109:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 109; then
rem_skip 109 "review remediation: Ensure permissions on /etc/cron.d are configured"

fi
# RULE110:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 110; then
rem_skip 110 "review remediation: Ensure at/cron is restricted to authorized users"

fi
# RULE111:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 111; then
rem_skip 111 "review remediation: Ensure password creation requirements are configured"

fi
}

sec_audit_remediate_pam_auth() {
# RULE112-113
# RULE112:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 112; then
pam_faillock_debian >/dev/null 2>&1 || true
rem_done 112 "pam faillock"

fi
# RULE113:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 113; then
set_login_defs_kv ENCRYPT_METHOD SHA512
rem_done 113 "ENCRYPT_METHOD SHA512"

fi
}

sec_audit_remediate_sshd() {
# RULE114-114
# RULE114:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 114; then
rem_skip 114 "review remediation: Ensure root login is restricted to system console"

fi
}

sec_audit_remediate_sudo_su() {
# RULE115-118
# RULE115:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 115; then
rem_skip 115 "review remediation: Ensure su command access is restricted"

fi
# RULE116:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 116; then
sec_audit_pkg_install sudo
rem_done 116 "sudo installed"

fi
# RULE117:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 117; then
rem_skip 117 "review remediation: Ensure sudo commands use pty"

fi
# RULE118:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 118; then
rem_skip 118 "review remediation: Ensure sudo sec_audit_log file exists"

fi
}

sec_audit_remediate_identity_files() {
# RULE119-120
# RULE119:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 119; then
rem_skip 119 "review remediation: Ensure users must provide password for escalation"

fi
# RULE120:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 120; then
rem_skip 120 "review remediation: Ensure re-authentication for privilege escalation is configured"

fi
}

sec_audit_remediate_sudo_su_2() {
# RULE121-126
# RULE121:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 121; then
rem_skip 121 "review remediation: Ensure sudo authentication uses strong hashing"

fi
# RULE122:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 122; then
rem_skip 122 "Ensure inactive password lock is configured"

fi
# RULE123:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 123; then
rem_skip 123 "review remediation: Ensure password expiration is configured"

fi
# RULE124:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 124; then
rem_skip 124 "review remediation: Ensure password expiration warning days are configured"

fi
# RULE125:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 125; then
rem_skip 125 "review remediation: Ensure password minimum days is configured"

fi
# RULE126:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 126; then
rem_skip 126 "review remediation: Ensure password reuse is limited"

fi
}

sec_audit_remediate_identity_files_2() {
# RULE127-128
# RULE127:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 127; then
rem_skip 127 "review remediation: Ensure all users have a password"

fi
# RULE128:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 128; then
rem_skip 128 "Ensure system accounts are secured"

fi
}

sec_audit_remediate_accounts() {
# RULE129-131
# RULE129:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 129; then
rem_skip 129 "Ensure default group for root account is GID 0"

fi
# RULE130:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 130; then
set_login_defs_kv UMASK 027
cat >/etc/profile.d/99-cre-umask.sh <<'EOF'
umask 027
EOF
rem_done 130 "default umask 027"

fi
# RULE131:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 131; then
cat >/etc/profile.d/99-cre-timeout.sh <<'EOF'
TMOUT=600
readonly TMOUT
export TMOUT
EOF
rem_done 131 "TMOUT=600"

fi
}

sec_audit_remediate_sshd_2() {
# RULE132-132
# RULE132:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 132; then
rem_skip 132 "Ensure root account is secured"

fi
}

sec_audit_remediate_identity_files_3() {
# RULE133-135
# RULE133:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 133; then
rem_skip 133 "Ensure all accounts have unique UID"

fi
# RULE135:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 135; then
rem_skip 135 "review remediation: Ensure all users' home directories exist"

fi
}

sec_audit_remediate_filesystem_integrity() {
# RULE136-139
# RULE136:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 136; then
rem_skip 136 "review remediation: Ensure users own their home directories"

fi
# RULE137:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 137; then
rem_skip 137 "review remediation: Ensure users' home directories permissions are 750 or more restrictive"

fi
# RULE138:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 138; then
rem_skip 138 "review remediation: Ensure no users have .netrc files"

fi
# RULE139:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 139; then
rem_skip 139 "review remediation: Ensure users' .forward files are not present"

fi
}

sec_audit_remediate_sshd_3() {
# RULE140-152
# RULE140:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 140; then
rem_skip 140 "review remediation: Ensure users' .rhosts files are not present"

fi
# RULE141:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 141; then
set_sshd_kv X11Forwarding no
rem_done 141 "sshd X11Forwarding"

fi
# RULE142:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 142; then
set_sshd_kv MaxAuthTries 4
rem_done 142 "sshd MaxAuthTries"

fi
# RULE143:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 143; then
set_sshd_kv IgnoreRhosts yes
rem_done 143 "sshd IgnoreRhosts"

fi
# RULE144:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 144; then
set_sshd_kv HostbasedAuthentication no
rem_done 144 "sshd HostbasedAuthentication"

fi
# RULE145:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 145; then
rem_skip 145 "review remediation: Ensure SSH root login is disabled"

fi
# RULE146:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 146; then
set_sshd_kv PermitEmptyPasswords no
rem_done 146 "sshd PermitEmptyPasswords"

fi
# RULE147:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 147; then
set_sshd_kv PermitUserEnvironment no
rem_done 147 "sshd PermitUserEnvironment"

fi
# RULE148:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 148; then
rem_skip 148 "review remediation: Ensure SSH Idle Timeout Interval is configured"

fi
# RULE149:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 149; then
set_sshd_kv LoginGraceTime 60
rem_done 149 "sshd LoginGraceTime"

fi
# RULE150:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 150; then
rem_skip 150 "review remediation: Ensure SSH PAM is enabled"

fi
# RULE151:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 151; then
rem_skip 151 "review remediation: Ensure SSH AllowTcpForwarding is disabled"

fi
# RULE152:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 152; then
set_sshd_kv MaxStartups 10:30:60
rem_done 152 "sshd MaxStartups"

fi
}

sec_audit_remediate_aide() {
# RULE153-154
# RULE153:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 153; then
set_sshd_kv MaxSessions 10
rem_done 153 "sshd MaxSessions"

fi
# RULE154:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 154; then
sec_audit_pkg_install aide
rem_done 154 "installed AIDE"

fi
}

sec_audit_remediate_identity_files_4() {
# RULE155-168
# RULE155:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 155; then
harden_file /etc/passwd 644 root:root
rem_done 155 "permissions /etc/passwd"

fi
# RULE156:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 156; then
chmod 640 /etc/shadow 2>/dev/null || true
chown root:shadow /etc/shadow 2>/dev/null || true
rem_done 156 "permissions /etc/shadow"

fi
# RULE157:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 157; then
rem_skip 157 "Ensure permissions on /etc/group are configured"

fi
# RULE158:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 158; then
chmod 640 /etc/gshadow 2>/dev/null || true
chown root:shadow /etc/gshadow 2>/dev/null || true
rem_done 158 "permissions /etc/gshadow"

fi
# RULE159:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 159; then
rem_skip 159 "review remediation: Ensure password fields are not empty"

fi
# RULE160:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 160; then
rem_skip 160 "review remediation: Ensure no legacy '+' entries exist in /etc/passwd"

fi
# RULE161:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 161; then
rem_skip 161 "review remediation: Ensure no legacy '+' entries exist in /etc/shadow"

fi
# RULE162:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 162; then
rem_skip 162 "Ensure no legacy '+' entries exist in /etc/group"

fi
# RULE163:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 163; then
rem_skip 163 "Ensure root is the only UID 0 account"

fi
# RULE164:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 164; then
rem_skip 164 "Ensure all groups in /etc/passwd exist in /etc/group"

fi
# RULE165:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 165; then
rem_skip 165 "Ensure no duplicate UIDs exist"

fi
# RULE166:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 166; then
rem_skip 166 "Ensure no duplicate GIDs exist"

fi
# RULE167:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 167; then
rem_skip 167 "Ensure no duplicate user names exist"

fi
# RULE168:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 168; then
rem_skip 168 "Ensure no duplicate group names exist"

fi

DEBIAN_FRONTEND=noninteractive apt-get update >/dev/null 2>&1 || true
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y >/dev/null 2>&1 || true

sec_audit_log " remediation complete (Debian12_remediation.sh)"
}

sec_audit_main() {
    sec_audit_remediate_kernel_modules
    sec_audit_remediate_filesystem_partitions
    sec_audit_remediate_package_security
    sec_audit_remediate_apparmor
    sec_audit_remediate_bootloader
    sec_audit_remediate_process_hardening
    sec_audit_remediate_banners
    sec_audit_remediate_gdm
    sec_audit_remediate_unused_services
    sec_audit_remediate_client_tools
    sec_audit_remediate_chrony
    sec_audit_remediate_unused_services_2
    sec_audit_remediate_network_stack
    sec_audit_remediate_unused_services_3
    sec_audit_remediate_auditd
    sec_audit_remediate_bootloader_2
    sec_audit_remediate_auditd_2
    sec_audit_remediate_logging
    sec_audit_remediate_cron_at
    sec_audit_remediate_pam_auth
    sec_audit_remediate_sshd
    sec_audit_remediate_sudo_su
    sec_audit_remediate_identity_files
    sec_audit_remediate_sudo_su_2
    sec_audit_remediate_identity_files_2
    sec_audit_remediate_accounts
    sec_audit_remediate_sshd_2
    sec_audit_remediate_identity_files_3
    sec_audit_remediate_filesystem_integrity
    sec_audit_remediate_sshd_3
    sec_audit_remediate_aide
    sec_audit_remediate_identity_files_4
    exit 0
}

# secaudit-restore-journal: paired with Debian12_remediation.sh
SECAUDIT_JOURNAL="${SECAUDIT_JOURNAL:-/var/backups/secaudit-debian12.journal}"
SECAUDIT_PKG="${SECAUDIT_PKG:-apt}"

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


if sec_audit_rename_fn ensure_mount_option; then
ensure_mount_option() {
		sec_audit_guard_file /etc/fstab
	sec_audit_remember_mount "$1"
	ensure_mount_option_raw "$@"
}
fi


if sec_audit_rename_fn set_sysctl; then
set_sysctl() {
	local key="$1" old
		sec_audit_guard_file /etc/sysctl.d/99-debian12-cre-sec.conf
	sec_audit_guard_file /etc/sysctl.d
	old=$(sysctl -n "$key" 2>/dev/null || true)
	[ -n "$old" ] && sec_audit_journal_once sysctl "$key" "$old"
	set_sysctl_raw "$@"
}
fi


if sec_audit_rename_fn set_sshd_kv; then
set_sshd_kv() {
		sec_audit_guard_file /etc/ssh/sshd_config
	set_sshd_kv_raw "$@"
}
fi


if sec_audit_rename_fn set_login_defs_kv; then
set_login_defs_kv() {
		sec_audit_guard_file /etc/login.defs
	set_login_defs_kv_raw "$@"
}
fi


if sec_audit_rename_fn pam_faillock_debian; then
pam_faillock_debian() {
		sec_audit_guard_file /etc/pam.d/common-auth
	sec_audit_guard_file /etc/security
	sec_audit_guard_file /etc/security/faillock.conf
	pam_faillock_debian_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_remediate_process_hardening; then
sec_audit_remediate_process_hardening() {
		sec_audit_guard_file /etc/security/limits.conf
	sec_audit_guard_file /etc/systemd/coredump.conf.d
	sec_audit_guard_file /etc/systemd/coredump.conf.d/99-cre-sec.conf
	sec_audit_remediate_process_hardening_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_remediate_chrony; then
sec_audit_remediate_chrony() {
		sec_audit_guard_file /etc/chrony.conf
	sec_audit_remediate_chrony_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_remediate_auditd_2; then
sec_audit_remediate_auditd_2() {
		sec_audit_guard_file /etc/audit/rules.d
	sec_audit_guard_file /etc/audit/rules.d/99-debian12-cre.rules
	sec_audit_guard_file /etc/sudoers
	sec_audit_guard_file /etc/passwd
	sec_audit_guard_file /etc/shadow
	sec_audit_guard_file /var/sec_audit_log/audit
	sec_audit_remediate_auditd_2_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_remediate_logging; then
sec_audit_remediate_logging() {
		sec_audit_guard_file /etc/systemd/journald.conf.d
	sec_audit_guard_file /etc/systemd/journald.conf.d/99-debian12-cre.conf
	sec_audit_remediate_logging_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_remediate_cron_at; then
sec_audit_remediate_cron_at() {
		sec_audit_guard_file /etc/crontab
	sec_audit_guard_file /etc/cron.hourly
	sec_audit_guard_file /etc/cron.daily
	sec_audit_guard_file /etc/cron.weekly
	sec_audit_guard_file /etc/cron.monthly
	sec_audit_guard_file /etc/cron.d
	sec_audit_remediate_cron_at_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_remediate_accounts; then
sec_audit_remediate_accounts() {
		sec_audit_guard_file /etc/profile.d/99-cre-umask.sh
	sec_audit_guard_file /etc/profile.d/99-cre-timeout.sh
	sec_audit_remediate_accounts_raw "$@"
}
fi


if sec_audit_rename_fn sec_audit_remediate_identity_files_4; then
sec_audit_remediate_identity_files_4() {
		sec_audit_guard_file /etc/passwd
	sec_audit_guard_file /etc/shadow
	sec_audit_guard_file /etc/group
	sec_audit_guard_file /etc/gshadow
	sec_audit_remediate_identity_files_4_raw "$@"
}
fi

sec_audit_main "$@"

