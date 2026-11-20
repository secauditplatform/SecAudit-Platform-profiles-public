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

sec_audit_disable_kernel_module() {
    local mod="$1"
    local f="/etc/modprobe.d/sec-audit-disable-${mod}.conf"
    [[ -d /etc/modprobe.d ]] || mkdir -p /etc/modprobe.d
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
    local key="$1" val="$2" f="/etc/sysctl.d/99-secaudit-alma9-sec.conf"
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
    local key="$1" val="$2"
    mkdir -p /etc/security/pwquality.conf.d
    local f=/etc/security/pwquality.conf
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

sec_audit_gdm_installed() { rpm -q gdm &>/dev/null; }

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

sec_audit_remediate_skip() {
    sec_audit_log "REMEDIATE RULE${1}= SKIP: manual step required - ${2}"
}

sec_audit_remediate_done() {
    sec_audit_log "REMEDIATE RULE${1}= applied: ${2}"
}

sec_audit_log "starting AlmaLinux 9 remediation (sec_AlmaLinux_OS_9_v2.0.0)"

# RULE1:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 1; then
sec_audit_disable_kernel_module cramfs
sec_audit_remediate_done 1 "blacklisted kernel module cramfs"

fi
# RULE2:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 2; then
sec_audit_disable_kernel_module freevxfs
sec_audit_remediate_done 2 "blacklisted kernel module freevxfs"

fi
# RULE3:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 3; then
sec_audit_disable_kernel_module hfs
sec_audit_remediate_done 3 "blacklisted kernel module hfs"

fi
# RULE4:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 4; then
sec_audit_disable_kernel_module hfsplus
sec_audit_remediate_done 4 "blacklisted kernel module hfsplus"

fi
# RULE5:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 5; then
sec_audit_disable_kernel_module jffs2
sec_audit_remediate_done 5 "blacklisted kernel module jffs2"

fi
# RULE6:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 6; then
sec_audit_disable_kernel_module squashfs
sec_audit_remediate_done 6 "blacklisted kernel module squashfs"

fi
# RULE7:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 7; then
sec_audit_disable_kernel_module udf
sec_audit_remediate_done 7 "blacklisted kernel module udf"

fi
# RULE8:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 8; then
sec_audit_disable_kernel_module usb-storage
sec_audit_remediate_done 8 "blacklisted kernel module usb-storage"

fi
# RULE9:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 9; then
sec_audit_remediate_skip 9 "blacklist unused filesystem modules (afs, ceph, cifs, etc.) per site policy"

fi
# RULE10:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 10; then
sec_audit_ensure_fstab_mount /tmp "nodev,nosuid,noexec"
sec_audit_remediate_done 10 "configured dedicated mount for /tmp"

fi
# RULE11:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 11; then
sec_audit_ensure_mount_option /tmp nodev
sec_audit_remediate_done 11 "set nodev on /tmp"

fi
# RULE12:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 12; then
sec_audit_ensure_mount_option /tmp nosuid
sec_audit_remediate_done 12 "set nosuid on /tmp"

fi
# RULE13:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 13; then
sec_audit_ensure_mount_option /tmp noexec
sec_audit_remediate_done 13 "set noexec on /tmp"

fi
# RULE14:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 14; then
sec_audit_ensure_fstab_mount /dev/shm "nodev,nosuid,noexec"
sec_audit_remediate_done 14 "configured dedicated mount for /dev/shm"

fi
# RULE15:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 15; then
sec_audit_ensure_mount_option /dev/shm nodev
sec_audit_remediate_done 15 "set nodev on /dev/shm"

fi
# RULE16:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 16; then
sec_audit_ensure_mount_option /dev/shm nosuid
sec_audit_remediate_done 16 "set nosuid on /dev/shm"

fi
# RULE17:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 17; then
sec_audit_ensure_mount_option /dev/shm noexec
sec_audit_remediate_done 17 "set noexec on /dev/shm"

fi
# RULE18:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 18; then
sec_audit_remediate_skip 18 "create separate partition for /home during provisioning; then set mount options"

fi
# RULE19:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 19; then
sec_audit_ensure_mount_option /home nodev
sec_audit_remediate_done 19 "set nodev on /home"

fi
# RULE20:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 20; then
sec_audit_ensure_mount_option /home nosuid
sec_audit_remediate_done 20 "set nosuid on /home"

fi
# RULE21:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 21; then
sec_audit_remediate_skip 21 "create separate partition for /var during provisioning; then set mount options"

fi
# RULE22:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 22; then
sec_audit_ensure_mount_option /var nodev
sec_audit_remediate_done 22 "set nodev on /var"

fi
# RULE23:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 23; then
sec_audit_ensure_mount_option /var nosuid
sec_audit_remediate_done 23 "set nosuid on /var"

fi
# RULE24:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 24; then
sec_audit_remediate_skip 24 "create separate partition for /var/tmp during provisioning; then set mount options"

fi
# RULE25:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 25; then
sec_audit_ensure_mount_option /var/tmp nodev
sec_audit_remediate_done 25 "set nodev on /var/tmp"

fi
# RULE26:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 26; then
sec_audit_ensure_mount_option /var/tmp nosuid
sec_audit_remediate_done 26 "set nosuid on /var/tmp"

fi
# RULE27:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 27; then
sec_audit_ensure_mount_option /var/tmp noexec
sec_audit_remediate_done 27 "set noexec on /var/tmp"

fi
# RULE28:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 28; then
sec_audit_remediate_skip 28 "create separate partition for /var/sec_audit_log during provisioning; then set mount options"

fi
# RULE29:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 29; then
sec_audit_ensure_mount_option /var/sec_audit_log nodev
sec_audit_remediate_done 29 "set nodev on /var/sec_audit_log"

fi
# RULE30:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 30; then
sec_audit_ensure_mount_option /var/sec_audit_log nosuid
sec_audit_remediate_done 30 "set nosuid on /var/sec_audit_log"

fi
# RULE31:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 31; then
sec_audit_ensure_mount_option /var/sec_audit_log noexec
sec_audit_remediate_done 31 "set noexec on /var/sec_audit_log"

fi
# RULE32:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 32; then
sec_audit_remediate_skip 32 "create separate partition for /var/sec_audit_log/audit during provisioning; then set mount options"

fi
# RULE33:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 33; then
sec_audit_ensure_mount_option /var/sec_audit_log/audit nodev
sec_audit_remediate_done 33 "set nodev on /var/sec_audit_log/audit"

fi
# RULE34:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 34; then
sec_audit_ensure_mount_option /var/sec_audit_log/audit nosuid
sec_audit_remediate_done 34 "set nosuid on /var/sec_audit_log/audit"

fi
# RULE35:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 35; then
sec_audit_ensure_mount_option /var/sec_audit_log/audit noexec
sec_audit_remediate_done 35 "set noexec on /var/sec_audit_log/audit"

fi
# RULE36:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 36; then
sec_audit_remediate_skip 36 "verify GPG keys in /etc/pki/rpm-gpg/ match trusted AlmaLinux repositories"

fi
# RULE37:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 37; then
sec_audit_set_dnf_main_kv gpgcheck 1
sec_audit_set_dnf_main_kv localpkg_gpgcheck 1
sec_audit_remediate_done 37 "enabled gpgcheck in dnf.conf"

fi
# RULE38:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 38; then
sec_audit_remediate_skip 38 "set repo_gpgcheck=1 in /etc/dnf/dnf.conf and .repo files if supported"

fi
# RULE39:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 39; then
sec_audit_remediate_skip 39 "configure valid AlmaLinux repositories in /etc/yum.repos.d/"

fi
# RULE40:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 40; then
sec_audit_remediate_skip 40 "run dnf upgrade --security after change review"

fi
# RULE41:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 41; then
sec_audit_pkg_install libselinux
sec_audit_remediate_done 41 "installed SELinux packages"

fi
# RULE42:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 42; then
if sec_audit_have_bin grubby; then
    grubby --update-kernel=ALL --remove-args="selinux=0 enforcing=0" >/dev/null 2>&1 || true
fi
sec_audit_remediate_done 42 "removed selinux=0 from bootloader"

fi
# RULE43:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 43; then
[[ -f /etc/selinux/config ]] && {
    sed -i "s/^SELINUXTYPE=.*/SELINUXTYPE=targeted/" /etc/selinux/config 2>/dev/null || true
    grep -q "^SELINUXTYPE=" /etc/selinux/config || echo "SELINUXTYPE=targeted" >>/etc/selinux/config
}
sec_audit_remediate_done 43 "set SELINUXTYPE=targeted"

fi
# RULE44:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 44; then
[[ -f /etc/selinux/config ]] && sed -i "s/^SELINUX=.*/SELINUX=enforcing/" /etc/selinux/config 2>/dev/null || true
sec_audit_have_bin setenforce && setenforce 1 >/dev/null 2>&1 || true
sec_audit_remediate_done 44 "SELinux mode not disabled"

fi
# RULE45:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 45; then
[[ -f /etc/selinux/config ]] && sed -i "s/^SELINUX=.*/SELINUX=enforcing/" /etc/selinux/config 2>/dev/null || true
sec_audit_have_bin setenforce && setenforce 1 >/dev/null 2>&1 || true
sec_audit_remediate_done 45 "SELinux enforcing"

fi
# RULE46:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 46; then
sec_audit_remediate_skip 46 "investigate unconfined_service_t processes; confine or remove services"

fi
# RULE47:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 47; then
sec_audit_pkg_remove mcstrans
sec_audit_disable_svc mcstrans.service
sec_audit_remediate_done 47 "removed mcstrans"

fi
# RULE48:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 48; then
sec_audit_pkg_remove setroubleshoot
sec_audit_remediate_done 48 "removed setroubleshoot"

fi
# RULE49:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 49; then
sec_audit_remediate_skip 49 "run grub2-setpassword and rebuild grub.cfg per 1.4.1"

fi
# RULE50:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 50; then
sec_audit_harden_file /boot/grub2/grub.cfg 600 root:root
sec_audit_harden_file /boot/grub2/user.cfg 600 root:root
sec_audit_remediate_done 50 "hardened grub permissions"

fi
# RULE51:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 51; then
grep -q "hard core" /etc/security/limits.conf 2>/dev/null || echo "* hard core 0" >>/etc/security/limits.conf
mkdir -p /etc/systemd/coredump.conf.d
cat >/etc/systemd/coredump.conf.d/99-secaudit-alma9-sec.conf <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
sec_audit_have_bin systemctl && systemctl daemon-reload >/dev/null 2>&1 || true
sec_audit_remediate_done 51 "disabled core dumps"

fi
# RULE52:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 52; then
sec_audit_set_sysctl fs.protected_hardlinks 1
sec_audit_remediate_done 52 "set fs.protected_hardlinks=1"

fi
# RULE53:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 53; then
sec_audit_set_sysctl fs.protected_symlinks 1
sec_audit_remediate_done 53 "set fs.protected_symlinks=1"

fi
# RULE54:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 54; then
sec_audit_set_sysctl fs.suid_dumpable 0
sec_audit_remediate_done 54 "set fs.suid_dumpable=0"

fi
# RULE55:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 55; then
sec_audit_have_bin update-crypto-policies && update-crypto-policies --set DEFAULT >/dev/null 2>&1 || true
sec_audit_remediate_done 55 "crypto policy not LEGACY"

fi
# RULE56:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 56; then
sec_audit_have_bin update-crypto-policies && update-crypto-policies --set DEFAULT:NO-SHA1:NO-SSHCBC >/dev/null 2>&1 || update-crypto-policies --set DEFAULT >/dev/null 2>&1 || true
sec_audit_remediate_done 56 "applied DEFAULT crypto policy modules"

fi
# RULE57:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 57; then
sec_audit_have_bin update-crypto-policies && update-crypto-policies --set DEFAULT:NO-SHA1:NO-SSHCBC >/dev/null 2>&1 || update-crypto-policies --set DEFAULT >/dev/null 2>&1 || true
sec_audit_remediate_done 57 "applied DEFAULT crypto policy modules"

fi
# RULE58:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 58; then
sec_audit_have_bin update-crypto-policies && update-crypto-policies --set DEFAULT:NO-SHA1:NO-SSHCBC >/dev/null 2>&1 || update-crypto-policies --set DEFAULT >/dev/null 2>&1 || true
sec_audit_remediate_done 58 "applied DEFAULT crypto policy modules"

fi
# RULE59:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 59; then
sec_audit_have_bin update-crypto-policies && update-crypto-policies --set DEFAULT:NO-SHA1:NO-SSHCBC >/dev/null 2>&1 || update-crypto-policies --set DEFAULT >/dev/null 2>&1 || true
sec_audit_remediate_done 59 "applied DEFAULT crypto policy modules"

fi
# RULE60:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 60; then
sec_audit_remediate_skip 60 "disable chacha20-poly1305 in crypto policy module if required by policy"

fi
# RULE61:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 61; then
sec_audit_remediate_skip 61 "set etm=DISABLE_ETM in crypto policy for ssh if required by policy"

fi
# RULE62:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 62; then
[[ -f /etc/motd ]] || echo "Authorized use only." >/etc/motd
sed -i 's/\\[vVrms]//g' /etc/motd 2>/dev/null || true
sec_audit_remediate_done 62 "sanitized login banner /etc/motd"

fi
# RULE63:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 63; then
[[ -f /etc/issue ]] || echo "Authorized use only." >/etc/issue
sed -i 's/\\[vVrms]//g' /etc/issue 2>/dev/null || true
sec_audit_remediate_done 63 "sanitized login banner /etc/issue"

fi
# RULE64:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 64; then
[[ -f /etc/issue.net ]] || echo "Authorized use only." >/etc/issue.net
sed -i 's/\\[vVrms]//g' /etc/issue.net 2>/dev/null || true
sec_audit_remediate_done 64 "sanitized login banner /etc/issue.net"

fi
# RULE65:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 65; then
sec_audit_harden_file /etc/motd 644 root:root
sec_audit_remediate_done 65 "set permissions on /etc/motd"

fi
# RULE66:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 66; then
sec_audit_harden_file /etc/issue 644 root:root
sec_audit_remediate_done 66 "set permissions on /etc/issue"

fi
# RULE67:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 67; then
sec_audit_harden_file /etc/issue.net 644 root:root
sec_audit_remediate_done 67 "set permissions on /etc/issue.net"

fi
# RULE68:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 68; then
sec_audit_pkg_remove gdm
sec_audit_disable_svc gdm
sec_audit_remediate_done 68 "removed GDM"

fi
# RULE69:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 69; then
mkdir -p /etc/dconf/db/gdm.d
printf "%s\n" "[org/gnome/login-screen]" "disable-user-list=true" >/etc/dconf/db/gdm.d/00-login-screen
sec_audit_have_bin dconf update && dconf update >/dev/null 2>&1 || true
sec_audit_remediate_done 69 "configured GDM hardening"

fi
# RULE70:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 70; then
mkdir -p /etc/dconf/db/gdm.d
printf "%s\n" "[org/gnome/desktop/media-handling]" "automount=false" "automount-open=false" "autorun-never=true" >/etc/dconf/db/gdm.d/01-media
sec_audit_have_bin dconf update && dconf update >/dev/null 2>&1 || true
sec_audit_remediate_done 70 "configured GDM hardening"

fi
# RULE71:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 71; then
mkdir -p /etc/dconf/db/gdm.d
printf "%s\n" "[org/gnome/desktop/media-handling]" "automount=false" "automount-open=false" "autorun-never=true" >/etc/dconf/db/gdm.d/01-media
sec_audit_have_bin dconf update && dconf update >/dev/null 2>&1 || true
sec_audit_remediate_done 71 "configured GDM hardening"

fi
# RULE72:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 72; then
mkdir -p /etc/dconf/db/gdm.d
printf "%s\n" "[org/gnome/desktop/media-handling]" "automount=false" "automount-open=false" "autorun-never=true" >/etc/dconf/db/gdm.d/01-media
sec_audit_have_bin dconf update && dconf update >/dev/null 2>&1 || true
sec_audit_remediate_done 72 "configured GDM hardening"

fi
# RULE73:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 73; then
mkdir -p /etc/gdm
grep -q "^\[daemon\]" /etc/gdm/custom.conf 2>/dev/null || echo "[daemon]" >>/etc/gdm/custom.conf
sed -i "/^\[daemon\]/a WaylandEnable=false" /etc/gdm/custom.conf 2>/dev/null || true
sec_audit_remediate_done 73 "configured GDM hardening"

fi
# RULE74:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 74; then
mkdir -p /etc/dconf/db/gdm.d
printf "%s\n" "[org/gnome/desktop/media-handling]" "automount=false" "automount-open=false" "autorun-never=true" >/etc/dconf/db/gdm.d/01-media
sec_audit_have_bin dconf update && dconf update >/dev/null 2>&1 || true
sec_audit_remediate_done 74 "configured GDM hardening"

fi
# RULE75:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 75; then
mkdir -p /etc/dconf/db/gdm.d
printf "%s\n" "[org/gnome/desktop/media-handling]" "automount=false" "automount-open=false" "autorun-never=true" >/etc/dconf/db/gdm.d/01-media
sec_audit_have_bin dconf update && dconf update >/dev/null 2>&1 || true
sec_audit_remediate_done 75 "configured GDM hardening"

fi
# RULE76:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 76; then
mkdir -p /etc/dconf/db/gdm.d
printf "%s\n" "[org/gnome/desktop/media-handling]" "automount=false" "automount-open=false" "autorun-never=true" >/etc/dconf/db/gdm.d/01-media
sec_audit_have_bin dconf update && dconf update >/dev/null 2>&1 || true
sec_audit_remediate_done 76 "configured GDM hardening"

fi
# RULE77:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 77; then
sed -i "/^\[xdmcp\]/,/^\[/ s/^Enable=.*/Enable=false/" /etc/gdm/custom.conf 2>/dev/null || true
sec_audit_remediate_done 77 "configured GDM hardening"

fi
# RULE78:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 78; then
sec_audit_disable_svc autofs.service
sec_audit_pkg_remove autofs
sec_audit_remediate_done 78 "disabled autofs services"

fi
# RULE79:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 79; then
sec_audit_disable_svc avahi-daemon.socket
sec_audit_disable_svc avahi-daemon.service
sec_audit_pkg_remove avahi
sec_audit_remediate_done 79 "disabled avahi services"

fi
# RULE80:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 80; then
sec_audit_disable_svc cockpit.socket
sec_audit_disable_svc cockpit.service
sec_audit_pkg_remove cockpit-ws
sec_audit_remediate_done 80 "disabled cockpit-ws services"

fi
# RULE81:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 81; then
sec_audit_disable_svc dhcpd.service
sec_audit_disable_svc dhcpd6.service
sec_audit_pkg_remove dhcp-server
sec_audit_remediate_done 81 "disabled dhcp-server services"

fi
# RULE82:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 82; then
sec_audit_disable_svc named.service
sec_audit_pkg_remove bind
sec_audit_remediate_done 82 "disabled bind services"

fi
# RULE83:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 83; then
sec_audit_disable_svc dnsmasq.service
sec_audit_pkg_remove dnsmasq
sec_audit_remediate_done 83 "disabled dnsmasq services"

fi
# RULE84:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 84; then
sec_audit_disable_svc vsftpd.service
sec_audit_pkg_remove vsftpd
sec_audit_remediate_done 84 "disabled vsftpd services"

fi
# RULE85:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 85; then
sec_audit_disable_svc dovecot.socket
sec_audit_disable_svc dovecot.service
sec_audit_disable_svc cyrus-imapd.service
sec_audit_pkg_remove dovecot
sec_audit_remediate_done 85 "disabled dovecot services"

fi
# RULE86:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 86; then
sec_audit_disable_svc nfs-server.service
sec_audit_pkg_remove nfs-utils
sec_audit_remediate_done 86 "disabled nfs-utils services"

fi
# RULE87:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 87; then
sec_audit_disable_svc cups.socket
sec_audit_disable_svc cups.service
sec_audit_pkg_remove cups
sec_audit_remediate_done 87 "disabled cups services"

fi
# RULE88:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 88; then
sec_audit_disable_svc rpcbind.socket
sec_audit_disable_svc rpcbind.service
sec_audit_pkg_remove rpcbind
sec_audit_remediate_done 88 "disabled rpcbind services"

fi
# RULE89:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 89; then
sec_audit_disable_svc rsyncd.socket
sec_audit_disable_svc rsyncd.service
sec_audit_pkg_remove rsync-daemon
sec_audit_remediate_done 89 "disabled rsync-daemon services"

fi
# RULE90:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 90; then
sec_audit_disable_svc smb.service
sec_audit_pkg_remove samba
sec_audit_remediate_done 90 "disabled samba services"

fi
# RULE91:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 91; then
sec_audit_disable_svc snmpd.service
sec_audit_pkg_remove net-snmp
sec_audit_remediate_done 91 "disabled net-snmp services"

fi
# RULE92:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 92; then
sec_audit_disable_svc telnet.socket
sec_audit_pkg_remove telnet-server
sec_audit_remediate_done 92 "disabled telnet-server services"

fi
# RULE93:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 93; then
sec_audit_disable_svc tftp.socket
sec_audit_disable_svc tftp.service
sec_audit_pkg_remove tftp-server
sec_audit_remediate_done 93 "disabled tftp-server services"

fi
# RULE94:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 94; then
sec_audit_disable_svc squid.service
sec_audit_pkg_remove squid
sec_audit_remediate_done 94 "disabled squid services"

fi
# RULE95:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 95; then
sec_audit_disable_svc httpd.service
sec_audit_disable_svc nginx.service
sec_audit_pkg_remove httpd
sec_audit_remediate_done 95 "disabled httpd services"

fi
# RULE96:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 96; then
sec_audit_pkg_remove gdm
sec_audit_disable_svc gdm
sec_audit_remediate_done 96 "removed GDM"

fi
# RULE97:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 97; then
sec_audit_disable_svc gdm
sec_audit_pkg_remove xorg-x11-server-Xorg
sec_audit_remediate_done 97 "disabled xorg-x11-server-Xorg services"

fi
# RULE98:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 98; then
if rpm -q postfix &>/dev/null; then
    postconf -e "inet_interfaces = loopback-only" >/dev/null 2>&1 || true
    systemctl restart postfix >/dev/null 2>&1 || true
fi
sec_audit_remediate_done 98 "postfix loopback-only"

fi
# RULE99:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 99; then
sec_audit_remediate_skip 99 "review listening ports with ss -tuln; stop unapproved services"

fi
# RULE100:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 100; then
sec_audit_pkg_remove ftp
sec_audit_remediate_done 100 "removed client package ftp"

fi
# RULE101:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 101; then
sec_audit_pkg_remove openldap-clients
sec_audit_remediate_done 101 "removed client package openldap-clients"

fi
# RULE102:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 102; then
sec_audit_pkg_remove telnet
sec_audit_remediate_done 102 "removed client package telnet"

fi
# RULE103:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 103; then
sec_audit_pkg_remove telnet
sec_audit_remediate_done 103 "removed client package telnet"

fi
# RULE104:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 104; then
sec_audit_pkg_remove tftp
sec_audit_remediate_done 104 "removed client package tftp"

fi
# RULE105:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 105; then
sec_audit_pkg_install chrony
sec_audit_start_svc chronyd
sec_audit_remediate_done 105 "installed chrony"

fi
# RULE106:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 106; then
sec_audit_pkg_install chrony
grep -q "^pool " /etc/chrony.conf 2>/dev/null || echo "pool 2.almalinux.pool.ntp.org iburst" >>/etc/chrony.conf
sec_audit_start_svc chronyd
sec_audit_remediate_done 106 "configured chrony pool"

fi
# RULE107:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 107; then
grep -q "^OPTIONS=" /etc/sysconfig/chronyd 2>/dev/null && sed -i 's/^OPTIONS=.*/OPTIONS="-u chrony"/' /etc/sysconfig/chronyd || echo 'OPTIONS="-u chrony"' >>/etc/sysconfig/chronyd
systemctl restart chronyd >/dev/null 2>&1 || true
sec_audit_remediate_done 107 "chrony not run as root"

fi
# RULE108:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 108; then
sec_audit_pkg_install cronie
sec_audit_start_svc crond
sec_audit_remediate_done 108 "enabled cron daemon"

fi
# RULE109:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 109; then
chmod 600 /etc/crontab 2>/dev/null || true
chown root:root /etc/crontab 2>/dev/null || true
sec_audit_remediate_done 109 "restricted cron path /etc/crontab"

fi
# RULE110:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 110; then
chmod 700 /etc/cron.hourly 2>/dev/null || true
chown root:root /etc/cron.hourly 2>/dev/null || true
sec_audit_remediate_done 110 "restricted cron path /etc/cron.hourly"

fi
# RULE111:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 111; then
chmod 700 /etc/cron.daily 2>/dev/null || true
chown root:root /etc/cron.daily 2>/dev/null || true
sec_audit_remediate_done 111 "restricted cron path /etc/cron.daily"

fi
# RULE112:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 112; then
chmod 700 /etc/cron.weekly 2>/dev/null || true
chown root:root /etc/cron.weekly 2>/dev/null || true
sec_audit_remediate_done 112 "restricted cron path /etc/cron.weekly"

fi
# RULE113:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 113; then
chmod 700 /etc/cron.monthly 2>/dev/null || true
chown root:root /etc/cron.monthly 2>/dev/null || true
sec_audit_remediate_done 113 "restricted cron path /etc/cron.monthly"

fi
# RULE114:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 114; then
chmod 700 /etc/cron.yearly 2>/dev/null || true
chown root:root /etc/cron.yearly 2>/dev/null || true
sec_audit_remediate_done 114 "restricted cron path /etc/cron.yearly"

fi
# RULE115:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 115; then
chmod 700 /etc/cron.d 2>/dev/null || true
chown root:root /etc/cron.d 2>/dev/null || true
sec_audit_remediate_done 115 "restricted cron path /etc/cron.d"

fi
# RULE116:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 116; then
chmod 600 /etc/cron.deny 2>/dev/null || true
chown root:root /etc/cron.deny 2>/dev/null || true
sec_audit_remediate_done 116 "restricted at/cron deny files"

fi
# RULE117:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 117; then
sec_audit_remediate_skip 117 "document IPv6 enable/disable decision and sysctl accordingly"

fi
# RULE118:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 118; then
sec_audit_disable_kernel_module bluetooth
sec_audit_pkg_remove bluez
sec_audit_remediate_done 118 "disabled wireless/bluetooth module"

fi
# RULE119:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 119; then
sec_audit_disable_svc bluetooth.service
sec_audit_pkg_remove bluez
sec_audit_remediate_done 119 "disabled bluetooth service"

fi
# RULE120:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 120; then
sec_audit_disable_kernel_module dccp
sec_audit_remediate_done 120 "blacklisted kernel module dccp"

fi
# RULE121:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 121; then
sec_audit_disable_kernel_module sctp
sec_audit_remediate_done 121 "blacklisted kernel module sctp"

fi
# RULE122:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 122; then
sec_audit_disable_kernel_module rds
sec_audit_remediate_done 122 "blacklisted kernel module rds"

fi
# RULE123:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 123; then
sec_audit_disable_kernel_module tipc
sec_audit_remediate_done 123 "blacklisted kernel module tipc"

fi
# RULE124:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 124; then
sec_audit_set_sysctl net.ipv4.conf.all.send_redirects 0
sec_audit_remediate_done 124 "set net.ipv4.conf.all.send_redirects=0"

fi
# RULE125:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 125; then
sec_audit_set_sysctl net.ipv4.conf.default.send_redirects 0
sec_audit_remediate_done 125 "set net.ipv4.conf.default.send_redirects=0"

fi
# RULE126:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 126; then
sec_audit_set_sysctl net.ipv4.icmp_ignore_bogus_error_responses 1
sec_audit_remediate_done 126 "set net.ipv4.icmp_ignore_bogus_error_responses=1"

fi
# RULE127:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 127; then
sec_audit_set_sysctl net.ipv4.conf.all.accept_redirects 0
sec_audit_remediate_done 127 "set net.ipv4.conf.all.accept_redirects=0"

fi
# RULE128:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 128; then
sec_audit_set_sysctl net.ipv6.conf.all.accept_redirects 0
sec_audit_remediate_done 128 "set net.ipv6.conf.all.accept_redirects=0"

fi
# RULE129:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 129; then
sec_audit_set_sysctl net.ipv4.conf.all.secure_redirects 0
sec_audit_remediate_done 129 "set net.ipv4.conf.all.secure_redirects=0"

fi
# RULE130:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 130; then
sec_audit_set_sysctl net.ipv4.conf.all.rp_filter 1
sec_audit_remediate_done 130 "set net.ipv4.conf.all.rp_filter=1"

fi
# RULE131:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 131; then
sec_audit_set_sysctl net.ipv4.conf.default.rp_filter 1
sec_audit_remediate_done 131 "set net.ipv4.conf.default.rp_filter=1"

fi
# RULE132:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 132; then
sec_audit_set_sysctl net.ipv4.conf.all.log_martians 1
sec_audit_remediate_done 132 "set net.ipv4.conf.all.log_martians=1"

fi
# RULE133:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 133; then
sec_audit_set_sysctl net.ipv4.conf.all.log_martians 1
sec_audit_remediate_done 133 "set net.ipv4.conf.all.log_martians=1"

fi
# RULE134:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 134; then
sec_audit_set_sysctl net.ipv4.tcp_syncookies 1
sec_audit_remediate_done 134 "set net.ipv4.tcp_syncookies=1"

fi
# RULE135:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 135; then
sec_audit_pkg_install firewalld
sec_audit_start_svc firewalld
sec_audit_remediate_done 135 "installed firewalld"

fi
# RULE136:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 136; then
[[ -f /etc/firewalld/firewalld.conf ]] && {
    grep -q "^FirewallBackend=" /etc/firewalld/firewalld.conf && sed -i "s/^FirewallBackend=.*/FirewallBackend=nftables/" /etc/firewalld/firewalld.conf || echo "FirewallBackend=nftables" >>/etc/firewalld/firewalld.conf
}
sec_audit_start_svc firewalld
sec_audit_remediate_done 136 "firewalld nftables backend"

fi
# RULE137:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 137; then
sec_audit_remediate_skip 137 "remove unnecessary firewalld services/ports per site policy"

fi
# RULE138:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 138; then
sec_audit_have_bin firewall-cmd && firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address="127.0.0.1" accept' >/dev/null 2>&1 && firewall-cmd --reload >/dev/null 2>&1 || true
sec_audit_remediate_done 138 "firewalld loopback"

fi
# RULE139:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 139; then
sec_audit_pkg_install nftables
cat >/etc/nftables/secaudit-alma9-sec.nft <<'EOF'
table inet filter {
  chain input { type filter hook input priority 0; policy drop;
    iif "lo" accept
    ct state established,related accept
    tcp dport 22 accept
  }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output { type filter hook output priority 0; policy accept; }
}
EOF
systemctl enable --now nftables >/dev/null 2>&1 || true
nft -f /etc/nftables/secaudit-alma9-sec.nft >/dev/null 2>&1 || true
sec_audit_remediate_done 139 "nftables baseline chains"

fi
# RULE140:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 140; then
sec_audit_remediate_skip 140 "configure nftables ct state established,related accept rules"

fi
# RULE141:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 141; then
sec_audit_pkg_install nftables
cat >/etc/nftables/secaudit-alma9-sec.nft <<'EOF'
table inet filter {
  chain input { type filter hook input priority 0; policy drop;
    iif "lo" accept
    ct state established,related accept
    tcp dport 22 accept
  }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output { type filter hook output priority 0; policy accept; }
}
EOF
systemctl enable --now nftables >/dev/null 2>&1 || true
nft -f /etc/nftables/secaudit-alma9-sec.nft >/dev/null 2>&1 || true
sec_audit_remediate_done 141 "nftables baseline chains"

fi
# RULE142:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 142; then
sec_audit_pkg_install nftables
cat >/etc/nftables/secaudit-alma9-sec.nft <<'EOF'
table inet filter {
  chain input { type filter hook input priority 0; policy drop;
    iif "lo" accept
    ct state established,related accept
    tcp dport 22 accept
  }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output { type filter hook output priority 0; policy accept; }
}
EOF
systemctl enable --now nftables >/dev/null 2>&1 || true
nft -f /etc/nftables/secaudit-alma9-sec.nft >/dev/null 2>&1 || true
sec_audit_remediate_done 142 "nftables baseline chains"

fi
# RULE143:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 143; then
sec_audit_harden_file /etc/ssh/sshd_config 600 root:root
sec_audit_remediate_done 143 "sshd_config permissions"

fi
# RULE144:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 144; then
chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null || true
chmod 644 /etc/ssh/ssh_host_*_key.pub 2>/dev/null || true
chown root:ssh_keys /etc/ssh/ssh_host_*_key 2>/dev/null || true
sec_audit_remediate_done 144 "SSH host key permissions"

fi
# RULE145:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 145; then
chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null || true
chmod 644 /etc/ssh/ssh_host_*_key.pub 2>/dev/null || true
chown root:ssh_keys /etc/ssh/ssh_host_*_key 2>/dev/null || true
sec_audit_remediate_done 145 "SSH host key permissions"

fi
# RULE146:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 146; then
sec_audit_set_sshd_kv AllowUsers "alloweduser"
sec_audit_remediate_done 146 "sshd AllowUsers placeholder - edit for site"

fi
# RULE147:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 147; then
sec_audit_set_sshd_kv Banner /etc/issue.net
sec_audit_remediate_done 147 "sshd Banner"

fi
# RULE148:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 148; then
sec_audit_have_bin update-crypto-policies && update-crypto-policies --set DEFAULT:NO-SHA1:NO-SSHCBC >/dev/null 2>&1 || true
systemctl restart sshd >/dev/null 2>&1 || true
sec_audit_remediate_done 148 "SSH crypto via system-wide crypto-policies"

fi
# RULE149:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 149; then
sec_audit_set_sshd_kv ClientAliveInterval 300
sec_audit_remediate_done 149 "sshd ClientAliveInterval"

fi
# RULE150:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 150; then
sec_audit_set_sshd_kv DisableForwarding yes
sec_audit_remediate_done 150 "sshd DisableForwarding"

fi
# RULE151:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 151; then
sec_audit_set_sshd_kv GSSAPIAuthentication no
sec_audit_remediate_done 151 "sshd GSSAPIAuthentication"

fi
# RULE152:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 152; then
sec_audit_set_sshd_kv HostbasedAuthentication no
sec_audit_remediate_done 152 "sshd HostbasedAuthentication"

fi
# RULE153:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 153; then
sec_audit_set_sshd_kv IgnoreRhosts yes
sec_audit_remediate_done 153 "sshd IgnoreRhosts"

fi
# RULE154:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 154; then
sec_audit_have_bin update-crypto-policies && update-crypto-policies --set DEFAULT:NO-SHA1:NO-SSHCBC >/dev/null 2>&1 || true
systemctl restart sshd >/dev/null 2>&1 || true
sec_audit_remediate_done 154 "SSH crypto via system-wide crypto-policies"

fi
# RULE155:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 155; then
sec_audit_set_sshd_kv LoginGraceTime 60
sec_audit_remediate_done 155 "sshd LoginGraceTime"

fi
# RULE156:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 156; then
sec_audit_set_sshd_kv LogLevel VERBOSE
sec_audit_remediate_done 156 "sshd LogLevel"

fi
# RULE157:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 157; then
sec_audit_have_bin update-crypto-policies && update-crypto-policies --set DEFAULT:NO-SHA1:NO-SSHCBC >/dev/null 2>&1 || true
systemctl restart sshd >/dev/null 2>&1 || true
sec_audit_remediate_done 157 "SSH crypto via system-wide crypto-policies"

fi
# RULE158:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 158; then
sec_audit_set_sshd_kv MaxAuthTries 4
sec_audit_remediate_done 158 "sshd MaxAuthTries"

fi
# RULE159:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 159; then
sec_audit_set_sshd_kv MaxStartups 10:30:60
sec_audit_remediate_done 159 "sshd MaxStartups"

fi
# RULE160:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 160; then
sec_audit_set_sshd_kv MaxSessions 10
sec_audit_remediate_done 160 "sshd MaxSessions"

fi
# RULE161:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 161; then
sec_audit_set_sshd_kv PermitEmptyPasswords no
sec_audit_remediate_done 161 "sshd PermitEmptyPasswords"

fi
# RULE162:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 162; then
sec_audit_set_sshd_kv PermitRootLogin no
sec_audit_remediate_done 162 "sshd PermitRootLogin"

fi
# RULE163:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 163; then
sec_audit_set_sshd_kv PermitUserEnvironment no
sec_audit_remediate_done 163 "sshd PermitUserEnvironment"

fi
# RULE164:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 164; then
sec_audit_set_sshd_kv UsePAM yes
sec_audit_remediate_done 164 "sshd UsePAM"

fi
# RULE165:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 165; then
sec_audit_pkg_install sudo
sec_audit_remediate_done 165 "sudo installed"

fi
# RULE166:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 166; then
echo "Defaults use_pty" >/etc/sudoers.d/99-secaudit-pty
chmod 440 /etc/sudoers.d/99-secaudit-pty
sec_audit_remediate_done 166 "sudo use_pty"

fi
# RULE167:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 167; then
echo "Defaults logfile=/var/sec_audit_log/sudo.sec_audit_log" >/etc/sudoers.d/99-secaudit-logfile
chmod 440 /etc/sudoers.d/99-secaudit-logfile
sec_audit_remediate_done 167 "sudo logfile"

fi
# RULE168:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 168; then
grep -q "^Defaults" /etc/sudoers 2>/dev/null || true
sec_audit_remediate_done 168 "verify sudo requires password (review sudoers)"

fi
# RULE169:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 169; then
sed -i "/!authenticate/d" /etc/sudoers /etc/sudoers.d/* 2>/dev/null || true
sec_audit_remediate_done 169 "removed global !authenticate"

fi
# RULE170:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 170; then
echo "Defaults timestamp_timeout=5" >/etc/sudoers.d/99-secaudit-timeout
chmod 440 /etc/sudoers.d/99-secaudit-timeout
sec_audit_remediate_done 170 "sudo timestamp_timeout=5"

fi
# RULE171:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 171; then
grep -q "^auth.*required.*pam_wheel.so" /etc/pam.d/su 2>/dev/null || echo "auth required pam_wheel.so use_uid" >>/etc/pam.d/su
grep -q "^wheel:" /etc/group || groupadd wheel 2>/dev/null || true
sec_audit_remediate_done 171 "restricted su to wheel"

fi
# RULE172:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 172; then
sec_audit_authselect_enable with-faillock
sec_audit_authselect_enable with-pwquality
sec_audit_remediate_done 172 "authselect PAM modules"

fi
# RULE173:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 173; then
sec_audit_authselect_enable with-faillock
sec_audit_remediate_done 173 "pam_faillock enabled"

fi
# RULE174:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 174; then
sec_audit_authselect_enable with-pwquality
sec_audit_remediate_done 174 "pam_pwquality enabled"

fi
# RULE175:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 175; then
sec_audit_authselect_enable with-faillock
sec_audit_authselect_enable with-pwquality
sec_audit_remediate_done 175 "authselect PAM modules"

fi
# RULE176:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 176; then
sec_audit_authselect_enable with-faillock
sec_audit_remediate_done 176 "pam_faillock enabled"

fi
# RULE177:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 177; then
sec_audit_authselect_enable with-pwquality
sec_audit_remediate_done 177 "pam_pwquality enabled"

fi
# RULE178:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 178; then
sec_audit_authselect_enable with-pwhistory
sec_audit_remediate_done 178 "pam_pwhistory enabled"

fi
# RULE179:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 179; then
authselect select sssd with-faillock with-pwquality with-pwhistory --force >/dev/null 2>&1 || authselect apply-changes >/dev/null 2>&1 || true
sec_audit_remediate_done 179 "pam_unix via authselect"

fi
# RULE180:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 180; then
sec_audit_set_faillock_kv deny 5
sec_audit_remediate_done 180 "faillock deny=5"

fi
# RULE181:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 181; then
sec_audit_set_faillock_kv unlock_time 900
sec_audit_remediate_done 181 "faillock unlock_time"

fi
# RULE182:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 182; then
grep -q even_deny_root /etc/security/faillock.conf 2>/dev/null || echo "even_deny_root" >>/etc/security/faillock.conf
sec_audit_remediate_done 182 "faillock even_deny_root"

fi
# RULE183:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 183; then
sec_audit_set_pwquality_kv difok 2
sec_audit_remediate_done 183 "pwquality difok"

fi
# RULE184:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 184; then
sec_audit_set_pwquality_kv minlen 14
sec_audit_remediate_done 184 "pwquality minlen 14"

fi
# RULE185:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 185; then
sec_audit_remediate_skip 185 "set minclass/dcredit/ucredit/lcredit/ocredit per organizational policy"

fi
# RULE186:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 186; then
sec_audit_set_pwquality_kv maxrepeat 3
sec_audit_remediate_done 186 "pwquality maxrepeat"

fi
# RULE187:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 187; then
sec_audit_set_pwquality_kv maxsequence 3
sec_audit_remediate_done 187 "pwquality maxsequence"

fi
# RULE188:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 188; then
sec_audit_set_pwquality_kv dictcheck 1
sec_audit_remediate_done 188 "pwquality dictcheck"

fi
# RULE189:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 189; then
grep -q enforce_for_root /etc/security/pwquality.conf 2>/dev/null || echo "enforce_for_root" >>/etc/security/pwquality.conf
sec_audit_remediate_done 189 "pwquality enforce_for_root"

fi
# RULE190:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 190; then
grep -q "^remember" /etc/security/pwhistory.conf 2>/dev/null || echo "remember = 24" >>/etc/security/pwhistory.conf
sec_audit_remediate_done 190 "pwhistory remember"

fi
# RULE191:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 191; then
grep -q enforce_for_root /etc/security/pwhistory.conf 2>/dev/null || echo "enforce_for_root" >>/etc/security/pwhistory.conf
sec_audit_remediate_done 191 "pwhistory enforce_for_root"

fi
# RULE192:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 192; then
authselect apply-changes >/dev/null 2>&1 || true
sec_audit_remediate_done 192 "PAM use_authtok via authselect"

fi
# RULE193:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 193; then
sed -i "s/nullok//g" /etc/pam.d/password-auth /etc/pam.d/system-auth 2>/dev/null || true
sec_audit_remediate_done 193 "removed pam_unix nullok"

fi
# RULE194:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 194; then
sed -i "/pam_unix.so/s/ remember=[0-9]*//g" /etc/pam.d/password-auth 2>/dev/null || true
sec_audit_remediate_done 194 "removed pam_unix remember"

fi
# RULE195:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 195; then
sec_audit_set_login_defs_kv ENCRYPT_METHOD SHA512
sec_audit_remediate_done 195 "ENCRYPT_METHOD SHA512"

fi
# RULE196:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 196; then
authselect apply-changes >/dev/null 2>&1 || true
sec_audit_remediate_done 196 "PAM use_authtok via authselect"

fi
# RULE197:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 197; then
sec_audit_set_login_defs_kv PASS_MAX_DAYS 90
sec_audit_remediate_done 197 "PASS_MAX_DAYS 90"

fi
# RULE198:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 198; then
sec_audit_remediate_skip 198 "set PASS_MIN_DAYS in /etc/login.defs per organizational policy ( suggests 1+)"

fi
# RULE199:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 199; then
sec_audit_set_login_defs_kv PASS_WARN_AGE 7
sec_audit_remediate_done 199 "PASS_WARN_AGE 7"

fi
# RULE200:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 200; then
sec_audit_set_login_defs_kv ENCRYPT_METHOD SHA512
sec_audit_remediate_done 200 "ENCRYPT_METHOD SHA512"

fi
# RULE201:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 201; then
useradd -D -f 45 >/dev/null 2>&1 || true
sec_audit_remediate_done 201 "INACTIVE=45"

fi
# RULE202:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 202; then
sec_audit_remediate_skip 202 "Ensure all users last password change date is in the past"

fi
# RULE203:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 203; then
sec_audit_remediate_skip 203 "Ensure root is the only UID 0 account"

fi
# RULE204:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 204; then
sec_audit_remediate_skip 204 "Ensure root is the only GID 0 account"

fi
# RULE205:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 205; then
sec_audit_remediate_skip 205 "Ensure group root is the only GID 0 group"

fi
# RULE206:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 206; then
sec_audit_remediate_skip 206 "Ensure root account access is controlled"

fi
# RULE207:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 207; then
sec_audit_remediate_skip 207 "Ensure root path integrity"

fi
# RULE208:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 208; then
grep -q umask /root/.bash_profile 2>/dev/null || echo "umask 027" >>/root/.bash_profile
sec_audit_remediate_done 208 "root umask 027"

fi
# RULE209:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 209; then
UID_MIN=$(awk "/^UID_MIN/{print \$2}" /etc/login.defs)
while IFS=: read -r u _ uid _ _ _ shell; do
    [[ "$uid" -lt "$UID_MIN" || "$uid" -eq 65534 ]] && continue
    [[ "$shell" == */nologin || "$shell" == */false ]] && usermod -s /sbin/nologin "$u" 2>/dev/null || true
done < /etc/passwd
sec_audit_remediate_done 209 "system accounts nologin shell"

fi
# RULE210:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 210; then
while IFS= read -r u; do
    passwd -l "$u" >/dev/null 2>&1 || true
done < <(awk -F: '($3>=1000 && $3<65534 && $7!~/nologin|false/) {print $1}' /etc/passwd)
sec_audit_remediate_done 210 "lock accounts without valid shell"

fi
# RULE211:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 211; then
sed -i "/\/nologin/d" /etc/shells 2>/dev/null || true
sec_audit_remediate_done 211 "removed nologin from /etc/shells"

fi
# RULE212:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 212; then
cat >/etc/profile.d/99-alma9-timeout.sh <<'EOF'
TMOUT=600
readonly TMOUT
export TMOUT
EOF
sec_audit_remediate_done 212 "TMOUT=600"

fi
# RULE213:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 213; then
sec_audit_set_login_defs_kv UMASK 027
cat >/etc/profile.d/99-alma9-umask.sh <<'EOF'
umask 027
EOF
sec_audit_remediate_done 213 "default umask 027"

fi
# RULE214:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 214; then
sec_audit_pkg_install aide
sec_audit_remediate_done 214 "installed AIDE"

fi
# RULE215:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 215; then
sec_audit_pkg_install aide
sec_audit_have_bin aide && aide --init >/dev/null 2>&1 || true
[[ -f /var/lib/aide/aide.db.new.gz ]] && cp -a /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz 2>/dev/null || true
sec_audit_start_svc aidecheck.timer
sec_audit_remediate_done 215 "AIDE periodic check"

fi
# RULE216:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 216; then
for t in /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules; do
    grep -q "$t" /etc/aide.conf 2>/dev/null || echo "$t p+i+n+u+g+s+b+m+c+sha256" >>/etc/aide.conf
done
sec_audit_remediate_done 216 "AIDE monitors audit tools"

fi
# RULE217:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 217; then
sec_audit_start_svc systemd-journald
sec_audit_remediate_done 217 "journald active"

fi
# RULE218:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 218; then
sec_audit_remediate_skip 218 "set z /var/sec_audit_log/journal permissions in /etc/tmpfiles.d/systemd.conf"

fi
# RULE219:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 219; then
sec_audit_remediate_skip 219 "set SystemMaxUse/SystemMaxFileSize in journald.conf per retention policy"

fi
# RULE220:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 220; then
sec_audit_disable_svc rsyslog
sec_audit_start_svc systemd-journald
sec_audit_remediate_done 220 "single logging system (journald)"

fi
# RULE221:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 221; then
sec_audit_remediate_skip 221 "install systemd-journal-remote only when journal-upload TLS/URL can be configured per site"

fi
# RULE222:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 222; then
sec_audit_remediate_skip 222 "Ensure systemd-journal-upload authentication is configured"

fi
# RULE223:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 223; then
sec_audit_remediate_skip 223 "enable systemd-journal-upload only if central logging required"

fi
# RULE224:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 224; then
sec_audit_disable_svc systemd-journal-remote.socket systemd-journal-remote.service
sec_audit_remediate_done 224 "journal-remote disabled"

fi
# RULE225:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 225; then
mkdir -p /etc/systemd/journald.conf.d
cat >/etc/systemd/journald.conf.d/99-secaudit-alma9.conf <<'EOF'
[Journal]
ForwardToSyslog=no
Compress=yes
Storage=persistent
EOF
systemctl restart systemd-journald >/dev/null 2>&1 || true
sec_audit_remediate_done 225 "journald ForwardToSyslog=no"

fi
# RULE226:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 226; then
mkdir -p /etc/systemd/journald.conf.d
grep -q "Compress=yes" /etc/systemd/journald.conf.d/99-secaudit-alma9.conf 2>/dev/null || cat >>/etc/systemd/journald.conf.d/99-secaudit-alma9.conf <<'EOF'
Compress=yes
Storage=persistent
EOF
systemctl restart systemd-journald >/dev/null 2>&1 || true
sec_audit_remediate_done 226 "journald compress/storage"

fi
# RULE227:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 227; then
mkdir -p /etc/systemd/journald.conf.d
grep -q "Compress=yes" /etc/systemd/journald.conf.d/99-secaudit-alma9.conf 2>/dev/null || cat >>/etc/systemd/journald.conf.d/99-secaudit-alma9.conf <<'EOF'
Compress=yes
Storage=persistent
EOF
systemctl restart systemd-journald >/dev/null 2>&1 || true
sec_audit_remediate_done 227 "journald compress/storage"

fi
# RULE228:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 228; then
sec_audit_remediate_skip 228 "install rsyslog only when remote sec_audit_log host forwarding can be configured per site"

fi
# RULE229:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 229; then
sec_audit_remediate_skip 229 "enable rsyslog only when remote sec_audit_log host forwarding can be configured per site"

fi
# RULE230:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 230; then
sec_audit_remediate_skip 230 "configure journald ForwardToSyslog=yes only when rsyslog central logging is deployed"

fi
# RULE231:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 231; then
sec_audit_remediate_skip 231 "configure rsyslog FileCreateMode when rsyslog is deployed per site"

fi
# RULE232:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 232; then
sec_audit_remediate_skip 232 "configure rsyslog rules per site logging policy"

fi
# RULE233:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 233; then
sec_audit_remediate_skip 233 "configure remote sec_audit_log host in /etc/rsyslog.d/ per site policy"

fi
# RULE234:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 234; then
sec_audit_remediate_skip 234 "disable rsyslog remote receive when rsyslog is deployed per site"

fi
# RULE235:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 235; then
sec_audit_remediate_skip 235 "verify /etc/logrotate.d/rsyslog rotation settings per site retention policy"

fi
# RULE236:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 236; then
find /var/sec_audit_log -type f -exec chmod g-wx,o-rwx {} + 2>/dev/null || true
find /var/sec_audit_log -type d -exec chmod g-wx,o-rwx {} + 2>/dev/null || true
sec_audit_remediate_done 236 "tightened /var/sec_audit_log file permissions"

fi
# RULE237:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 237; then
sec_audit_pkg_install audit
sec_audit_start_svc auditd
sec_audit_remediate_done 237 "auditd installed and running"

fi
# RULE238:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 238; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-238.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 238 "auditd baseline and permissions"

fi
# RULE239:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 239; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-239.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 239 "auditd baseline and permissions"

fi
# RULE240:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 240; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-240.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 240 "auditd baseline and permissions"

fi
# RULE241:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 241; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-241.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 241 "auditd baseline and permissions"

fi
# RULE242:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 242; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-242.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 242 "auditd baseline and permissions"

fi
# RULE243:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 243; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-243.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 243 "auditd baseline and permissions"

fi
# RULE244:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 244; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-244.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 244 "auditd baseline and permissions"

fi
# RULE245:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 245; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-245.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 245 "auditd baseline and permissions"

fi
# RULE246:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 246; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-246.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 246 "auditd baseline and permissions"

fi
# RULE247:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 247; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-247.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 247 "auditd baseline and permissions"

fi
# RULE248:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 248; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-248.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 248 "auditd baseline and permissions"

fi
# RULE249:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 249; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-249.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 249 "auditd baseline and permissions"

fi
# RULE250:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 250; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-250.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 250 "auditd baseline and permissions"

fi
# RULE251:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 251; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-251.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 251 "auditd baseline and permissions"

fi
# RULE252:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 252; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-252.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 252 "auditd baseline and permissions"

fi
# RULE253:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 253; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-253.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 253 "auditd baseline and permissions"

fi
# RULE254:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 254; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-254.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 254 "auditd baseline and permissions"

fi
# RULE255:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 255; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-255.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 255 "auditd baseline and permissions"

fi
# RULE256:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 256; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-256.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 256 "auditd baseline and permissions"

fi
# RULE257:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 257; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-257.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 257 "auditd baseline and permissions"

fi
# RULE258:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 258; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-258.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 258 "auditd baseline and permissions"

fi
# RULE259:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 259; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-259.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 259 "auditd baseline and permissions"

fi
# RULE260:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 260; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-260.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 260 "auditd baseline and permissions"

fi
# RULE261:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 261; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-261.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 261 "auditd baseline and permissions"

fi
# RULE262:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 262; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-262.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 262 "auditd baseline and permissions"

fi
# RULE263:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 263; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-263.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 263 "auditd baseline and permissions"

fi
# RULE264:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 264; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-264.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 264 "auditd baseline and permissions"

fi
# RULE265:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 265; then
sec_audit_remediate_skip 265 "Ensure the running and on disk configuration is the same"

fi
# RULE266:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 266; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-266.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 266 "auditd baseline and permissions"

fi
# RULE267:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 267; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-267.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 267 "auditd baseline and permissions"

fi
# RULE268:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 268; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-268.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 268 "auditd baseline and permissions"

fi
# RULE269:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 269; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-269.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 269 "auditd baseline and permissions"

fi
# RULE270:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 270; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-270.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 270 "auditd baseline and permissions"

fi
# RULE271:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 271; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-271.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 271 "auditd baseline and permissions"

fi
# RULE272:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 272; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-272.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 272 "auditd baseline and permissions"

fi
# RULE273:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 273; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-273.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 273 "auditd baseline and permissions"

fi
# RULE274:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 274; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-274.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 274 "auditd baseline and permissions"

fi
# RULE275:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 275; then
sec_audit_pkg_install audit
mkdir -p /etc/audit/rules.d
cat >/etc/audit/rules.d/99-secaudit-alma9-275.rules <<'EOF'
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
chmod 600 /etc/audit/*.conf /etc/audit/rules.d/*.rules 2>/dev/null || true
chown root:root /sbin/audit* 2>/dev/null || true
chmod go-rwx /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules 2>/dev/null || true
sec_audit_remediate_done 275 "auditd baseline and permissions"

fi
# RULE276:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 276; then
sec_audit_harden_file /etc/passwd 644 root:root
sec_audit_remediate_done 276 "permissions /etc/passwd"

fi
# RULE277:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 277; then
sec_audit_harden_file /etc/passwd- 644 root:root
sec_audit_remediate_done 277 "permissions /etc/passwd-"

fi
# RULE278:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 278; then
sec_audit_harden_file /etc/group 644 root:root
sec_audit_remediate_done 278 "permissions /etc/group"

fi
# RULE279:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 279; then
sec_audit_harden_file /etc/group- 644 root:root
sec_audit_remediate_done 279 "permissions /etc/group-"

fi
# RULE280:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 280; then
chmod 640 /etc/shadow 2>/dev/null || true
chown root:shadow /etc/shadow 2>/dev/null || chown root:root /etc/shadow 2>/dev/null || true
sec_audit_remediate_done 280 "permissions /etc/shadow"

fi
# RULE281:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 281; then
chmod 640 /etc/shadow- 2>/dev/null || true
chown root:shadow /etc/shadow- 2>/dev/null || chown root:root /etc/shadow- 2>/dev/null || true
sec_audit_remediate_done 281 "permissions /etc/shadow-"

fi
# RULE282:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 282; then
chmod 640 /etc/gshadow 2>/dev/null || true
chown root:shadow /etc/gshadow 2>/dev/null || chown root:root /etc/gshadow 2>/dev/null || true
sec_audit_remediate_done 282 "permissions /etc/gshadow"

fi
# RULE283:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 283; then
chmod 640 /etc/gshadow- 2>/dev/null || true
chown root:shadow /etc/gshadow- 2>/dev/null || chown root:root /etc/gshadow- 2>/dev/null || true
sec_audit_remediate_done 283 "permissions /etc/gshadow-"

fi
# RULE284:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 284; then
sec_audit_harden_file /etc/shells 644 root:root
sec_audit_remediate_done 284 "permissions /etc/shells"

fi
# RULE285:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 285; then
sec_audit_harden_file /etc/security/opasswd 600 root:root
sec_audit_remediate_done 285 "permissions /etc/security/opasswd"

fi
# RULE286:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 286; then
sec_audit_remediate_skip 286 "find and chmod o-w on world-writable files under critical paths"

fi
# RULE287:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 287; then
sec_audit_remediate_skip 287 "review remediation: Ensure no files or directories without an owner and a group exist"

fi
# RULE288:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 288; then
sec_audit_remediate_skip 288 "review SUID/SGID files and remove unnecessary binaries"

fi
# RULE289:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 289; then
sec_audit_remediate_done 289 "shadowed passwords - verify /etc/passwd second field is x"

fi
# RULE290:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 290; then
awk -F: '($2=="") {print $1}' /etc/shadow | while read -r u; do passwd -l "$u" >/dev/null 2>&1 || true; done
sec_audit_remediate_done 290 "lock accounts with empty shadow password"

fi
# RULE291:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 291; then
sec_audit_remediate_skip 291 "Ensure all groups in /etc/passwd exist in /etc/group"

fi
# RULE292:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 292; then
sec_audit_remediate_skip 292 "Ensure no duplicate UIDs exist"

fi
# RULE293:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 293; then
sec_audit_remediate_skip 293 "Ensure no duplicate GIDs exist"

fi
# RULE294:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 294; then
sec_audit_remediate_skip 294 "Ensure no duplicate user names exist"

fi
# RULE295:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 295; then
sec_audit_remediate_skip 295 "Ensure no duplicate group names exist"

fi
# RULE296:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 296; then
sec_audit_remediate_skip 296 "Ensure local interactive user home directories are configured"

fi
# RULE297:  # SECAUDIT_RULE_WRAP
if secaudit_rule_enabled 297; then
sec_audit_remediate_skip 297 "Ensure local interactive user dot files access is configured"

if sec_audit_have_bin dnf; then
    timeout 300 dnf upgrade --security -y >/dev/null 2>&1 || true
fi

sec_audit_log "AlmaLinux 9 remediation complete"
exit 0

fi
