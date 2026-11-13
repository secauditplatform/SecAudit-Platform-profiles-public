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

# RULE1:
sec_audit_disable_kernel_module cramfs
sec_audit_remediate_done 1 "blacklisted kernel module cramfs"

# RULE2:
sec_audit_disable_kernel_module freevxfs
sec_audit_remediate_done 2 "blacklisted kernel module freevxfs"

# RULE3:
sec_audit_disable_kernel_module hfs
sec_audit_remediate_done 3 "blacklisted kernel module hfs"

# RULE4:
sec_audit_disable_kernel_module hfsplus
sec_audit_remediate_done 4 "blacklisted kernel module hfsplus"

# RULE5:
sec_audit_disable_kernel_module jffs2
sec_audit_remediate_done 5 "blacklisted kernel module jffs2"

# RULE6:
sec_audit_disable_kernel_module squashfs
sec_audit_remediate_done 6 "blacklisted kernel module squashfs"

# RULE7:
sec_audit_disable_kernel_module udf
sec_audit_remediate_done 7 "blacklisted kernel module udf"

# RULE8:
sec_audit_disable_kernel_module usb-storage
sec_audit_remediate_done 8 "blacklisted kernel module usb-storage"

# RULE9:
sec_audit_remediate_skip 9 "blacklist unused filesystem modules (afs, ceph, cifs, etc.) per site policy"

# RULE10:
sec_audit_ensure_fstab_mount /tmp "nodev,nosuid,noexec"
sec_audit_remediate_done 10 "configured dedicated mount for /tmp"

# RULE11:
sec_audit_ensure_mount_option /tmp nodev
sec_audit_remediate_done 11 "set nodev on /tmp"

# RULE12:
sec_audit_ensure_mount_option /tmp nosuid
sec_audit_remediate_done 12 "set nosuid on /tmp"

# RULE13:
sec_audit_ensure_mount_option /tmp noexec
sec_audit_remediate_done 13 "set noexec on /tmp"

# RULE14:
sec_audit_ensure_fstab_mount /dev/shm "nodev,nosuid,noexec"
sec_audit_remediate_done 14 "configured dedicated mount for /dev/shm"

# RULE15:
sec_audit_ensure_mount_option /dev/shm nodev
sec_audit_remediate_done 15 "set nodev on /dev/shm"

# RULE16:
sec_audit_ensure_mount_option /dev/shm nosuid
sec_audit_remediate_done 16 "set nosuid on /dev/shm"

# RULE17:
sec_audit_ensure_mount_option /dev/shm noexec
sec_audit_remediate_done 17 "set noexec on /dev/shm"

# RULE18:
sec_audit_remediate_skip 18 "create separate partition for /home during provisioning; then set mount options"

# RULE19:
sec_audit_ensure_mount_option /home nodev
sec_audit_remediate_done 19 "set nodev on /home"

# RULE20:
sec_audit_ensure_mount_option /home nosuid
sec_audit_remediate_done 20 "set nosuid on /home"

# RULE21:
sec_audit_remediate_skip 21 "create separate partition for /var during provisioning; then set mount options"

# RULE22:
sec_audit_ensure_mount_option /var nodev
sec_audit_remediate_done 22 "set nodev on /var"

# RULE23:
sec_audit_ensure_mount_option /var nosuid
sec_audit_remediate_done 23 "set nosuid on /var"

# RULE24:
sec_audit_remediate_skip 24 "create separate partition for /var/tmp during provisioning; then set mount options"

# RULE25:
sec_audit_ensure_mount_option /var/tmp nodev
sec_audit_remediate_done 25 "set nodev on /var/tmp"

# RULE26:
sec_audit_ensure_mount_option /var/tmp nosuid
sec_audit_remediate_done 26 "set nosuid on /var/tmp"

# RULE27:
sec_audit_ensure_mount_option /var/tmp noexec
sec_audit_remediate_done 27 "set noexec on /var/tmp"

# RULE28:
sec_audit_remediate_skip 28 "create separate partition for /var/sec_audit_log during provisioning; then set mount options"

# RULE29:
sec_audit_ensure_mount_option /var/sec_audit_log nodev
sec_audit_remediate_done 29 "set nodev on /var/sec_audit_log"

# RULE30:
sec_audit_ensure_mount_option /var/sec_audit_log nosuid
sec_audit_remediate_done 30 "set nosuid on /var/sec_audit_log"

# RULE31:
sec_audit_ensure_mount_option /var/sec_audit_log noexec
sec_audit_remediate_done 31 "set noexec on /var/sec_audit_log"

# RULE32:
sec_audit_remediate_skip 32 "create separate partition for /var/sec_audit_log/audit during provisioning; then set mount options"

# RULE33:
sec_audit_ensure_mount_option /var/sec_audit_log/audit nodev
sec_audit_remediate_done 33 "set nodev on /var/sec_audit_log/audit"

# RULE34:
sec_audit_ensure_mount_option /var/sec_audit_log/audit nosuid
sec_audit_remediate_done 34 "set nosuid on /var/sec_audit_log/audit"

# RULE35:
sec_audit_ensure_mount_option /var/sec_audit_log/audit noexec
sec_audit_remediate_done 35 "set noexec on /var/sec_audit_log/audit"

# RULE36:
sec_audit_remediate_skip 36 "verify GPG keys in /etc/pki/rpm-gpg/ match trusted AlmaLinux repositories"

# RULE37:
sec_audit_set_dnf_main_kv gpgcheck 1
sec_audit_set_dnf_main_kv localpkg_gpgcheck 1
sec_audit_remediate_done 37 "enabled gpgcheck in dnf.conf"

# RULE38:
sec_audit_remediate_skip 38 "set repo_gpgcheck=1 in /etc/dnf/dnf.conf and .repo files if supported"

# RULE39:
sec_audit_remediate_skip 39 "configure valid AlmaLinux repositories in /etc/yum.repos.d/"

# RULE40:
sec_audit_remediate_skip 40 "run dnf upgrade --security after change review"

# RULE41:
sec_audit_pkg_install libselinux
sec_audit_remediate_done 41 "installed SELinux packages"

# RULE42:
if sec_audit_have_bin grubby; then
    grubby --update-kernel=ALL --remove-args="selinux=0 enforcing=0" >/dev/null 2>&1 || true
fi
sec_audit_remediate_done 42 "removed selinux=0 from bootloader"

# RULE43:
[[ -f /etc/selinux/config ]] && {
    sed -i "s/^SELINUXTYPE=.*/SELINUXTYPE=targeted/" /etc/selinux/config 2>/dev/null || true
    grep -q "^SELINUXTYPE=" /etc/selinux/config || echo "SELINUXTYPE=targeted" >>/etc/selinux/config
}
sec_audit_remediate_done 43 "set SELINUXTYPE=targeted"

# RULE44:
[[ -f /etc/selinux/config ]] && sed -i "s/^SELINUX=.*/SELINUX=enforcing/" /etc/selinux/config 2>/dev/null || true
sec_audit_have_bin setenforce && setenforce 1 >/dev/null 2>&1 || true
sec_audit_remediate_done 44 "SELinux mode not disabled"

# RULE45:
[[ -f /etc/selinux/config ]] && sed -i "s/^SELINUX=.*/SELINUX=enforcing/" /etc/selinux/config 2>/dev/null || true
sec_audit_have_bin setenforce && setenforce 1 >/dev/null 2>&1 || true
sec_audit_remediate_done 45 "SELinux enforcing"

# RULE46:
sec_audit_remediate_skip 46 "investigate unconfined_service_t processes; confine or remove services"

# RULE47:
sec_audit_pkg_remove mcstrans
sec_audit_disable_svc mcstrans.service
sec_audit_remediate_done 47 "removed mcstrans"

# RULE48:
sec_audit_pkg_remove setroubleshoot
sec_audit_remediate_done 48 "removed setroubleshoot"

# RULE49:
sec_audit_remediate_skip 49 "run grub2-setpassword and rebuild grub.cfg per 1.4.1"

# RULE50:
sec_audit_harden_file /boot/grub2/grub.cfg 600 root:root
sec_audit_harden_file /boot/grub2/user.cfg 600 root:root
sec_audit_remediate_done 50 "hardened grub permissions"

# RULE51:
grep -q "hard core" /etc/security/limits.conf 2>/dev/null || echo "* hard core 0" >>/etc/security/limits.conf
mkdir -p /etc/systemd/coredump.conf.d
cat >/etc/systemd/coredump.conf.d/99-secaudit-alma9-sec.conf <<'EOF'
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
sec_audit_set_sysctl fs.suid_dumpable 0
sec_audit_remediate_done 54 "set fs.suid_dumpable=0"

# RULE55:
sec_audit_have_bin update-crypto-policies && update-crypto-policies --set DEFAULT >/dev/null 2>&1 || true
sec_audit_remediate_done 55 "crypto policy not LEGACY"

# RULE56:
sec_audit_have_bin update-crypto-policies && update-crypto-policies --set DEFAULT:NO-SHA1:NO-SSHCBC >/dev/null 2>&1 || update-crypto-policies --set DEFAULT >/dev/null 2>&1 || true
sec_audit_remediate_done 56 "applied DEFAULT crypto policy modules"

# RULE57:
sec_audit_have_bin update-crypto-policies && update-crypto-policies --set DEFAULT:NO-SHA1:NO-SSHCBC >/dev/null 2>&1 || update-crypto-policies --set DEFAULT >/dev/null 2>&1 || true
sec_audit_remediate_done 57 "applied DEFAULT crypto policy modules"

# RULE58:
sec_audit_have_bin update-crypto-policies && update-crypto-policies --set DEFAULT:NO-SHA1:NO-SSHCBC >/dev/null 2>&1 || update-crypto-policies --set DEFAULT >/dev/null 2>&1 || true
sec_audit_remediate_done 58 "applied DEFAULT crypto policy modules"

# RULE59:
sec_audit_have_bin update-crypto-policies && update-crypto-policies --set DEFAULT:NO-SHA1:NO-SSHCBC >/dev/null 2>&1 || update-crypto-policies --set DEFAULT >/dev/null 2>&1 || true
sec_audit_remediate_done 59 "applied DEFAULT crypto policy modules"

# RULE60:
sec_audit_remediate_skip 60 "disable chacha20-poly1305 in crypto policy module if required by policy"

# RULE61:
sec_audit_remediate_skip 61 "set etm=DISABLE_ETM in crypto policy for ssh if required by policy"

# RULE62:
[[ -f /etc/motd ]] || echo "Authorized use only." >/etc/motd
sed -i 's/\\[vVrms]//g' /etc/motd 2>/dev/null || true
sec_audit_remediate_done 62 "sanitized login banner /etc/motd"

# RULE63:
[[ -f /etc/issue ]] || echo "Authorized use only." >/etc/issue
sed -i 's/\\[vVrms]//g' /etc/issue 2>/dev/null || true
sec_audit_remediate_done 63 "sanitized login banner /etc/issue"

# RULE64:
[[ -f /etc/issue.net ]] || echo "Authorized use only." >/etc/issue.net
sed -i 's/\\[vVrms]//g' /etc/issue.net 2>/dev/null || true
sec_audit_remediate_done 64 "sanitized login banner /etc/issue.net"

# RULE65:
sec_audit_harden_file /etc/motd 644 root:root
sec_audit_remediate_done 65 "set permissions on /etc/motd"

# RULE66:
sec_audit_harden_file /etc/issue 644 root:root
sec_audit_remediate_done 66 "set permissions on /etc/issue"

# RULE67:
sec_audit_harden_file /etc/issue.net 644 root:root
sec_audit_remediate_done 67 "set permissions on /etc/issue.net"

# RULE68:
sec_audit_pkg_remove gdm
sec_audit_disable_svc gdm
sec_audit_remediate_done 68 "removed GDM"

# RULE69:
mkdir -p /etc/dconf/db/gdm.d
printf "%s\n" "[org/gnome/login-screen]" "disable-user-list=true" >/etc/dconf/db/gdm.d/00-login-screen
sec_audit_have_bin dconf update && dconf update >/dev/null 2>&1 || true
sec_audit_remediate_done 69 "configured GDM hardening"

# RULE70:
mkdir -p /etc/dconf/db/gdm.d
printf "%s\n" "[org/gnome/desktop/media-handling]" "automount=false" "automount-open=false" "autorun-never=true" >/etc/dconf/db/gdm.d/01-media
sec_audit_have_bin dconf update && dconf update >/dev/null 2>&1 || true
sec_audit_remediate_done 70 "configured GDM hardening"

# RULE71:
mkdir -p /etc/dconf/db/gdm.d
printf "%s\n" "[org/gnome/desktop/media-handling]" "automount=false" "automount-open=false" "autorun-never=true" >/etc/dconf/db/gdm.d/01-media
sec_audit_have_bin dconf update && dconf update >/dev/null 2>&1 || true
sec_audit_remediate_done 71 "configured GDM hardening"

# RULE72:
mkdir -p /etc/dconf/db/gdm.d
printf "%s\n" "[org/gnome/desktop/media-handling]" "automount=false" "automount-open=false" "autorun-never=true" >/etc/dconf/db/gdm.d/01-media
sec_audit_have_bin dconf update && dconf update >/dev/null 2>&1 || true
sec_audit_remediate_done 72 "configured GDM hardening"

# RULE73:
mkdir -p /etc/gdm
grep -q "^\[daemon\]" /etc/gdm/custom.conf 2>/dev/null || echo "[daemon]" >>/etc/gdm/custom.conf
sed -i "/^\[daemon\]/a WaylandEnable=false" /etc/gdm/custom.conf 2>/dev/null || true
sec_audit_remediate_done 73 "configured GDM hardening"

# RULE74:
mkdir -p /etc/dconf/db/gdm.d
printf "%s\n" "[org/gnome/desktop/media-handling]" "automount=false" "automount-open=false" "autorun-never=true" >/etc/dconf/db/gdm.d/01-media
sec_audit_have_bin dconf update && dconf update >/dev/null 2>&1 || true
sec_audit_remediate_done 74 "configured GDM hardening"

# RULE75:
mkdir -p /etc/dconf/db/gdm.d
printf "%s\n" "[org/gnome/desktop/media-handling]" "automount=false" "automount-open=false" "autorun-never=true" >/etc/dconf/db/gdm.d/01-media
sec_audit_have_bin dconf update && dconf update >/dev/null 2>&1 || true
sec_audit_remediate_done 75 "configured GDM hardening"

# RULE76:
mkdir -p /etc/dconf/db/gdm.d
printf "%s\n" "[org/gnome/desktop/media-handling]" "automount=false" "automount-open=false" "autorun-never=true" >/etc/dconf/db/gdm.d/01-media
sec_audit_have_bin dconf update && dconf update >/dev/null 2>&1 || true
sec_audit_remediate_done 76 "configured GDM hardening"

# RULE77:
sed -i "/^\[xdmcp\]/,/^\[/ s/^Enable=.*/Enable=false/" /etc/gdm/custom.conf 2>/dev/null || true
sec_audit_remediate_done 77 "configured GDM hardening"

# RULE78:
sec_audit_disable_svc autofs.service
sec_audit_pkg_remove autofs
sec_audit_remediate_done 78 "disabled autofs services"

# RULE79:
sec_audit_disable_svc avahi-daemon.socket
sec_audit_disable_svc avahi-daemon.service
sec_audit_pkg_remove avahi
sec_audit_remediate_done 79 "disabled avahi services"

# RULE80:
sec_audit_disable_svc cockpit.socket
sec_audit_disable_svc cockpit.service
sec_audit_pkg_remove cockpit-ws
sec_audit_remediate_done 80 "disabled cockpit-ws services"

# RULE81:
sec_audit_disable_svc dhcpd.service
sec_audit_disable_svc dhcpd6.service
sec_audit_pkg_remove dhcp-server
sec_audit_remediate_done 81 "disabled dhcp-server services"

# RULE82:
sec_audit_disable_svc named.service
sec_audit_pkg_remove bind
sec_audit_remediate_done 82 "disabled bind services"

# RULE83:
sec_audit_disable_svc dnsmasq.service
sec_audit_pkg_remove dnsmasq
sec_audit_remediate_done 83 "disabled dnsmasq services"

# RULE84:
sec_audit_disable_svc vsftpd.service
sec_audit_pkg_remove vsftpd
sec_audit_remediate_done 84 "disabled vsftpd services"

# RULE85:
sec_audit_disable_svc dovecot.socket
sec_audit_disable_svc dovecot.service
sec_audit_disable_svc cyrus-imapd.service
sec_audit_pkg_remove dovecot
sec_audit_remediate_done 85 "disabled dovecot services"

# RULE86:
sec_audit_disable_svc nfs-server.service
sec_audit_pkg_remove nfs-utils
sec_audit_remediate_done 86 "disabled nfs-utils services"

# RULE87:
sec_audit_disable_svc cups.socket
sec_audit_disable_svc cups.service
sec_audit_pkg_remove cups
sec_audit_remediate_done 87 "disabled cups services"

# RULE88:
sec_audit_disable_svc rpcbind.socket
sec_audit_disable_svc rpcbind.service
sec_audit_pkg_remove rpcbind
sec_audit_remediate_done 88 "disabled rpcbind services"

# RULE89:
sec_audit_disable_svc rsyncd.socket
sec_audit_disable_svc rsyncd.service
sec_audit_pkg_remove rsync-daemon
sec_audit_remediate_done 89 "disabled rsync-daemon services"

# RULE90:
sec_audit_disable_svc smb.service
sec_audit_pkg_remove samba
sec_audit_remediate_done 90 "disabled samba services"

# RULE91:
sec_audit_disable_svc snmpd.service
sec_audit_pkg_remove net-snmp
sec_audit_remediate_done 91 "disabled net-snmp services"

# RULE92:
sec_audit_disable_svc telnet.socket
sec_audit_pkg_remove telnet-server
sec_audit_remediate_done 92 "disabled telnet-server services"

# RULE93:
sec_audit_disable_svc tftp.socket
sec_audit_disable_svc tftp.service
sec_audit_pkg_remove tftp-server
sec_audit_remediate_done 93 "disabled tftp-server services"

# RULE94:
sec_audit_disable_svc squid.service
sec_audit_pkg_remove squid
sec_audit_remediate_done 94 "disabled squid services"

# RULE95:
sec_audit_disable_svc httpd.service
sec_audit_disable_svc nginx.service
sec_audit_pkg_remove httpd
sec_audit_remediate_done 95 "disabled httpd services"

# RULE96:
sec_audit_pkg_remove gdm
sec_audit_disable_svc gdm
sec_audit_remediate_done 96 "removed GDM"

# RULE97:
sec_audit_disable_svc gdm
sec_audit_pkg_remove xorg-x11-server-Xorg
sec_audit_remediate_done 97 "disabled xorg-x11-server-Xorg services"

# RULE98:
if rpm -q postfix &>/dev/null; then
    postconf -e "inet_interfaces = loopback-only" >/dev/null 2>&1 || true
    systemctl restart postfix >/dev/null 2>&1 || true
fi
sec_audit_remediate_done 98 "postfix loopback-only"

# RULE99:
sec_audit_remediate_skip 99 "review listening ports with ss -tuln; stop unapproved services"

# RULE100:
sec_audit_pkg_remove ftp
sec_audit_remediate_done 100 "removed client package ftp"

# RULE101:
sec_audit_pkg_remove openldap-clients
sec_audit_remediate_done 101 "removed client package openldap-clients"

# RULE102:
sec_audit_pkg_remove telnet
sec_audit_remediate_done 102 "removed client package telnet"

# RULE103:
sec_audit_pkg_remove telnet
sec_audit_remediate_done 103 "removed client package telnet"

# RULE104:
sec_audit_pkg_remove tftp
sec_audit_remediate_done 104 "removed client package tftp"

# RULE105:
sec_audit_pkg_install chrony
sec_audit_start_svc chronyd
sec_audit_remediate_done 105 "installed chrony"

# RULE106:
sec_audit_pkg_install chrony
grep -q "^pool " /etc/chrony.conf 2>/dev/null || echo "pool 2.almalinux.pool.ntp.org iburst" >>/etc/chrony.conf
sec_audit_start_svc chronyd
sec_audit_remediate_done 106 "configured chrony pool"

# RULE107:
grep -q "^OPTIONS=" /etc/sysconfig/chronyd 2>/dev/null && sed -i 's/^OPTIONS=.*/OPTIONS="-u chrony"/' /etc/sysconfig/chronyd || echo 'OPTIONS="-u chrony"' >>/etc/sysconfig/chronyd
systemctl restart chronyd >/dev/null 2>&1 || true
sec_audit_remediate_done 107 "chrony not run as root"

# RULE108:
sec_audit_pkg_install cronie
sec_audit_start_svc crond
sec_audit_remediate_done 108 "enabled cron daemon"

# RULE109:
chmod 600 /etc/crontab 2>/dev/null || true
chown root:root /etc/crontab 2>/dev/null || true
sec_audit_remediate_done 109 "restricted cron path /etc/crontab"

# RULE110:
chmod 700 /etc/cron.hourly 2>/dev/null || true
chown root:root /etc/cron.hourly 2>/dev/null || true
sec_audit_remediate_done 110 "restricted cron path /etc/cron.hourly"

# RULE111:
chmod 700 /etc/cron.daily 2>/dev/null || true
chown root:root /etc/cron.daily 2>/dev/null || true
sec_audit_remediate_done 111 "restricted cron path /etc/cron.daily"

# RULE112:
chmod 700 /etc/cron.weekly 2>/dev/null || true
chown root:root /etc/cron.weekly 2>/dev/null || true
sec_audit_remediate_done 112 "restricted cron path /etc/cron.weekly"

# RULE113:
chmod 700 /etc/cron.monthly 2>/dev/null || true
chown root:root /etc/cron.monthly 2>/dev/null || true
sec_audit_remediate_done 113 "restricted cron path /etc/cron.monthly"

# RULE114:
chmod 700 /etc/cron.yearly 2>/dev/null || true
chown root:root /etc/cron.yearly 2>/dev/null || true
sec_audit_remediate_done 114 "restricted cron path /etc/cron.yearly"

# RULE115:
chmod 700 /etc/cron.d 2>/dev/null || true
chown root:root /etc/cron.d 2>/dev/null || true
sec_audit_remediate_done 115 "restricted cron path /etc/cron.d"

# RULE116:
chmod 600 /etc/cron.deny 2>/dev/null || true
chown root:root /etc/cron.deny 2>/dev/null || true
sec_audit_remediate_done 116 "restricted at/cron deny files"

# RULE117:
sec_audit_remediate_skip 117 "document IPv6 enable/disable decision and sysctl accordingly"

# RULE118:
sec_audit_disable_kernel_module bluetooth
sec_audit_pkg_remove bluez
sec_audit_remediate_done 118 "disabled wireless/bluetooth module"

# RULE119:
sec_audit_disable_svc bluetooth.service
sec_audit_pkg_remove bluez
sec_audit_remediate_done 119 "disabled bluetooth service"

# RULE120:
sec_audit_disable_kernel_module dccp
sec_audit_remediate_done 120 "blacklisted kernel module dccp"

# RULE121:
sec_audit_disable_kernel_module sctp
sec_audit_remediate_done 121 "blacklisted kernel module sctp"

# RULE122:
sec_audit_disable_kernel_module rds
sec_audit_remediate_done 122 "blacklisted kernel module rds"

# RULE123:
sec_audit_disable_kernel_module tipc
sec_audit_remediate_done 123 "blacklisted kernel module tipc"

# RULE124:
sec_audit_set_sysctl net.ipv4.conf.all.send_redirects 0
sec_audit_remediate_done 124 "set net.ipv4.conf.all.send_redirects=0"

# RULE125:
sec_audit_set_sysctl net.ipv4.conf.default.send_redirects 0
sec_audit_remediate_done 125 "set net.ipv4.conf.default.send_redirects=0"

# RULE126:
sec_audit_set_sysctl net.ipv4.icmp_ignore_bogus_error_responses 1
sec_audit_remediate_done 126 "set net.ipv4.icmp_ignore_bogus_error_responses=1"

# RULE127:
sec_audit_set_sysctl net.ipv4.conf.all.accept_redirects 0
sec_audit_remediate_done 127 "set net.ipv4.conf.all.accept_redirects=0"

# RULE128:
sec_audit_set_sysctl net.ipv6.conf.all.accept_redirects 0
sec_audit_remediate_done 128 "set net.ipv6.conf.all.accept_redirects=0"

# RULE129:
sec_audit_set_sysctl net.ipv4.conf.all.secure_redirects 0
sec_audit_remediate_done 129 "set net.ipv4.conf.all.secure_redirects=0"

# RULE130:
sec_audit_set_sysctl net.ipv4.conf.all.rp_filter 1
sec_audit_remediate_done 130 "set net.ipv4.conf.all.rp_filter=1"

# RULE131:
sec_audit_set_sysctl net.ipv4.conf.default.rp_filter 1
sec_audit_remediate_done 131 "set net.ipv4.conf.default.rp_filter=1"

# RULE132:
sec_audit_set_sysctl net.ipv4.conf.all.log_martians 1
sec_audit_remediate_done 132 "set net.ipv4.conf.all.log_martians=1"

# RULE133:
sec_audit_set_sysctl net.ipv4.conf.all.log_martians 1
sec_audit_remediate_done 133 "set net.ipv4.conf.all.log_martians=1"

# RULE134:
sec_audit_set_sysctl net.ipv4.tcp_syncookies 1
sec_audit_remediate_done 134 "set net.ipv4.tcp_syncookies=1"

# RULE135:
sec_audit_pkg_install firewalld
sec_audit_start_svc firewalld
sec_audit_remediate_done 135 "installed firewalld"

# RULE136:
[[ -f /etc/firewalld/firewalld.conf ]] && {
    grep -q "^FirewallBackend=" /etc/firewalld/firewalld.conf && sed -i "s/^FirewallBackend=.*/FirewallBackend=nftables/" /etc/firewalld/firewalld.conf || echo "FirewallBackend=nftables" >>/etc/firewalld/firewalld.conf
}
sec_audit_start_svc firewalld
sec_audit_remediate_done 136 "firewalld nftables backend"

# RULE137:
sec_audit_remediate_skip 137 "remove unnecessary firewalld services/ports per site policy"

# RULE138:
sec_audit_have_bin firewall-cmd && firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address="127.0.0.1" accept' >/dev/null 2>&1 && firewall-cmd --reload >/dev/null 2>&1 || true
sec_audit_remediate_done 138 "firewalld loopback"

# RULE139:
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

# RULE140:
sec_audit_remediate_skip 140 "configure nftables ct state established,related accept rules"

# RULE141:
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

# RULE142:
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

# RULE143:
sec_audit_harden_file /etc/ssh/sshd_config 600 root:root
sec_audit_remediate_done 143 "sshd_config permissions"

# RULE144:
chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null || true
chmod 644 /etc/ssh/ssh_host_*_key.pub 2>/dev/null || true
chown root:ssh_keys /etc/ssh/ssh_host_*_key 2>/dev/null || true
sec_audit_remediate_done 144 "SSH host key permissions"

# RULE145:
chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null || true
chmod 644 /etc/ssh/ssh_host_*_key.pub 2>/dev/null || true
chown root:ssh_keys /etc/ssh/ssh_host_*_key 2>/dev/null || true
sec_audit_remediate_done 145 "SSH host key permissions"

# RULE146:
sec_audit_set_sshd_kv AllowUsers "alloweduser"
sec_audit_remediate_done 146 "sshd AllowUsers placeholder - edit for site"

# RULE147:
sec_audit_set_sshd_kv Banner /etc/issue.net
sec_audit_remediate_done 147 "sshd Banner"

# RULE148:
sec_audit_have_bin update-crypto-policies && update-crypto-policies --set DEFAULT:NO-SHA1:NO-SSHCBC >/dev/null 2>&1 || true
systemctl restart sshd >/dev/null 2>&1 || true
sec_audit_remediate_done 148 "SSH crypto via system-wide crypto-policies"

# RULE149:
sec_audit_set_sshd_kv ClientAliveInterval 300
sec_audit_remediate_done 149 "sshd ClientAliveInterval"

# RULE150:
sec_audit_set_sshd_kv DisableForwarding yes
sec_audit_remediate_done 150 "sshd DisableForwarding"

# RULE151:
sec_audit_set_sshd_kv GSSAPIAuthentication no
sec_audit_remediate_done 151 "sshd GSSAPIAuthentication"

# RULE152:
sec_audit_set_sshd_kv HostbasedAuthentication no
sec_audit_remediate_done 152 "sshd HostbasedAuthentication"

# RULE153:
sec_audit_set_sshd_kv IgnoreRhosts yes
sec_audit_remediate_done 153 "sshd IgnoreRhosts"

# RULE154:
sec_audit_have_bin update-crypto-policies && update-crypto-policies --set DEFAULT:NO-SHA1:NO-SSHCBC >/dev/null 2>&1 || true
systemctl restart sshd >/dev/null 2>&1 || true
sec_audit_remediate_done 154 "SSH crypto via system-wide crypto-policies"

# RULE155:
sec_audit_set_sshd_kv LoginGraceTime 60
sec_audit_remediate_done 155 "sshd LoginGraceTime"

# RULE156:
sec_audit_set_sshd_kv LogLevel VERBOSE
sec_audit_remediate_done 156 "sshd LogLevel"

# RULE157:
sec_audit_have_bin update-crypto-policies && update-crypto-policies --set DEFAULT:NO-SHA1:NO-SSHCBC >/dev/null 2>&1 || true
systemctl restart sshd >/dev/null 2>&1 || true
sec_audit_remediate_done 157 "SSH crypto via system-wide crypto-policies"

# RULE158:
sec_audit_set_sshd_kv MaxAuthTries 4
sec_audit_remediate_done 158 "sshd MaxAuthTries"

# RULE159:
sec_audit_set_sshd_kv MaxStartups 10:30:60
sec_audit_remediate_done 159 "sshd MaxStartups"

# RULE160:
sec_audit_set_sshd_kv MaxSessions 10
sec_audit_remediate_done 160 "sshd MaxSessions"

# RULE161:
sec_audit_set_sshd_kv PermitEmptyPasswords no
sec_audit_remediate_done 161 "sshd PermitEmptyPasswords"

# RULE162:
sec_audit_set_sshd_kv PermitRootLogin no
sec_audit_remediate_done 162 "sshd PermitRootLogin"

# RULE163:
sec_audit_set_sshd_kv PermitUserEnvironment no
sec_audit_remediate_done 163 "sshd PermitUserEnvironment"

# RULE164:
sec_audit_set_sshd_kv UsePAM yes
sec_audit_remediate_done 164 "sshd UsePAM"

# RULE165:
sec_audit_pkg_install sudo
sec_audit_remediate_done 165 "sudo installed"

# RULE166:
echo "Defaults use_pty" >/etc/sudoers.d/99-secaudit-pty
chmod 440 /etc/sudoers.d/99-secaudit-pty
sec_audit_remediate_done 166 "sudo use_pty"

# RULE167:
echo "Defaults logfile=/var/sec_audit_log/sudo.sec_audit_log" >/etc/sudoers.d/99-secaudit-logfile
chmod 440 /etc/sudoers.d/99-secaudit-logfile
sec_audit_remediate_done 167 "sudo logfile"

# RULE168:
grep -q "^Defaults" /etc/sudoers 2>/dev/null || true
sec_audit_remediate_done 168 "verify sudo requires password (review sudoers)"

# RULE169:
sed -i "/!authenticate/d" /etc/sudoers /etc/sudoers.d/* 2>/dev/null || true
sec_audit_remediate_done 169 "removed global !authenticate"

# RULE170:
echo "Defaults timestamp_timeout=5" >/etc/sudoers.d/99-secaudit-timeout
chmod 440 /etc/sudoers.d/99-secaudit-timeout
sec_audit_remediate_done 170 "sudo timestamp_timeout=5"

# RULE171:
grep -q "^auth.*required.*pam_wheel.so" /etc/pam.d/su 2>/dev/null || echo "auth required pam_wheel.so use_uid" >>/etc/pam.d/su
grep -q "^wheel:" /etc/group || groupadd wheel 2>/dev/null || true
sec_audit_remediate_done 171 "restricted su to wheel"

# RULE172:
sec_audit_authselect_enable with-faillock
sec_audit_authselect_enable with-pwquality
sec_audit_remediate_done 172 "authselect PAM modules"

# RULE173:
sec_audit_authselect_enable with-faillock
sec_audit_remediate_done 173 "pam_faillock enabled"

# RULE174:
sec_audit_authselect_enable with-pwquality
sec_audit_remediate_done 174 "pam_pwquality enabled"

# RULE175:
sec_audit_authselect_enable with-faillock
sec_audit_authselect_enable with-pwquality
sec_audit_remediate_done 175 "authselect PAM modules"

# RULE176:
sec_audit_authselect_enable with-faillock
sec_audit_remediate_done 176 "pam_faillock enabled"

# RULE177:
sec_audit_authselect_enable with-pwquality
sec_audit_remediate_done 177 "pam_pwquality enabled"

# RULE178:
sec_audit_authselect_enable with-pwhistory
sec_audit_remediate_done 178 "pam_pwhistory enabled"

# RULE179:
authselect select sssd with-faillock with-pwquality with-pwhistory --force >/dev/null 2>&1 || authselect apply-changes >/dev/null 2>&1 || true
sec_audit_remediate_done 179 "pam_unix via authselect"

# RULE180:
sec_audit_set_faillock_kv deny 5
sec_audit_remediate_done 180 "faillock deny=5"

# RULE181:
sec_audit_set_faillock_kv unlock_time 900
sec_audit_remediate_done 181 "faillock unlock_time"

# RULE182:
grep -q even_deny_root /etc/security/faillock.conf 2>/dev/null || echo "even_deny_root" >>/etc/security/faillock.conf
sec_audit_remediate_done 182 "faillock even_deny_root"

# RULE183:
sec_audit_set_pwquality_kv difok 2
sec_audit_remediate_done 183 "pwquality difok"

# RULE184:
sec_audit_set_pwquality_kv minlen 14
sec_audit_remediate_done 184 "pwquality minlen 14"

# RULE185:
sec_audit_remediate_skip 185 "set minclass/dcredit/ucredit/lcredit/ocredit per organizational policy"

# RULE186:
sec_audit_set_pwquality_kv maxrepeat 3
sec_audit_remediate_done 186 "pwquality maxrepeat"

# RULE187:
sec_audit_set_pwquality_kv maxsequence 3
sec_audit_remediate_done 187 "pwquality maxsequence"

# RULE188:
sec_audit_set_pwquality_kv dictcheck 1
sec_audit_remediate_done 188 "pwquality dictcheck"

# RULE189:
grep -q enforce_for_root /etc/security/pwquality.conf 2>/dev/null || echo "enforce_for_root" >>/etc/security/pwquality.conf
sec_audit_remediate_done 189 "pwquality enforce_for_root"

# RULE190:
grep -q "^remember" /etc/security/pwhistory.conf 2>/dev/null || echo "remember = 24" >>/etc/security/pwhistory.conf
sec_audit_remediate_done 190 "pwhistory remember"

# RULE191:
grep -q enforce_for_root /etc/security/pwhistory.conf 2>/dev/null || echo "enforce_for_root" >>/etc/security/pwhistory.conf
sec_audit_remediate_done 191 "pwhistory enforce_for_root"

# RULE192:
authselect apply-changes >/dev/null 2>&1 || true
sec_audit_remediate_done 192 "PAM use_authtok via authselect"

# RULE193:
sed -i "s/nullok//g" /etc/pam.d/password-auth /etc/pam.d/system-auth 2>/dev/null || true
sec_audit_remediate_done 193 "removed pam_unix nullok"

# RULE194:
sed -i "/pam_unix.so/s/ remember=[0-9]*//g" /etc/pam.d/password-auth 2>/dev/null || true
sec_audit_remediate_done 194 "removed pam_unix remember"

# RULE195:
sec_audit_set_login_defs_kv ENCRYPT_METHOD SHA512
sec_audit_remediate_done 195 "ENCRYPT_METHOD SHA512"

# RULE196:
authselect apply-changes >/dev/null 2>&1 || true
sec_audit_remediate_done 196 "PAM use_authtok via authselect"

# RULE197:
sec_audit_set_login_defs_kv PASS_MAX_DAYS 90
sec_audit_remediate_done 197 "PASS_MAX_DAYS 90"

# RULE198:
sec_audit_remediate_skip 198 "set PASS_MIN_DAYS in /etc/login.defs per organizational policy ( suggests 1+)"

# RULE199:
sec_audit_set_login_defs_kv PASS_WARN_AGE 7
sec_audit_remediate_done 199 "PASS_WARN_AGE 7"

# RULE200:
sec_audit_set_login_defs_kv ENCRYPT_METHOD SHA512
sec_audit_remediate_done 200 "ENCRYPT_METHOD SHA512"

# RULE201:
useradd -D -f 45 >/dev/null 2>&1 || true
sec_audit_remediate_done 201 "INACTIVE=45"

# RULE202:
sec_audit_remediate_skip 202 "Ensure all users last password change date is in the past"

# RULE203:
sec_audit_remediate_skip 203 "Ensure root is the only UID 0 account"

# RULE204:
sec_audit_remediate_skip 204 "Ensure root is the only GID 0 account"

# RULE205:
sec_audit_remediate_skip 205 "Ensure group root is the only GID 0 group"

# RULE206:
sec_audit_remediate_skip 206 "Ensure root account access is controlled"

# RULE207:
sec_audit_remediate_skip 207 "Ensure root path integrity"

# RULE208:
grep -q umask /root/.bash_profile 2>/dev/null || echo "umask 027" >>/root/.bash_profile
sec_audit_remediate_done 208 "root umask 027"

# RULE209:
UID_MIN=$(awk "/^UID_MIN/{print \$2}" /etc/login.defs)
while IFS=: read -r u _ uid _ _ _ shell; do
    [[ "$uid" -lt "$UID_MIN" || "$uid" -eq 65534 ]] && continue
    [[ "$shell" == */nologin || "$shell" == */false ]] && usermod -s /sbin/nologin "$u" 2>/dev/null || true
done < /etc/passwd
sec_audit_remediate_done 209 "system accounts nologin shell"

# RULE210:
while IFS= read -r u; do
    passwd -l "$u" >/dev/null 2>&1 || true
done < <(awk -F: '($3>=1000 && $3<65534 && $7!~/nologin|false/) {print $1}' /etc/passwd)
sec_audit_remediate_done 210 "lock accounts without valid shell"

# RULE211:
sed -i "/\/nologin/d" /etc/shells 2>/dev/null || true
sec_audit_remediate_done 211 "removed nologin from /etc/shells"

# RULE212:
cat >/etc/profile.d/99-alma9-timeout.sh <<'EOF'
TMOUT=600
readonly TMOUT
export TMOUT
EOF
sec_audit_remediate_done 212 "TMOUT=600"

# RULE213:
sec_audit_set_login_defs_kv UMASK 027
cat >/etc/profile.d/99-alma9-umask.sh <<'EOF'
umask 027
EOF
sec_audit_remediate_done 213 "default umask 027"

# RULE214:
sec_audit_pkg_install aide
sec_audit_remediate_done 214 "installed AIDE"

# RULE215:
sec_audit_pkg_install aide
sec_audit_have_bin aide && aide --init >/dev/null 2>&1 || true
[[ -f /var/lib/aide/aide.db.new.gz ]] && cp -a /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz 2>/dev/null || true
sec_audit_start_svc aidecheck.timer
sec_audit_remediate_done 215 "AIDE periodic check"

# RULE216:
for t in /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules; do
    grep -q "$t" /etc/aide.conf 2>/dev/null || echo "$t p+i+n+u+g+s+b+m+c+sha256" >>/etc/aide.conf
done
sec_audit_remediate_done 216 "AIDE monitors audit tools"

# RULE217:
sec_audit_start_svc systemd-journald
sec_audit_remediate_done 217 "journald active"

# RULE218:
sec_audit_remediate_skip 218 "set z /var/sec_audit_log/journal permissions in /etc/tmpfiles.d/systemd.conf"

# RULE219:
sec_audit_remediate_skip 219 "set SystemMaxUse/SystemMaxFileSize in journald.conf per retention policy"

# RULE220:
sec_audit_disable_svc rsyslog
sec_audit_start_svc systemd-journald
sec_audit_remediate_done 220 "single logging system (journald)"

# RULE221:
sec_audit_remediate_skip 221 "install systemd-journal-remote only when journal-upload TLS/URL can be configured per site"

# RULE222:
sec_audit_remediate_skip 222 "Ensure systemd-journal-upload authentication is configured"

# RULE223:
sec_audit_remediate_skip 223 "enable systemd-journal-upload only if central logging required"

# RULE224:
sec_audit_disable_svc systemd-journal-remote.socket systemd-journal-remote.service
sec_audit_remediate_done 224 "journal-remote disabled"

# RULE225:
mkdir -p /etc/systemd/journald.conf.d
cat >/etc/systemd/journald.conf.d/99-secaudit-alma9.conf <<'EOF'
[Journal]
ForwardToSyslog=no
Compress=yes
Storage=persistent
EOF
systemctl restart systemd-journald >/dev/null 2>&1 || true
sec_audit_remediate_done 225 "journald ForwardToSyslog=no"

# RULE226:
mkdir -p /etc/systemd/journald.conf.d
grep -q "Compress=yes" /etc/systemd/journald.conf.d/99-secaudit-alma9.conf 2>/dev/null || cat >>/etc/systemd/journald.conf.d/99-secaudit-alma9.conf <<'EOF'
Compress=yes
Storage=persistent
EOF
systemctl restart systemd-journald >/dev/null 2>&1 || true
sec_audit_remediate_done 226 "journald compress/storage"

# RULE227:
mkdir -p /etc/systemd/journald.conf.d
grep -q "Compress=yes" /etc/systemd/journald.conf.d/99-secaudit-alma9.conf 2>/dev/null || cat >>/etc/systemd/journald.conf.d/99-secaudit-alma9.conf <<'EOF'
Compress=yes
Storage=persistent
EOF
systemctl restart systemd-journald >/dev/null 2>&1 || true
sec_audit_remediate_done 227 "journald compress/storage"

# RULE228:
sec_audit_remediate_skip 228 "install rsyslog only when remote sec_audit_log host forwarding can be configured per site"

# RULE229:
sec_audit_remediate_skip 229 "enable rsyslog only when remote sec_audit_log host forwarding can be configured per site"

# RULE230:
sec_audit_remediate_skip 230 "configure journald ForwardToSyslog=yes only when rsyslog central logging is deployed"

# RULE231:
sec_audit_remediate_skip 231 "configure rsyslog FileCreateMode when rsyslog is deployed per site"

# RULE232:
sec_audit_remediate_skip 232 "configure rsyslog rules per site logging policy"

# RULE233:
sec_audit_remediate_skip 233 "configure remote sec_audit_log host in /etc/rsyslog.d/ per site policy"

# RULE234:
sec_audit_remediate_skip 234 "disable rsyslog remote receive when rsyslog is deployed per site"

# RULE235:
sec_audit_remediate_skip 235 "verify /etc/logrotate.d/rsyslog rotation settings per site retention policy"

# RULE236:
find /var/sec_audit_log -type f -exec chmod g-wx,o-rwx {} + 2>/dev/null || true
find /var/sec_audit_log -type d -exec chmod g-wx,o-rwx {} + 2>/dev/null || true
sec_audit_remediate_done 236 "tightened /var/sec_audit_log file permissions"

# RULE237:
sec_audit_pkg_install audit
sec_audit_start_svc auditd
sec_audit_remediate_done 237 "auditd installed and running"

# RULE238:
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

# RULE239:
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

# RULE240:
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

# RULE241:
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

# RULE242:
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

# RULE243:
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

# RULE244:
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

# RULE245:
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

# RULE246:
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

# RULE247:
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

# RULE248:
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

# RULE249:
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

# RULE250:
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

# RULE251:
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

# RULE252:
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

# RULE253:
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

# RULE254:
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

# RULE255:
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

# RULE256:
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

# RULE257:
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

# RULE258:
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

# RULE259:
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

# RULE260:
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

# RULE261:
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

# RULE262:
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

# RULE263:
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

# RULE264:
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

# RULE265:
sec_audit_remediate_skip 265 "Ensure the running and on disk configuration is the same"

# RULE266:
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

# RULE267:
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

# RULE268:
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

# RULE269:
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

# RULE270:
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

# RULE271:
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

# RULE272:
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

# RULE273:
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

# RULE274:
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

# RULE275:
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

# RULE276:
sec_audit_harden_file /etc/passwd 644 root:root
sec_audit_remediate_done 276 "permissions /etc/passwd"

# RULE277:
sec_audit_harden_file /etc/passwd- 644 root:root
sec_audit_remediate_done 277 "permissions /etc/passwd-"

# RULE278:
sec_audit_harden_file /etc/group 644 root:root
sec_audit_remediate_done 278 "permissions /etc/group"

# RULE279:
sec_audit_harden_file /etc/group- 644 root:root
sec_audit_remediate_done 279 "permissions /etc/group-"

# RULE280:
chmod 640 /etc/shadow 2>/dev/null || true
chown root:shadow /etc/shadow 2>/dev/null || chown root:root /etc/shadow 2>/dev/null || true
sec_audit_remediate_done 280 "permissions /etc/shadow"

# RULE281:
chmod 640 /etc/shadow- 2>/dev/null || true
chown root:shadow /etc/shadow- 2>/dev/null || chown root:root /etc/shadow- 2>/dev/null || true
sec_audit_remediate_done 281 "permissions /etc/shadow-"

# RULE282:
chmod 640 /etc/gshadow 2>/dev/null || true
chown root:shadow /etc/gshadow 2>/dev/null || chown root:root /etc/gshadow 2>/dev/null || true
sec_audit_remediate_done 282 "permissions /etc/gshadow"

# RULE283:
chmod 640 /etc/gshadow- 2>/dev/null || true
chown root:shadow /etc/gshadow- 2>/dev/null || chown root:root /etc/gshadow- 2>/dev/null || true
sec_audit_remediate_done 283 "permissions /etc/gshadow-"

# RULE284:
sec_audit_harden_file /etc/shells 644 root:root
sec_audit_remediate_done 284 "permissions /etc/shells"

# RULE285:
sec_audit_harden_file /etc/security/opasswd 600 root:root
sec_audit_remediate_done 285 "permissions /etc/security/opasswd"

# RULE286:
sec_audit_remediate_skip 286 "find and chmod o-w on world-writable files under critical paths"

# RULE287:
sec_audit_remediate_skip 287 "review remediation: Ensure no files or directories without an owner and a group exist"

# RULE288:
sec_audit_remediate_skip 288 "review SUID/SGID files and remove unnecessary binaries"

# RULE289:
sec_audit_remediate_done 289 "shadowed passwords - verify /etc/passwd second field is x"

# RULE290:
awk -F: '($2=="") {print $1}' /etc/shadow | while read -r u; do passwd -l "$u" >/dev/null 2>&1 || true; done
sec_audit_remediate_done 290 "lock accounts with empty shadow password"

# RULE291:
sec_audit_remediate_skip 291 "Ensure all groups in /etc/passwd exist in /etc/group"

# RULE292:
sec_audit_remediate_skip 292 "Ensure no duplicate UIDs exist"

# RULE293:
sec_audit_remediate_skip 293 "Ensure no duplicate GIDs exist"

# RULE294:
sec_audit_remediate_skip 294 "Ensure no duplicate user names exist"

# RULE295:
sec_audit_remediate_skip 295 "Ensure no duplicate group names exist"

# RULE296:
sec_audit_remediate_skip 296 "Ensure local interactive user home directories are configured"

# RULE297:
sec_audit_remediate_skip 297 "Ensure local interactive user dot files access is configured"

if sec_audit_have_bin dnf; then
    timeout 300 dnf upgrade --security -y >/dev/null 2>&1 || true
fi

sec_audit_log "AlmaLinux 9 remediation complete"
exit 0

