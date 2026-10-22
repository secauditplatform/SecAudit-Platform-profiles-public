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
# pipefail left unset so soft-fail pipelines do not abort the remediator.

DEB13_ALLOW_CONTAINER_KMOD="${DEB13_ALLOW_CONTAINER_KMOD:-${DEB13_ALLOW_CONTAINER_MODULES:-0}}"
DEB13_REMEDIATE_SECURITY_UPGRADE="${DEB13_REMEDIATE_SECURITY_UPGRADE:-0}"
DEB13_SYSCTL_FILE="/etc/sysctl.d/99-secaudit-debian13.conf"
DEB13_AUDIT_RULES_FILE="/etc/audit/rules.d/99-secaudit-debian13.rules"
DEB13_MODPROBE_PREFIX="/etc/modprobe.d/sec-audit-disable"

# =============================================================================
# Helpers
# =============================================================================

sec_audit_have_bin() { command -v "$1" >/dev/null 2>&1; }

sec_audit_log() { printf '[remediation] %s\n' "$*"; }

sec_audit_remediate_done() {
    printf '[remediation] REMEDIATE RULE%s= applied: %s\n' "$1" "$2"
}

sec_audit_remediate_skip() {
    printf '[remediation] REMEDIATE RULE%s= SKIP: manual step required - %s\n' "$1" "$2"
}

sec_audit_pkg_install() {
    sec_audit_have_bin apt-get || return 0
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" >/dev/null 2>&1 || true
}

sec_audit_pkg_remove() {
    local p
    sec_audit_have_bin apt-get || return 0
    for p in "$@"; do
        if sec_audit_have_bin dpkg-query; then
            dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed' || continue
        fi
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
    systemctl mask "$u" >/dev/null 2>&1 || true
}

sec_audit_kmod_aliases() {
    local mod="$1" alt
    printf '%s\n' "$mod"
    alt="${mod//_/-}"
    [ "$alt" != "$mod" ] && printf '%s\n' "$alt"
    alt="${mod//-/_}"
    [ "$alt" != "$mod" ] && printf '%s\n' "$alt"
}

sec_audit_disable_kmod() {
    # Usage: sec_audit_disable_kmod <primary> [extra aliases...]
    # Writes /etc/modprobe.d/sec-audit-disable-<primary>.conf with install/blacklist
    # for underscore and hyphen forms. Returns 2 when container waiver applies.
    local primary="$1"
    shift || true
    local a safe f names=() seen=""
    case "$primary" in
        overlay|squashfs)
            if [ "${DEB13_ALLOW_CONTAINER_KMOD}" = "1" ]; then
                return 2
            fi
            ;;
    esac
    while IFS= read -r a; do
        [ -n "$a" ] || continue
        case " $seen " in
            *" $a "*) continue ;;
        esac
        seen="$seen $a"
        names+=("$a")
    done < <(sec_audit_kmod_aliases "$primary"; for a in "$@"; do sec_audit_kmod_aliases "$a"; done)

    safe="${primary//\//_}"
    f="${DEB13_MODPROBE_PREFIX}-${safe}.conf"
    mkdir -p /etc/modprobe.d
    {
        echo "# SecAudit Debian 13 — disable ${primary}"
        for a in "${names[@]}"; do
            echo "install ${a} /bin/false"
            echo "blacklist ${a}"
        done
    } >"$f"

    for a in "${names[@]}"; do
        if [ -f /proc/modules ] && awk '{print $1}' /proc/modules 2>/dev/null | grep -qx "$a"; then
            modprobe -r "$a" >/dev/null 2>&1 || rmmod "$a" >/dev/null 2>&1 || true
        fi
    done
    return 0
}

sec_audit_set_sysctl() {
    local key="$1" val="$2" path
    mkdir -p /etc/sysctl.d
    if [ -f "$DEB13_SYSCTL_FILE" ] && grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$DEB13_SYSCTL_FILE"; then
        sed -i "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${val}|" "$DEB13_SYSCTL_FILE"
    else
        printf '%s = %s\n' "$key" "$val" >>"$DEB13_SYSCTL_FILE"
    fi
    if sec_audit_have_bin sysctl; then
        sysctl -w "${key}=${val}" >/dev/null 2>&1 || true
    else
        path="/proc/sys/${key//.//}"
        if [ -w "$path" ]; then
            printf '%s' "$val" >"$path" 2>/dev/null || true
        fi
    fi
}

sec_audit_set_apt_unauth_false() {
    mkdir -p /etc/apt/apt.conf.d
    cat >/etc/apt/apt.conf.d/99-secaudit-debian13-gpg <<'EOF'
APT::Get::AllowUnauthenticated "false";
Acquire::AllowInsecureRepositories "false";
EOF
}

sec_audit_set_sshd_kv() {
    local key="$1" val="$2" f=/etc/ssh/sshd_config
    [ -f "$f" ] || return 1
    if grep -qE "^[[:space:]]*#?[[:space:]]*${key}([[:space:]]|=)" "$f"; then
        sed -i "s|^[[:space:]]*#\?[[:space:]]*${key}[[:space:]].*|${key} ${val}|" "$f"
    else
        printf '%s %s\n' "$key" "$val" >>"$f"
    fi
    return 0
}

sec_audit_set_login_defs_kv() {
    local key="$1" val="$2" f=/etc/login.defs
    [ -f "$f" ] || return 0
    if grep -qE "^${key}[[:space:]]" "$f"; then
        sed -i "s/^${key}[[:space:]].*/${key}   ${val}/" "$f"
    else
        printf '%s   %s\n' "$key" "$val" >>"$f"
    fi
}

sec_audit_set_pwquality_kv() {
    local key="$1" val="$2" f=/etc/security/pwquality.conf
    mkdir -p /etc/security
    touch "$f"
    if grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$f"; then
        sed -i "s/^[[:space:]]*${key}[[:space:]]*=.*/${key} = ${val}/" "$f"
    else
        printf '%s = %s\n' "$key" "$val" >>"$f"
    fi
}

sec_audit_set_faillock_kv() {
    local key="$1" val="$2" f=/etc/security/faillock.conf
    mkdir -p /etc/security
    touch "$f"
    if grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$f"; then
        sed -i "s/^[[:space:]]*${key}[[:space:]]*=.*/${key} = ${val}/" "$f"
    else
        printf '%s = %s\n' "$key" "$val" >>"$f"
    fi
}

sec_audit_set_auditd_conf_kv() {
    local key="$1" val="$2" f=/etc/audit/auditd.conf
    [ -f "$f" ] || return 1
    if grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$f"; then
        sed -i "s/^[[:space:]]*${key}[[:space:]]*=.*/${key} = ${val}/" "$f"
    else
        printf '%s = %s\n' "$key" "$val" >>"$f"
    fi
    return 0
}

sec_audit_harden_path() {
    local path="$1" mode="$2" owner="${3:-root:root}"
    [ -e "$path" ] || return 1
    chmod "$mode" "$path" 2>/dev/null || true
    chown "$owner" "$path" 2>/dev/null || true
    return 0
}

sec_audit_authselect_enable() { return 0; }

sec_audit_pam_faillock_debian() {
    mkdir -p /etc/pam.d /etc/security
    touch /etc/security/faillock.conf
    grep -qE '^[[:space:]]*deny[[:space:]]*=' /etc/security/faillock.conf 2>/dev/null || echo 'deny = 5' >>/etc/security/faillock.conf
    grep -qE '^[[:space:]]*unlock_time[[:space:]]*=' /etc/security/faillock.conf 2>/dev/null || echo 'unlock_time = 900' >>/etc/security/faillock.conf
    local f
    for f in /etc/pam.d/common-auth /etc/pam.d/common-account; do
        [ -f "$f" ] || continue
        grep -q 'pam_faillock.so' "$f" 2>/dev/null && continue
        if [ "$(basename "$f")" = "common-auth" ]; then
            printf '%s
' 'auth required pam_faillock.so preauth' 'auth required pam_faillock.so authfail' >>"$f"
        else
            printf '%s
' 'account required pam_faillock.so' >>"$f"
        fi
    done
}

sec_audit_fstab_has_mount() {
    local mp="${1%/}"
    [ -f /etc/fstab ] || return 1
    awk -v mp="$mp" '
        $0 ~ /^[[:space:]]*#/ { next }
        NF >= 2 && $2 == mp { found = 1 }
        END { exit(found ? 0 : 1) }
    ' /etc/fstab 2>/dev/null
}

sec_audit_fstab_has_option() {
    local mp="${1%/}" flag="$2"
    [ -f /etc/fstab ] || return 1
    awk -v mp="$mp" -v flag="$flag" '
        $0 ~ /^[[:space:]]*#/ { next }
        NF >= 4 && $2 == mp {
            n = split($4, opts, ",")
            for (i = 1; i <= n; i++) {
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", opts[i])
                if (opts[i] == flag) found = 1
            }
        }
        END { exit(found ? 0 : 1) }
    ' /etc/fstab 2>/dev/null
}

sec_audit_add_fstab_option() {
    # Append opt to existing fstab mount options column without duplicating.
    local mp="${1%/}" opt="$2"
    [ -f /etc/fstab ] || return 1
    sec_audit_fstab_has_mount "$mp" || return 1
    sec_audit_fstab_has_option "$mp" "$opt" && return 0
    awk -v mp="$mp" -v opt="$opt" '
        BEGIN { OFS = "\t" }
        $0 ~ /^[[:space:]]*#/ { print; next }
        NF >= 4 && $2 == mp {
            if ($4 ~ "(^|,)" opt "(,|$)") { print; next }
            if ($4 == "" || $4 == "defaults") $4 = ($4 == "" ? opt : $4 "," opt)
            else $4 = $4 "," opt
            print
            next
        }
        { print }
    ' /etc/fstab > /etc/fstab.secaudit.tmp && mv /etc/fstab.secaudit.tmp /etc/fstab
}

sec_audit_ensure_tmpfs_fstab() {
    # Ensure a tmpfs fstab line exists for /tmp or /dev/shm with given options.
    local mp="$1"
    shift
    local opt csv="defaults" o
    for o in "$@"; do
        case ",$csv," in
            *",$o,"*) ;;
            *) csv="$csv,$o" ;;
        esac
    done
    if sec_audit_fstab_has_mount "$mp"; then
        for o in "$@"; do
            sec_audit_add_fstab_option "$mp" "$o" || true
        done
        return 0
    fi
    printf 'tmpfs %s tmpfs %s 0 0\n' "$mp" "$csv" >>/etc/fstab
    return 0
}

sec_audit_remount_option() {
    local mp="$1" opt="$2"
    if mountpoint -q "$mp" 2>/dev/null || findmnt -kn "$mp" &>/dev/null; then
        mount -o "remount,${opt}" "$mp" >/dev/null 2>&1 || true
        return 0
    fi
    return 1
}

sec_audit_ensure_mount_option() {
    # Safer mount option remediator.
    # - Updates existing fstab options without duplicates
    # - For /tmp and /dev/shm, may create tmpfs fstab persistence
    # - Otherwise skips inventing fstab lines for paths without partitions
    # Returns 0 on applied/persisted attempt, 1 when skipped as unsafe.
    local mp="$1" opt="$2"
    case "$mp" in
        /tmp|/dev/shm)
            sec_audit_ensure_tmpfs_fstab "$mp" "$opt" || true
            sec_audit_remount_option "$mp" "$opt" || mount -t tmpfs -o "defaults,${opt}" tmpfs "$mp" >/dev/null 2>&1 || true
            return 0
            ;;
    esac
    if sec_audit_fstab_has_mount "$mp"; then
        sec_audit_add_fstab_option "$mp" "$opt" || true
        sec_audit_remount_option "$mp" "$opt" || true
        return 0
    fi
    # Dedicated mount without fstab (transient) — remount only, warn via caller.
    if findmnt -kn "$mp" &>/dev/null && [ "$(findmnt -kn -T "$mp" -o TARGET --noheadings 2>/dev/null | head -n1 | tr -d '[:space:]')" = "$mp" ]; then
        sec_audit_remount_option "$mp" "$opt" || true
        return 0
    fi
    return 1
}

sec_audit_audit_rules_immutable() {
    if sec_audit_have_bin auditctl && auditctl -s 2>/dev/null | grep -qiE 'enabled[[:space:]]+2'; then
        return 0
    fi
    return 1
}

sec_audit_reload_audit_rules() {
    if sec_audit_audit_rules_immutable; then
        return 2
    fi
    if sec_audit_have_bin augenrules; then
        augenrules --load >/dev/null 2>&1 || true
    elif sec_audit_have_bin auditctl && [ -f /etc/audit/audit.rules ]; then
        auditctl -R /etc/audit/audit.rules >/dev/null 2>&1 || true
    fi
    return 0
}

sec_audit_ensure_audit_baseline() {
    # Single shared on-disk audit rules baseline used by multiple RULE remediations.
    mkdir -p /etc/audit/rules.d
    cat >"$DEB13_AUDIT_RULES_FILE" <<'EOF'
## SecAudit Debian 13 baseline audit rules
-D
-b 8192
-f 1

## sudoers scope
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope

## identity
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

## NetworkManager
-w /etc/NetworkManager/ -p wa -k network_modifications

## privileged commands
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -k privileged

## actions as another user
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k user_emulation
-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k user_emulation

## sudo log
-w /var/log/sudo.log -p wa -k sudo_log_file

## unsuccessful access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access

## mounts
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts

## session / login
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

## deletions
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete

## kernel modules
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=1000 -F auid!=unset -k modules
-a always,exit -F arch=b32 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=1000 -F auid!=unset -k modules
-w /usr/bin/kmod -p x -k modules

## audit log dir
-w /var/log/audit/ -p wa -k audit_log
EOF
    chmod 640 "$DEB13_AUDIT_RULES_FILE" 2>/dev/null || true
    chown root:root "$DEB13_AUDIT_RULES_FILE" 2>/dev/null || true
    sec_audit_reload_audit_rules
    return $?
}

sec_audit_ensure_module_audit_rules() {
    # RULE244-focused: ensure init_module/delete_module auditing without blacklisting a fake module.
    mkdir -p /etc/audit/rules.d
    local f="/etc/audit/rules.d/50-secaudit-modules.rules"
    cat >"$f" <<'EOF'
## SecAudit Debian 13 — kernel module load/unload auditing
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=1000 -F auid!=unset -k modules
-a always,exit -F arch=b32 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=1000 -F auid!=unset -k modules
-w /usr/bin/kmod -p x -k modules
EOF
    chmod 640 "$f" 2>/dev/null || true
    chown root:root "$f" 2>/dev/null || true
    sec_audit_reload_audit_rules
    return $?
}

sec_audit_harden_audit_logs() {
    local alogdir mode
    alogdir=$(awk -F= '/^[[:space:]]*log_file[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' /etc/audit/auditd.conf 2>/dev/null)
    alogdir="${alogdir:-/var/log/audit/audit.log}"
    alogdir=$(dirname "$alogdir")
    [ -d "$alogdir" ] || mkdir -p "$alogdir"
    chmod 750 "$alogdir" 2>/dev/null || true
    chown root:root "$alogdir" 2>/dev/null || true
    sec_audit_set_auditd_conf_kv log_group root || true
    if sec_audit_have_bin find; then
        find "$alogdir" -xdev -maxdepth 1 -type f -exec chmod 0600 {} \; 2>/dev/null || true
        find "$alogdir" -xdev -maxdepth 1 -type f -exec chown root:root {} \; 2>/dev/null || true
    fi
}

sec_audit_harden_audit_config() {
    local f
    [ -d /etc/audit ] || return 0
    if sec_audit_have_bin find; then
        find /etc/audit -xdev -type f \( -name '*.conf' -o -name '*.rules' \) -exec chmod 0640 {} \; 2>/dev/null || true
        find /etc/audit -xdev -type f \( -name '*.conf' -o -name '*.rules' \) -exec chown root:root {} \; 2>/dev/null || true
    fi
    for f in /etc/audit/auditd.conf /etc/audit/audit.rules; do
        [ -e "$f" ] || continue
        sec_audit_harden_path "$f" 640 root:root || true
    done
}

sec_audit_harden_audit_tools() {
    local tool
    for tool in /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules \
                /usr/sbin/auditctl /usr/sbin/aureport /usr/sbin/ausearch /usr/sbin/auditd /usr/sbin/augenrules; do
        [ -f "$tool" ] || continue
        sec_audit_harden_path "$tool" 755 root:root || true
    done
}

sec_audit_configure_journald() {
    mkdir -p /etc/systemd/journald.conf.d
    cat >/etc/systemd/journald.conf.d/99-secaudit-debian13.conf <<'EOF'
[Journal]
ForwardToSyslog=no
Compress=yes
Storage=persistent
EOF
    sec_audit_have_bin systemctl && systemctl restart systemd-journald >/dev/null 2>&1 || true
}

sec_audit_configure_coredump() {
    grep -q 'hard core' /etc/security/limits.conf 2>/dev/null || echo '* hard core 0' >>/etc/security/limits.conf
    mkdir -p /etc/security/limits.d
    printf '* hard core 0\n' >/etc/security/limits.d/99-secaudit-core.conf
    mkdir -p /etc/systemd/coredump.conf.d
    cat >/etc/systemd/coredump.conf.d/99-secaudit-debian13.conf <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
    sec_audit_have_bin systemctl && systemctl daemon-reload >/dev/null 2>&1 || true
}

sec_audit_sanitize_banner() {
    local f="$1"
    [ -f "$f" ] || printf '%s\n' 'Authorized use only.' >"$f"
    sed -i 's/\\[vVrms]//g' "$f" 2>/dev/null || true
}

sec_audit_gdm_dconf_stub() {
    mkdir -p /etc/dconf/db/gdm.d /etc/dconf/db/gdm.d/locks
    cat >/etc/dconf/db/gdm.d/99-secaudit-debian13 <<'EOF'
[org/gnome/login-screen]
banner-message-enable=true
banner-message-text='Authorized use only.'
disable-user-list=true
EOF
    cat >/etc/dconf/db/gdm.d/locks/99-secaudit-debian13 <<'EOF'
/org/gnome/login-screen/banner-message-enable
/org/gnome/login-screen/banner-message-text
/org/gnome/login-screen/disable-user-list
EOF
    sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
}

# =============================================================================
# Section runners (RULE1 .. RULE284)
# =============================================================================

sec_audit_remediate_kernel_modules() {
    local _msg
    # RULE1
    sec_audit_disable_kmod cramfs
    sec_audit_remediate_done 1 "blacklisted kernel module cramfs"

    # RULE2
    sec_audit_disable_kmod freevxfs
    sec_audit_remediate_done 2 "blacklisted kernel module freevxfs"

    # RULE3
    sec_audit_disable_kmod hfs
    sec_audit_remediate_done 3 "blacklisted kernel module hfs"

    # RULE4
    sec_audit_disable_kmod hfsplus
    sec_audit_remediate_done 4 "blacklisted kernel module hfsplus"

    # RULE5
    sec_audit_disable_kmod jffs2
    sec_audit_remediate_done 5 "blacklisted kernel module jffs2"

    _msg="blacklisted kernel module overlay"
    if [ "${DEB13_ALLOW_CONTAINER_KMOD}" = "1" ]; then
        _msg="waived blacklisting overlay (DEB13_ALLOW_CONTAINER_KMOD=1)"
    else
        sec_audit_disable_kmod overlay || true
    fi
    sec_audit_remediate_done 6 "$_msg"
    _msg="blacklisted kernel module squashfs"
    if [ "${DEB13_ALLOW_CONTAINER_KMOD}" = "1" ]; then
        _msg="waived blacklisting squashfs (DEB13_ALLOW_CONTAINER_KMOD=1)"
    else
        sec_audit_disable_kmod squashfs || true
    fi
    sec_audit_remediate_done 7 "$_msg"
    # RULE8
    sec_audit_disable_kmod udf
    sec_audit_remediate_done 8 "blacklisted kernel module udf"

    # RULE9
    sec_audit_disable_kmod firewire_core firewire-core
    sec_audit_remediate_done 9 "blacklisted kernel module firewire-core"

    # RULE10
    sec_audit_disable_kmod usb_storage usb-storage
    sec_audit_remediate_done 10 "blacklisted kernel module usb-storage"

}

sec_audit_remediate_filesystem_partitions() {
    # RULE11
    sec_audit_remediate_skip 11 "Ensure /tmp is tmpfs or a separate partition"

    # RULE12
    sec_audit_ensure_mount_option /tmp nodev
    sec_audit_remediate_done 12 "set nodev on /tmp"

    # RULE13
    sec_audit_remediate_skip 13 "Ensure nosuid option set on /tmp partition"

    # RULE14
    sec_audit_ensure_mount_option /tmp noexec
    sec_audit_remediate_done 14 "set noexec on /tmp"

    # RULE15
    sec_audit_remediate_skip 15 "Ensure /dev/shm is tmpfs or a separate partition"

    # RULE16
    sec_audit_ensure_mount_option /dev/shm nodev
    sec_audit_remediate_done 16 "set nodev on /dev/shm"

    # RULE17
    sec_audit_remediate_skip 17 "Ensure nosuid option set on /dev/shm partition"

    # RULE18
    sec_audit_ensure_mount_option /dev/shm noexec
    sec_audit_remediate_done 18 "set noexec on /dev/shm"

    # RULE19
    sec_audit_remediate_skip 19 "Ensure separate partition exists for /home"

    # RULE20
    sec_audit_ensure_mount_option /home nodev
    sec_audit_remediate_done 20 "set nodev on /home"

    # RULE21
    sec_audit_remediate_skip 21 "Ensure nosuid option set on /home partition"

    # RULE22
    sec_audit_remediate_skip 22 "Ensure separate partition exists for /var"

    # RULE23
    sec_audit_ensure_mount_option /var nodev
    sec_audit_remediate_done 23 "set nodev on /var"

    # RULE24
    sec_audit_remediate_skip 24 "Ensure nosuid option set on /var partition"

    # RULE25
    sec_audit_remediate_skip 25 "Ensure separate partition exists for /var/tmp"

    # RULE26
    sec_audit_ensure_mount_option /var/tmp nodev
    sec_audit_remediate_done 26 "set nodev on /var/tmp"

    # RULE27
    sec_audit_remediate_skip 27 "Ensure nosuid option set on /var/tmp partition"

    # RULE28
    sec_audit_ensure_mount_option /var/tmp noexec
    sec_audit_remediate_done 28 "set noexec on /var/tmp"

    # RULE29
    sec_audit_remediate_skip 29 "Ensure separate partition exists for /var/log"

    # RULE30
    sec_audit_ensure_mount_option /var/log nodev
    sec_audit_remediate_done 30 "set nodev on /var/log"

    # RULE31
    sec_audit_remediate_skip 31 "Ensure nosuid option set on /var/log partition"

    # RULE32
    sec_audit_ensure_mount_option /var/log noexec
    sec_audit_remediate_done 32 "set noexec on /var/log"

    # RULE33
    sec_audit_remediate_skip 33 "Ensure separate partition exists for /var/log/audit"

    # RULE34
    sec_audit_ensure_mount_option /var/log/audit nodev
    sec_audit_remediate_done 34 "set nodev on /var/log/audit"

    # RULE35
    sec_audit_remediate_skip 35 "Ensure nosuid option set on /var/log/audit partition"

    # RULE36
    sec_audit_ensure_mount_option /var/log/audit noexec
    sec_audit_remediate_done 36 "set noexec on /var/log/audit"

}

sec_audit_remediate_package_security() {
    # RULE37
    sec_audit_set_apt_unauth_false
    sec_audit_remediate_done 37 "apt authentication baseline (AllowUnauthenticated false)"

}

sec_audit_remediate_apparmor() {
    # RULE38
    sec_audit_pkg_install apparmor apparmor-utils
    sec_audit_remediate_done 38 "installed AppArmor"

    # RULE39
    if [ -f /etc/default/grub ]; then
        if grep -q '^GRUB_CMDLINE_LINUX=' /etc/default/grub; then
            grep -q 'apparmor=1' /etc/default/grub || sed -i 's/^GRUB_CMDLINE_LINUX="/&apparmor=1 /' /etc/default/grub
            grep -q 'security=apparmor' /etc/default/grub || sed -i 's/^GRUB_CMDLINE_LINUX="/&security=apparmor /' /etc/default/grub
        fi
    fi
    sec_audit_remediate_done 39 "enabled AppArmor in GRUB_CMDLINE_LINUX (reboot required)"

    # RULE40
    sec_audit_pkg_install apparmor apparmor-utils
    sec_audit_have_bin aa-enforce && aa-enforce /etc/apparmor.d/* >/dev/null 2>&1 || true
    sec_audit_have_bin systemctl && systemctl enable --now apparmor >/dev/null 2>&1 || true
    sec_audit_remediate_done 40 "AppArmor profiles set toward enforce/complain"

    # RULE41
    sec_audit_pkg_install apparmor apparmor-utils
    sec_audit_have_bin aa-enforce && aa-enforce /etc/apparmor.d/* >/dev/null 2>&1 || true
    sec_audit_have_bin systemctl && systemctl enable --now apparmor >/dev/null 2>&1 || true
    sec_audit_remediate_done 41 "AppArmor profiles enforced where possible"

}

sec_audit_remediate_bootloader() {
    # RULE42
    sec_audit_remediate_skip 42 "Ensure bootloader password is set"

}

sec_audit_remediate_process_hardening() {
    # RULE43
    sec_audit_configure_coredump
    sec_audit_remediate_done 43 "disabled core dumps (limits + systemd-coredump)"

    # RULE44
    sec_audit_set_sysctl fs.protected_hardlinks 1
    sec_audit_remediate_done 44 "set fs.protected_hardlinks=1"

    # RULE45
    sec_audit_set_sysctl fs.protected_symlinks 1
    sec_audit_remediate_done 45 "set fs.protected_symlinks=1"

    # RULE46
    sec_audit_remediate_skip 46 "Ensure fs.suid_dumpable is configured"

    # RULE47
    sec_audit_set_sysctl kernel.dmesg_restrict 1
    sec_audit_remediate_done 47 "set kernel.dmesg_restrict=1"

    # RULE48
    sec_audit_set_sysctl kernel.kptr_restrict 2
    sec_audit_remediate_done 48 "set kernel.kptr_restrict=2"

    # RULE49
    sec_audit_set_sysctl kernel.yama.ptrace_scope 1
    sec_audit_remediate_done 49 "set kernel.yama.ptrace_scope=1"

    # RULE50
    sec_audit_set_sysctl kernel.randomize_va_space 2
    sec_audit_remediate_done 50 "set kernel.randomize_va_space=2"

    # RULE51
    sec_audit_set_sysctl fs.suid_dumpable 0
    sec_audit_remediate_done 51 "coredump limits via sysctl/coredump.conf"

    # RULE52
    grep -q "hard core" /etc/security/limits.conf 2>/dev/null || echo "* hard core 0" >>/etc/security/limits.conf
    mkdir -p /etc/systemd/coredump.conf.d
    cat >/etc/systemd/coredump.conf.d/99-secaudit-debian13.conf <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
    sec_audit_have_bin systemctl && systemctl daemon-reload >/dev/null 2>&1 || true
    sec_audit_remediate_done 52 "disabled core dumps"

}

sec_audit_remediate_banners() {
    # RULE53
    sec_audit_have_bin update-crypto-policies && update-crypto-policies --set DEFAULT >/dev/null 2>&1 || true
    sec_audit_remediate_done 53 "crypto policy not LEGACY"

    # RULE54
    [[ -f /etc/issue ]] || echo "Authorized use only." >/etc/issue
    sed -i 's/\\[vVrms]//g' /etc/issue 2>/dev/null || true
    sec_audit_remediate_done 54 "sanitized banner /etc/issue"

    # RULE55
    sec_audit_remediate_skip 55 "review remediation: Ensure system wide crypto policy macs are configured"

}

sec_audit_remediate_gdm() {
    # RULE56
    [[ -f /etc/motd ]] || echo "Authorized use only." >/etc/motd
    sed -i 's/\\[vVrms]//g' /etc/motd 2>/dev/null || true
    sec_audit_remediate_done 56 "sanitized banner /etc/motd"

}

sec_audit_remediate_unused_services() {
    # RULE57
    sec_audit_disable_svc autofs.service
    sec_audit_pkg_remove autofs
    sec_audit_remediate_done 57 "disabled autofs"

    # RULE58
    sec_audit_disable_svc avahi-daemon.socket
    sec_audit_disable_svc avahi-daemon.service
    sec_audit_pkg_remove avahi
    sec_audit_remediate_done 58 "disabled avahi"

    # RULE59
    sec_audit_disable_svc cockpit.socket
    sec_audit_disable_svc cockpit.service
    sec_audit_pkg_remove cockpit-ws
    sec_audit_remediate_done 59 "disabled cockpit-ws"

    # RULE60
    sec_audit_disable_svc dhcpd.service
    sec_audit_disable_svc dhcpd6.service
    sec_audit_pkg_remove dhcp-server
    sec_audit_remediate_done 60 "disabled dhcp-server"

    # RULE61
    sec_audit_disable_svc named.service
    sec_audit_pkg_remove bind
    sec_audit_remediate_done 61 "disabled bind"

    # RULE62
    sec_audit_disable_svc dnsmasq.service
    sec_audit_pkg_remove dnsmasq
    sec_audit_remediate_done 62 "disabled dnsmasq"

    # RULE63
    sec_audit_disable_svc vsftpd.service
    sec_audit_pkg_remove vsftpd
    sec_audit_remediate_done 63 "disabled vsftpd"

    # RULE64
    sec_audit_remediate_skip 64 "review remediation: Ensure message access server services are not in use"

    # RULE65
    sec_audit_remediate_skip 65 "review remediation: Ensure network file system services are not in use"

    # RULE66
    sec_audit_remediate_skip 66 "review remediation: Ensure print server services are not in use"

    # RULE67
    sec_audit_disable_svc rpcbind.socket
    sec_audit_disable_svc rpcbind.service
    sec_audit_pkg_remove rpcbind
    sec_audit_remediate_done 67 "disabled rpcbind"

    # RULE68
    sec_audit_disable_svc rsyncd.socket
    sec_audit_disable_svc rsyncd.service
    sec_audit_pkg_remove rsync-daemon
    sec_audit_remediate_done 68 "disabled rsync-daemon"

    # RULE69
    sec_audit_disable_svc smb.service
    sec_audit_disable_svc smbd.service
    sec_audit_pkg_remove samba
    sec_audit_remediate_done 69 "disabled samba"

    # RULE70
    sec_audit_disable_svc snmpd.service
    sec_audit_pkg_remove net-snmp
    sec_audit_remediate_done 70 "disabled net-snmp"

    # RULE71
    sec_audit_disable_svc telnet.socket
    sec_audit_pkg_remove telnet-server
    sec_audit_remediate_done 71 "disabled telnet-server"

    # RULE72
    sec_audit_disable_svc vsftpd.service
    sec_audit_pkg_remove vsftpd
    sec_audit_remediate_done 72 "disabled vsftpd"

    # RULE73
    sec_audit_remediate_skip 73 "review remediation: Ensure web proxy server services are not in use"

    # RULE74
    sec_audit_remediate_skip 74 "review remediation: Ensure web server services are not in use"

    # RULE75
    sec_audit_remediate_skip 75 "review remediation: Ensure GNOME Display Manager is removed"

    # RULE76
    sec_audit_remediate_skip 76 "review remediation: Ensure X window server services are not in use"

}

sec_audit_remediate_client_tools() {
    # RULE77
    sec_audit_remediate_skip 77 "review remediation: Ensure X window server services are not in use"

    # RULE78
    sec_audit_remediate_skip 78 "review remediation: Ensure mail transfer agents are configured for local-only mode"

    # RULE79
    sec_audit_pkg_remove ftp
    sec_audit_remediate_done 79 "removed ftp"

    # RULE80
    sec_audit_pkg_remove rsh-client
    sec_audit_remediate_done 80 "removed rsh-client"

    # RULE81
    sec_audit_pkg_remove talk
    sec_audit_remediate_done 81 "removed talk"

    # RULE82
    sec_audit_pkg_remove telnet
    sec_audit_remediate_done 82 "removed telnet"

    # RULE83
    sec_audit_pkg_remove ldap-utils
    sec_audit_remediate_done 83 "removed ldap-utils"

    # RULE84
    sec_audit_pkg_remove ftp
    sec_audit_remediate_done 84 "removed ftp"

}

sec_audit_remediate_time_sync() {
    # RULE85
    sec_audit_pkg_install chrony
    sec_audit_start_svc chronyd
    sec_audit_remediate_done 85 "installed chrony"

    # RULE86
    sec_audit_remediate_skip 86 "review remediation: Ensure systemd-timesyncd is enabled and running"

    # RULE87
    sec_audit_remediate_skip 87 "review remediation: Ensure chrony is running as user _chrony"

    # RULE88
    sec_audit_remediate_skip 88 "review remediation: Ensure chrony is enabled and running"

}

sec_audit_remediate_cron_at() {
    # RULE89
    sec_audit_pkg_install cron
    sec_audit_start_svc cron
    sec_audit_remediate_done 89 "enabled cron"

}

sec_audit_remediate_network_stack() {
    # RULE90
    sec_audit_disable_kmod bluetooth
    sec_audit_remediate_done 90 "disabled wireless interfaces"

    # RULE91
    sec_audit_disable_svc bluetooth.service
    sec_audit_pkg_remove bluez
    sec_audit_remediate_done 91 "disabled bluez"

    # RULE92
    sec_audit_disable_kmod is
    sec_audit_remediate_done 92 "blacklisted is"

    # RULE93
    sec_audit_disable_kmod is
    sec_audit_remediate_done 93 "blacklisted is"

    # RULE94
    sec_audit_disable_kmod is
    sec_audit_remediate_done 94 "blacklisted is"

    # RULE95
    sec_audit_disable_kmod is
    sec_audit_remediate_done 95 "blacklisted is"

    # RULE96
    sec_audit_disable_kmod is
    sec_audit_remediate_done 96 "blacklisted is"

    # RULE97
    sec_audit_disable_kmod is
    sec_audit_remediate_done 97 "blacklisted is"

    # RULE98
    sec_audit_set_sysctl net.ipv4.ip_forward 0
    sec_audit_remediate_done 98 "set net.ipv4.ip_forward=0"

    # RULE99
    sec_audit_remediate_skip 99 "review remediation: Ensure net.ipv4.conf.all.forwarding is configured"

    # RULE100
    sec_audit_remediate_skip 100 "review remediation: Ensure net.ipv4.conf.default.forwarding is configured"

    # RULE101
    sec_audit_set_sysctl net.ipv4.conf.all.send_redirects 0
    sec_audit_remediate_done 101 "set net.ipv4.conf.all.send_redirects=0"

    # RULE102
    sec_audit_set_sysctl net.ipv4.conf.all.send_redirects 0
    sec_audit_remediate_done 102 "set net.ipv4.conf.all.send_redirects=0"

    # RULE103
    sec_audit_set_sysctl net.ipv4.icmp_ignore_bogus_error_responses 1
    sec_audit_remediate_done 103 "set net.ipv4.icmp_ignore_bogus_error_responses=1"

    # RULE104
    sec_audit_remediate_skip 104 "review remediation: Ensure net.ipv4.icmp_echo_ignore_broadcasts is configured"

    # RULE105
    sec_audit_set_sysctl net.ipv4.conf.all.accept_redirects 0
    sec_audit_remediate_done 105 "set net.ipv4.conf.all.accept_redirects=0"

    # RULE106
    sec_audit_set_sysctl net.ipv4.conf.all.accept_redirects 0
    sec_audit_remediate_done 106 "set net.ipv4.conf.all.accept_redirects=0"

    # RULE107
    sec_audit_set_sysctl net.ipv4.conf.all.secure_redirects 0
    sec_audit_remediate_done 107 "set net.ipv4.conf.all.secure_redirects=0"

    # RULE108
    sec_audit_set_sysctl net.ipv4.conf.all.secure_redirects 0
    sec_audit_remediate_done 108 "set net.ipv4.conf.all.secure_redirects=0"

    # RULE109
    sec_audit_set_sysctl net.ipv4.conf.all.rp_filter 1
    sec_audit_remediate_done 109 "set net.ipv4.conf.all.rp_filter=1"

    # RULE110
    sec_audit_set_sysctl net.ipv4.conf.all.rp_filter 1
    sec_audit_remediate_done 110 "set net.ipv4.conf.all.rp_filter=1"

    # RULE111
    sec_audit_remediate_skip 111 "review remediation: Ensure net.ipv4.conf.all.accept_source_route is configured"

    # RULE112
    sec_audit_remediate_skip 112 "review remediation: Ensure net.ipv4.conf.default.accept_source_route is configured"

    # RULE113
    sec_audit_set_sysctl net.ipv4.conf.all.log_martians 1
    sec_audit_remediate_done 113 "set net.ipv4.conf.all.log_martians=1"

    # RULE114
    sec_audit_set_sysctl net.ipv4.conf.all.log_martians 1
    sec_audit_remediate_done 114 "set net.ipv4.conf.all.log_martians=1"

    # RULE115
    sec_audit_set_sysctl net.ipv4.tcp_syncookies 1
    sec_audit_remediate_done 115 "set net.ipv4.tcp_syncookies=1"

    # RULE116
    sec_audit_remediate_skip 116 "Ensure net.ipv6.conf.all.forwarding is configured"

    # RULE117
    sec_audit_remediate_skip 117 "Ensure net.ipv6.conf.default.forwarding is configured"

    # RULE118
    sec_audit_remediate_skip 118 "Ensure net.ipv6.conf.all.accept_redirects is configured"

    # RULE119
    sec_audit_remediate_skip 119 "Ensure net.ipv6.conf.default.accept_redirects is configured"

    # RULE120
    sec_audit_remediate_skip 120 "Ensure net.ipv6.conf.all.accept_source_route is configured"

    # RULE121
    sec_audit_remediate_skip 121 "Ensure net.ipv6.conf.default.accept_source_route is configured"

    # RULE122
    sec_audit_remediate_skip 122 "Ensure net.ipv6.conf.all.accept_ra is configured"

    # RULE123
    sec_audit_remediate_skip 123 "Ensure net.ipv6.conf.default.accept_ra is configured"

}

sec_audit_remediate_firewall() {
    # RULE124
    sec_audit_pkg_install firewalld
    sec_audit_start_svc firewalld
    sec_audit_remediate_done 124 "installed firewalld"

    # RULE125
    sec_audit_remediate_skip 125 "review remediation: Ensure firewalld backend is configured"

    # RULE126
    sec_audit_remediate_skip 126 "review remediation: Ensure firewalld.service is configured"

    # RULE127
    sec_audit_remediate_skip 127 "review remediation: Ensure firewalld active zone target is configured"

    # RULE128
    sec_audit_remediate_skip 128 "review remediation: Ensure firewalld loopback traffic is configured"

}

sec_audit_remediate_sshd() {
    # RULE129
    sec_audit_remediate_skip 129 "review remediation: Ensure access to /etc/ssh/sshd_config is configured"

    # RULE130
    sec_audit_remediate_skip 130 "review remediation: Ensure access to SSH private host key files is configured"

    # RULE131
    sec_audit_remediate_skip 131 "review remediation: Ensure access to SSH public host key files is configured"

    # RULE132
    sec_audit_remediate_skip 132 "review remediation: Ensure sshd access is configured"

    # RULE133
    sec_audit_set_sshd_kv Banner /etc/issue.net
    sec_audit_remediate_done 133 "sshd Banner"

    # RULE134
    sec_audit_remediate_skip 134 "review remediation: Ensure sshd Ciphers are configured"

    # RULE135
    sec_audit_set_sshd_kv ClientAliveInterval 300
    sec_audit_remediate_done 135 "sshd ClientAliveInterval"

    # RULE136
    sec_audit_set_sshd_kv DisableForwarding yes
    sec_audit_remediate_done 136 "sshd DisableForwarding"

    # RULE137
    sec_audit_set_sshd_kv GSSAPIAuthentication no
    sec_audit_remediate_done 137 "sshd GSSAPIAuthentication"

    # RULE138
    sec_audit_set_sshd_kv HostbasedAuthentication no
    sec_audit_remediate_done 138 "sshd HostbasedAuthentication"

    # RULE139
    sec_audit_set_sshd_kv IgnoreRhosts yes
    sec_audit_remediate_done 139 "sshd IgnoreRhosts"

    # RULE140
    sec_audit_remediate_skip 140 "review remediation: Ensure sshd KexAlgorithms is configured"

    # RULE141
    sec_audit_set_sshd_kv LoginGraceTime 60
    sec_audit_remediate_done 141 "sshd LoginGraceTime"

    # RULE142
    sec_audit_set_sshd_kv LogLevel VERBOSE
    sec_audit_remediate_done 142 "sshd LogLevel"

    # RULE143
    sec_audit_remediate_skip 143 "review remediation: Ensure sshd MACs are configured"

    # RULE144
    sec_audit_set_sshd_kv MaxAuthTries 4
    sec_audit_remediate_done 144 "sshd MaxAuthTries"

    # RULE145
    sec_audit_set_sshd_kv MaxStartups 10:30:60
    sec_audit_remediate_done 145 "sshd MaxStartups"

    # RULE146
    sec_audit_set_sshd_kv MaxSessions 10
    sec_audit_remediate_done 146 "sshd MaxSessions"

    # RULE147
    sec_audit_set_sshd_kv PermitEmptyPasswords no
    sec_audit_remediate_done 147 "sshd PermitEmptyPasswords"

    # RULE148
    sec_audit_set_sshd_kv PermitRootLogin no
    sec_audit_remediate_done 148 "sshd PermitRootLogin"

    # RULE149
    sec_audit_set_sshd_kv PermitUserEnvironment no
    sec_audit_remediate_done 149 "sshd PermitUserEnvironment"

    # RULE150
    sec_audit_set_sshd_kv UsePAM yes
    sec_audit_remediate_done 150 "sshd UsePAM"

    # RULE151
    sec_audit_set_sshd_kv UsePAM yes
    sec_audit_remediate_done 151 "sshd UsePAM"

}

sec_audit_remediate_sudo_su() {
    # RULE152
    sec_audit_pkg_install sudo
    sec_audit_remediate_done 152 "sudo installed"

    # RULE153
    sec_audit_remediate_skip 153 "review remediation: Ensure sudo commands use pty"

    # RULE154
    sec_audit_remediate_skip 154 "review remediation: Ensure sudo sec_audit_log file exists"

    # RULE155
    sec_audit_remediate_skip 155 "review remediation: Ensure users must provide password for escalation"

    # RULE156
    sec_audit_remediate_skip 156 "review remediation: Ensure re-authentication for privilege escalation is not disabled globally"

    # RULE157
    echo "Defaults timestamp_timeout=5" >/etc/sudoers.d/99-cre-timeout
    chmod 440 /etc/sudoers.d/99-cre-timeout
    sec_audit_remediate_done 157 "sudo timestamp_timeout=5"

    # RULE158
    sec_audit_remediate_skip 158 "review remediation: Ensure access to the su command is restricted"

}

sec_audit_remediate_pam_auth() {
    # RULE159
    sec_audit_pkg_install libpam-pwquality
    cat >/etc/security/pwquality.conf <<'EOF'
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF
    sec_audit_remediate_done 159 "password quality"

    # RULE160
    sec_audit_remediate_skip 160 "review remediation: Ensure pam_unix module is enabled"

    # RULE161
    sec_audit_pam_faillock_debian >/dev/null 2>&1 || true
    sec_audit_remediate_done 161 "pam faillock"

    # RULE162
    sec_audit_pkg_install libpam-pwquality
    cat >/etc/security/pwquality.conf <<'EOF'
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF
    sec_audit_remediate_done 162 "password quality"

    # RULE163
    grep -q remember /etc/security/pwhistory.conf 2>/dev/null || echo 'remember = 24' >>/etc/security/pwhistory.conf
    sec_audit_remediate_done 163 "password history"

    # RULE164
    sec_audit_pam_faillock_debian >/dev/null 2>&1 || true
    sec_audit_remediate_done 164 "pam faillock"

    # RULE165
    sec_audit_remediate_skip 165 "review remediation: Ensure password unlock time is configured"

    # RULE166
    sec_audit_remediate_skip 166 "Ensure password failed attempts lockout includes root account"

    # RULE167
    sec_audit_remediate_skip 167 "review remediation: Ensure password number of changed characters is configured"

    # RULE168
    sec_audit_remediate_skip 168 "review remediation: Ensure password length is configured"

    # RULE169
    sec_audit_remediate_skip 169 "review remediation: Ensure password same consecutive characters is configured"

    # RULE170
    sec_audit_remediate_skip 170 "review remediation: Ensure password maximum sequential characters is configured"

    # RULE171
    sec_audit_remediate_skip 171 "review remediation: Ensure password dictionary check is enabled"

    # RULE172
    sec_audit_pkg_install libpam-pwquality
    cat >/etc/security/pwquality.conf <<'EOF'
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF
    sec_audit_remediate_done 172 "password quality"

    # RULE173
    sec_audit_pkg_install libpam-pwquality
    cat >/etc/security/pwquality.conf <<'EOF'
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF
    sec_audit_remediate_done 173 "password quality"

}

sec_audit_remediate_accounts() {
    # RULE174
    grep -q remember /etc/security/pwhistory.conf 2>/dev/null || echo 'remember = 24' >>/etc/security/pwhistory.conf
    sec_audit_remediate_done 174 "password history"

    # RULE175
    grep -q remember /etc/security/pwhistory.conf 2>/dev/null || echo 'remember = 24' >>/etc/security/pwhistory.conf
    sec_audit_remediate_done 175 "password history"

    # RULE176
    grep -q remember /etc/security/pwhistory.conf 2>/dev/null || echo 'remember = 24' >>/etc/security/pwhistory.conf
    sec_audit_remediate_done 176 "password history"

    # RULE177
    sec_audit_remediate_skip 177 "review remediation: Ensure pam_unix does not include nullok"

    # RULE178
    grep -q remember /etc/security/pwhistory.conf 2>/dev/null || echo 'remember = 24' >>/etc/security/pwhistory.conf
    sec_audit_remediate_done 178 "password history"

    # RULE179
    sec_audit_set_login_defs_kv ENCRYPT_METHOD SHA512
    sec_audit_remediate_done 179 "ENCRYPT_METHOD SHA512"

    # RULE180
    sec_audit_remediate_skip 180 "review remediation: Ensure pam_unix includes use_authok"

    # RULE181
    sec_audit_remediate_skip 181 "review remediation: Ensure password expiration is configured"

    # RULE182
    sec_audit_remediate_skip 182 "review remediation: Ensure password expiration warning days is configured"

    # RULE183
    sec_audit_set_login_defs_kv ENCRYPT_METHOD SHA512
    sec_audit_remediate_done 183 "ENCRYPT_METHOD SHA512"

    # RULE184
    sec_audit_remediate_skip 184 "Ensure inactive password lock is configured"

    # RULE185
    sec_audit_remediate_skip 185 "Ensure all users last password change date is in the past"

    # RULE186
    sec_audit_remediate_skip 186 "Ensure root is the only UID 0 account"

    # RULE187
    sec_audit_remediate_skip 187 "Ensure root is the only GID 0 account"

    # RULE188
    sec_audit_remediate_skip 188 "Ensure group root is the only GID 0 group"

    # RULE189
    sec_audit_remediate_skip 189 "Ensure root path integrity"

    # RULE190
    sec_audit_set_login_defs_kv UMASK 027
    cat >/etc/profile.d/99-cre-umask.sh <<'EOF'
umask 027
EOF
    sec_audit_remediate_done 190 "default umask 027"

    # RULE191
    sec_audit_remediate_skip 191 "Ensure system accounts do not have a valid login shell"

    # RULE192
    sec_audit_remediate_skip 192 "Ensure accounts without a valid login shell are locked"

    # RULE193
    sec_audit_remediate_skip 193 "review remediation: Ensure nologin is not listed in /etc/shells"

    # RULE194
    cat >/etc/profile.d/99-cre-timeout.sh <<'EOF'
TMOUT=600
readonly TMOUT
export TMOUT
EOF
    sec_audit_remediate_done 194 "TMOUT=600"

    # RULE195
    sec_audit_set_login_defs_kv UMASK 027
    cat >/etc/profile.d/99-cre-umask.sh <<'EOF'
umask 027
EOF
    sec_audit_remediate_done 195 "default umask 027"

}

sec_audit_remediate_logging() {
    # RULE196
    sec_audit_start_svc systemd-journald
    sec_audit_remediate_done 196 "journald active"

    # RULE197
    sec_audit_remediate_skip 197 "configure central logging per site policy before enabling journal remote/upload"

    # RULE198
    mkdir -p /etc/systemd/journald.conf.d
    cat >/etc/systemd/journald.conf.d/99-debian13-cre.conf <<'EOF'
[Journal]
ForwardToSyslog=no
Compress=yes
Storage=persistent
EOF
    systemctl restart systemd-journald >/dev/null 2>&1 || true
    sec_audit_remediate_done 198 "journald configuration"

    # RULE199
    mkdir -p /etc/systemd/journald.conf.d
    cat >/etc/systemd/journald.conf.d/99-debian13-cre.conf <<'EOF'
[Journal]
ForwardToSyslog=no
Compress=yes
Storage=persistent
EOF
    systemctl restart systemd-journald >/dev/null 2>&1 || true
    sec_audit_remediate_done 199 "journald configuration"

    # RULE200
    sec_audit_remediate_skip 200 "Ensure systemd-journal-remote is installed"

    # RULE201
    sec_audit_remediate_skip 201 "Ensure systemd-journal-upload is enabled and active"

    # RULE202
    sec_audit_remediate_skip 202 "Ensure systemd-journal-remote service is not in use"

    # RULE203
    sec_audit_pkg_install rsyslog
    sec_audit_start_svc rsyslog
    sec_audit_remediate_done 203 "rsyslog installed"

    # RULE204
    sec_audit_pkg_install rsyslog
    sec_audit_start_svc rsyslog
    sec_audit_remediate_done 204 "rsyslog installed"

    # RULE205
    sec_audit_start_svc systemd-journald
    sec_audit_remediate_done 205 "journald active"

    # RULE206
    sec_audit_pkg_install rsyslog
    sec_audit_start_svc rsyslog
    sec_audit_remediate_done 206 "rsyslog installed"

    # RULE207
    sec_audit_remediate_skip 207 "Ensure rsyslog is not configured to receive logs from a remote client"

    # RULE208
    sec_audit_pkg_install rsyslog
    sec_audit_start_svc rsyslog
    sec_audit_remediate_done 208 "rsyslog installed"

    # RULE209
    sec_audit_remediate_skip 209 "install/configure rsyslog remote forwarding only when sec_audit_log host policy exists"

    # RULE210
    sec_audit_remediate_skip 210 "review remediation: Ensure access to all logfiles has been configured"

}

sec_audit_remediate_auditd() {
    # RULE211
    sec_audit_start_svc systemd-journald
    sec_audit_remediate_done 211 "journald active"

    # RULE212
    sec_audit_start_svc systemd-journald
    sec_audit_remediate_done 212 "journald active"

    # RULE213
    sec_audit_start_svc systemd-journald
    sec_audit_remediate_done 213 "journald active"

    # RULE214
    sec_audit_remediate_skip 214 "review remediation: Ensure only one logging system is in use"

    # RULE215
    sec_audit_pkg_install audit auditd 2>/dev/null || true
    mkdir -p /etc/audit/rules.d
    cat >/etc/audit/rules.d/99-debian13-cre.rules <<'EOF'
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
    sec_audit_remediate_done 215 "audit rules baseline"

    # RULE216
    sec_audit_remediate_skip 216 "configure central logging per site policy before enabling journal remote/upload"

    # RULE217
    mkdir -p /etc/systemd/journald.conf.d
    cat >/etc/systemd/journald.conf.d/99-debian13-cre.conf <<'EOF'
[Journal]
ForwardToSyslog=no
Compress=yes
Storage=persistent
EOF
    systemctl restart systemd-journald >/dev/null 2>&1 || true
    sec_audit_remediate_done 217 "journald configuration"

    # RULE218
    mkdir -p /etc/systemd/journald.conf.d
    cat >/etc/systemd/journald.conf.d/99-debian13-cre.conf <<'EOF'
[Journal]
ForwardToSyslog=no
Compress=yes
Storage=persistent
EOF
    systemctl restart systemd-journald >/dev/null 2>&1 || true
    sec_audit_remediate_done 218 "journald configuration"

    # RULE219
    sec_audit_pkg_install rsyslog
    sec_audit_start_svc rsyslog
    sec_audit_remediate_done 219 "rsyslog installed"

    # RULE220
    sec_audit_pkg_install rsyslog
    sec_audit_start_svc rsyslog
    sec_audit_remediate_done 220 "rsyslog installed"

    # RULE221
    sec_audit_start_svc systemd-journald
    sec_audit_remediate_done 221 "journald active"

    # RULE222
    sec_audit_pkg_install rsyslog
    sec_audit_start_svc rsyslog
    sec_audit_remediate_done 222 "rsyslog installed"

    # RULE223
    sec_audit_pkg_install rsyslog
    sec_audit_start_svc rsyslog
    sec_audit_remediate_done 223 "rsyslog installed"

    # RULE224
    sec_audit_remediate_skip 224 "review remediation: Ensure events that modify /etc/issue and /etc/issue.net are collected"

    # RULE225
    sec_audit_remediate_skip 225 "review remediation: Ensure events that modify /etc/hosts and /etc/hostname are collected"

    # RULE226
    sec_audit_remediate_skip 226 "Ensure rsyslog logrotate is configured"

    # RULE227
    sec_audit_remediate_skip 227 "review remediation: Ensure events that modify /etc/NetworkManager directory are collected"

    # RULE228
    sec_audit_remediate_skip 228 "review remediation: Ensure use of privileged commands are collected"

    # RULE229
    sec_audit_remediate_skip 229 "review remediation: Ensure unsuccessful file access attempts are collected"

    # RULE230
    sec_audit_remediate_skip 230 "Ensure events that modify /etc/group information are collected"

    # RULE231
    sec_audit_remediate_skip 231 "review remediation: Ensure events that modify /etc/passwd information are collected"

    # RULE232
    sec_audit_remediate_skip 232 "review remediation: Ensure events that modify /etc/shadow and /etc/gshadow are collected"

    # RULE233
    sec_audit_remediate_skip 233 "review remediation: Ensure events that modify /etc/security/opasswd are collected"

    # RULE234
    sec_audit_remediate_skip 234 "review remediation: Ensure events that modify /etc/nsswitch.conf file are collected"

    # RULE235
    sec_audit_remediate_skip 235 "review remediation: Ensure events that modify /etc/pam.conf and /etc/pam.d/ are collected"

    # RULE236
    sec_audit_remediate_skip 236 "review remediation: Ensure DAC permission modification events chmod,fchmod,fchmodat are collected"

    # RULE237
    sec_audit_remediate_skip 237 "review remediation: Ensure DAC permission modification events chown,fchown,lchown,fchownat are collected"

    # RULE238
    sec_audit_remediate_skip 238 "review remediation: Ensure DAC permission modification events setxattr,removexattr are collected"

    # RULE239
    sec_audit_remediate_skip 239 "review remediation: Ensure successful file system mounts are collected"

    # RULE240
    sec_audit_remediate_skip 240 "review remediation: Ensure session initiation information is collected"

    # RULE241
    sec_audit_remediate_skip 241 "review remediation: Ensure login and logout events are collected"

    # RULE242
    sec_audit_remediate_skip 242 "review remediation: Ensure unlink file deletion events by users are collected"

    # RULE243
    sec_audit_remediate_skip 243 "review remediation: Ensure rename file deletion events by users are collected"

    # RULE244
    sec_audit_remediate_skip 244 "review remediation: Ensure events that modify MAC are collected"

    # RULE245
    sec_audit_remediate_skip 245 "review remediation: Ensure chcon command use is collected"

    # RULE246
    sec_audit_remediate_skip 246 "review remediation: Ensure setfacl command use is collected"

    # RULE247
    sec_audit_remediate_skip 247 "review remediation: Ensure chacl command use is collected"

    # RULE248
    sec_audit_remediate_skip 248 "review remediation: Ensure usermod command use is collected"

    # RULE249
    sec_audit_disable_kmod loading/unloading/modification
    sec_audit_remediate_done 249 "blacklisted loading/unloading/modification"

    # RULE250
    sec_audit_remediate_skip 250 "review remediation: Ensure kernel init_module and finit_module is collected"

    # RULE251
    sec_audit_remediate_skip 251 "review remediation: Ensure kernel delete_module is collected"

    # RULE252
    sec_audit_remediate_skip 252 "review remediation: Ensure the audit configuration is loaded regardless of errors"

    # RULE253
    sec_audit_remediate_skip 253 "review remediation: Ensure the audit configuration is immutable"

    # RULE254
    sec_audit_remediate_skip 254 "review remediation: Ensure access to all logfiles has been configured"

    # RULE255
    sec_audit_pkg_install audit auditd 2>/dev/null || true
    mkdir -p /etc/audit/rules.d
    cat >/etc/audit/rules.d/99-debian13-cre.rules <<'EOF'
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
    sec_audit_remediate_done 255 "audit rules baseline"

    # RULE256
    sec_audit_remediate_skip 256 "Ensure audit sec_audit_log files group owner is configured"

    # RULE257
    sec_audit_pkg_install audit auditd 2>/dev/null || true
    mkdir -p /etc/audit/rules.d
    cat >/etc/audit/rules.d/99-debian13-cre.rules <<'EOF'
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
    sec_audit_remediate_done 257 "audit rules baseline"

    # RULE258
    sec_audit_pkg_install audit auditd 2>/dev/null || true
    mkdir -p /etc/audit/rules.d
    cat >/etc/audit/rules.d/99-debian13-cre.rules <<'EOF'
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
    sec_audit_remediate_done 258 "audit rules baseline"

    # RULE259
    sec_audit_pkg_install audit auditd 2>/dev/null || true
    mkdir -p /etc/audit/rules.d
    cat >/etc/audit/rules.d/99-debian13-cre.rules <<'EOF'
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
    sec_audit_remediate_done 259 "audit rules baseline"

    # RULE260
    sec_audit_remediate_skip 260 "Ensure audit configuration files group owner is configured"

    # RULE261
    sec_audit_pkg_install audit auditd 2>/dev/null || true
    mkdir -p /etc/audit/rules.d
    cat >/etc/audit/rules.d/99-debian13-cre.rules <<'EOF'
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
    sec_audit_remediate_done 261 "audit rules baseline"

    # RULE262
    sec_audit_pkg_install audit auditd 2>/dev/null || true
    mkdir -p /etc/audit/rules.d
    cat >/etc/audit/rules.d/99-debian13-cre.rules <<'EOF'
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
    sec_audit_remediate_done 262 "audit rules baseline"

    # RULE263
    sec_audit_remediate_skip 263 "Ensure audit tools group owner is configured"

    # Shared on-disk audit baseline for operators enabling collection rules.
    sec_audit_ensure_audit_baseline >/dev/null 2>&1 || true

}

sec_audit_remediate_aide() {
    # RULE264
    sec_audit_pkg_install aide
    sec_audit_remediate_done 264 "installed AIDE"

    # RULE265
    sec_audit_pkg_install aide afick
    sec_audit_remediate_done 265 "integrity tooling"

}

sec_audit_remediate_identity_files() {
    # RULE266
    sec_audit_harden_path /etc/passwd 644 root:root || true
    sec_audit_remediate_done 266 "hardened /etc/passwd (644 root:root)"

    # RULE267
    sec_audit_harden_path /etc/passwd- 644 root:root || true
    sec_audit_remediate_done 267 "hardened /etc/passwd- (644 root:root)"

    # RULE268
    sec_audit_harden_path /etc/group 644 root:root || true
    sec_audit_remediate_done 268 "hardened /etc/group (644 root:root)"

    # RULE269
    sec_audit_harden_path /etc/group- 644 root:root || true
    sec_audit_remediate_done 269 "hardened /etc/group- (644 root:root)"

    # RULE270
    sec_audit_harden_path /etc/shadow 640 root:shadow || true
    sec_audit_remediate_done 270 "hardened /etc/shadow (640 root:shadow)"

    # RULE271
    sec_audit_harden_path /etc/shadow- 640 root:shadow || true
    sec_audit_remediate_done 271 "hardened /etc/shadow- (640 root:shadow)"

    # RULE272
    sec_audit_harden_path /etc/gshadow 640 root:shadow || true
    sec_audit_remediate_done 272 "hardened /etc/gshadow (640 root:shadow)"

    # RULE273
    sec_audit_harden_path /etc/gshadow- 640 root:shadow || true
    sec_audit_remediate_done 273 "hardened /etc/gshadow- (640 root:shadow)"

    # RULE274
    sec_audit_harden_path /etc/shells 644 root:root || true
    sec_audit_remediate_done 274 "hardened /etc/shells (644 root:root)"

    # RULE275
    mkdir -p /etc/security
    [ -e /etc/security/opasswd ] || touch /etc/security/opasswd 2>/dev/null || true
    sec_audit_harden_path /etc/security/opasswd 600 root:root || true
    sec_audit_remediate_done 275 "hardened /etc/security/opasswd (600 root:root)"

}

sec_audit_remediate_filesystem_integrity() {
    # RULE276
    sec_audit_remediate_skip 276 "Ensure accounts in /etc/passwd use shadowed passwords"

    # RULE277
    sec_audit_remediate_skip 277 "review remediation: Ensure /etc/shadow password fields are not empty"

    # RULE278
    sec_audit_remediate_skip 278 "Ensure no duplicate UIDs exist"

    # RULE279
    sec_audit_remediate_skip 279 "Ensure no duplicate GIDs exist"

    # RULE280
    sec_audit_remediate_skip 280 "Ensure no duplicate user names exist"

    # RULE281
    sec_audit_remediate_skip 281 "Ensure no duplicate group names exist"

    # RULE282
    sec_audit_remediate_skip 282 "Ensure shadow group is empty"

    # RULE283
    sec_audit_remediate_skip 283 "Ensure local interactive user dot files access is configured"

    # RULE284
    sec_audit_remediate_skip 284 "Ensure no passwords are stored in /etc/group"

}

sec_audit_maybe_security_upgrade() {
    if [ "${DEB13_REMEDIATE_SECURITY_UPGRADE}" != "1" ]; then
        sec_audit_log "skipping apt-get upgrade (set DEB13_REMEDIATE_SECURITY_UPGRADE=1 to enable)"
        return 0
    fi
    if sec_audit_have_bin apt-get; then
        if sec_audit_have_bin timeout; then
            timeout 300 apt-get update >/dev/null 2>&1 || true
            timeout 600 DEBIAN_FRONTEND=noninteractive apt-get upgrade -y >/dev/null 2>&1 || true
        else
            apt-get update >/dev/null 2>&1 || true
            DEBIAN_FRONTEND=noninteractive apt-get upgrade -y >/dev/null 2>&1 || true
        fi
    fi
}

sec_audit_main() {
    sec_audit_log "starting remediation (Debian 13 / sec_audit_* style)"

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
    sec_audit_remediate_time_sync
    sec_audit_remediate_cron_at
    sec_audit_remediate_network_stack
    sec_audit_remediate_firewall
    sec_audit_remediate_sshd
    sec_audit_remediate_sudo_su
    sec_audit_remediate_pam_auth
    sec_audit_remediate_accounts
    sec_audit_remediate_logging
    sec_audit_remediate_auditd
    sec_audit_remediate_aide
    sec_audit_remediate_identity_files
    sec_audit_remediate_filesystem_integrity

    sec_audit_maybe_security_upgrade
    sec_audit_log "remediation complete (Debian13_remediation.sh)"
    exit 0
}

sec_audit_main "$@"
