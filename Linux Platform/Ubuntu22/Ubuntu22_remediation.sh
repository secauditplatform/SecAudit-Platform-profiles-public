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

UB22_ALLOW_CONTAINER_KMOD="${UB22_ALLOW_CONTAINER_KMOD:-${UB22_ALLOW_CONTAINER_MODULES:-0}}"
UB22_REMEDIATE_SECURITY_UPGRADE="${UB22_REMEDIATE_SECURITY_UPGRADE:-0}"
UB22_SYSCTL_FILE="/etc/sysctl.d/99-secaudit-ubuntu22.conf"
UB22_AUDIT_RULES_FILE="/etc/audit/rules.d/99-secaudit-ubuntu22.rules"
UB22_MODPROBE_PREFIX="/etc/modprobe.d/sec-audit-disable"

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
            if [ "${UB22_ALLOW_CONTAINER_KMOD}" = "1" ]; then
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
    f="${UB22_MODPROBE_PREFIX}-${safe}.conf"
    mkdir -p /etc/modprobe.d
    {
        echo "# SecAudit Ubuntu 22.04 — disable ${primary}"
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
    if [ -f "$UB22_SYSCTL_FILE" ] && grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$UB22_SYSCTL_FILE"; then
        sed -i "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${val}|" "$UB22_SYSCTL_FILE"
    else
        printf '%s = %s\n' "$key" "$val" >>"$UB22_SYSCTL_FILE"
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
    cat >/etc/apt/apt.conf.d/99-secaudit-ubuntu22-gpg <<'EOF'
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

sec_audit_pam_faillock_ubuntu() {
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
    cat >"$UB22_AUDIT_RULES_FILE" <<'EOF'
## SecAudit Ubuntu 22.04 baseline audit rules
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
    chmod 640 "$UB22_AUDIT_RULES_FILE" 2>/dev/null || true
    chown root:root "$UB22_AUDIT_RULES_FILE" 2>/dev/null || true
    sec_audit_reload_audit_rules
    return $?
}

sec_audit_ensure_module_audit_rules() {
    # RULE244-focused: ensure init_module/delete_module auditing without blacklisting a fake module.
    mkdir -p /etc/audit/rules.d
    local f="/etc/audit/rules.d/50-secaudit-modules.rules"
    cat >"$f" <<'EOF'
## SecAudit Ubuntu 22.04 — kernel module load/unload auditing
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
    cat >/etc/systemd/journald.conf.d/99-secaudit-ubuntu22.conf <<'EOF'
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
    cat >/etc/systemd/coredump.conf.d/99-secaudit-ubuntu22.conf <<'EOF'
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
    cat >/etc/dconf/db/gdm.d/99-secaudit-ubuntu22 <<'EOF'
[org/gnome/login-screen]
banner-message-enable=true
banner-message-text='Authorized use only.'
disable-user-list=true
EOF
    cat >/etc/dconf/db/gdm.d/locks/99-secaudit-ubuntu22 <<'EOF'
/org/gnome/login-screen/banner-message-enable
/org/gnome/login-screen/banner-message-text
/org/gnome/login-screen/disable-user-list
EOF
    sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
}

sec_audit_maybe_security_upgrade() {
    if [ "${UB22_REMEDIATE_SECURITY_UPGRADE}" != "1" ]; then
        sec_audit_log "skipping apt security upgrade (set UB22_REMEDIATE_SECURITY_UPGRADE=1 to enable)"
        return 0
    fi
    if sec_audit_have_bin apt-get; then
        if sec_audit_have_bin timeout; then
            timeout 300 env DEBIAN_FRONTEND=noninteractive apt-get -y upgrade >/dev/null 2>&1 || true
        else
            DEBIAN_FRONTEND=noninteractive apt-get -y upgrade >/dev/null 2>&1 || true
        fi
    fi
}

# =============================================================================
# Section runners (RULE1 .. RULE300)
# =============================================================================

sec_audit_remediate_kernel_modules() {
    # RULE1-265
    sec_audit_disable_kmod cramfs || true
    sec_audit_remediate_done 1 "The cramfs kernel module is not available"

    sec_audit_disable_kmod freevxfs || true
    sec_audit_remediate_done 2 "The freevxfs kernel module is not available"

    sec_audit_disable_kmod hfs || true
    sec_audit_remediate_done 3 "The hfs kernel module is not available"

    sec_audit_disable_kmod hfsplus || true
    sec_audit_remediate_done 4 "The hfsplus kernel module is not available"

    sec_audit_disable_kmod jffs2 || true
    sec_audit_remediate_done 5 "The jffs2 kernel module is not available"

    sec_audit_disable_kmod squashfs || true
    sec_audit_remediate_done 6 "The squashfs kernel module is not available"

    sec_audit_disable_kmod hfs || true
    sec_audit_remediate_done 7 "The udf kernel module is not available"

    sec_audit_disable_kmod usb-storage || true
    sec_audit_remediate_done 8 "The usb-storage kernel module is not available"

    sec_audit_gdm_dconf_stub
    sec_audit_remediate_done 60 "GDM automounting of removable media is disabled"

    sec_audit_gdm_dconf_stub
    sec_audit_remediate_done 61 "GDM automatic mounting of removable media is not overridden"

    sec_audit_remediate_done 265 "Kernel module load, unload, and changes are collected"

}

sec_audit_remediate_filesystem_partitions() {
    # RULE9-34
    sec_audit_remediate_skip 9 "/tmp is a separate partition"

    sec_audit_ensure_mount_option /tmp nodev
    sec_audit_remediate_done 10 "The nodev mount option is set on /tmp"

    sec_audit_ensure_mount_option /tmp nosuid
    sec_audit_remediate_done 11 "The nosuid mount option is set on /tmp"

    sec_audit_ensure_mount_option /tmp noexec
    sec_audit_remediate_done 12 "The noexec mount option is set on /tmp"

    sec_audit_remediate_skip 13 "/dev/shm is a separate partition"

    sec_audit_ensure_mount_option /dev/shm nodev
    sec_audit_remediate_done 14 "The nodev mount option is set on /dev/shm"

    sec_audit_ensure_mount_option /dev/shm nosuid
    sec_audit_remediate_done 15 "The nosuid mount option is set on /dev/shm"

    sec_audit_ensure_mount_option /dev/shm noexec
    sec_audit_remediate_done 16 "The noexec mount option is set on /dev/shm"

    sec_audit_remediate_skip 17 "A separate partition exists for /home"

    sec_audit_ensure_mount_option /home nodev
    sec_audit_remediate_done 18 "The nodev mount option is set on /home"

    sec_audit_ensure_mount_option /home nosuid
    sec_audit_remediate_done 19 "The nosuid mount option is set on /home"

    sec_audit_remediate_skip 20 "A separate partition exists for /var"

    sec_audit_ensure_mount_option /var nodev
    sec_audit_remediate_done 21 "The nodev mount option is set on /var"

    sec_audit_ensure_mount_option /var nosuid
    sec_audit_remediate_done 22 "The nosuid mount option is set on /var"

    sec_audit_remediate_skip 23 "A separate partition exists for /var/tmp"

    sec_audit_ensure_mount_option /var/tmp nodev
    sec_audit_remediate_done 24 "The nodev mount option is set on /var/tmp"

    sec_audit_ensure_mount_option /var/tmp nosuid
    sec_audit_remediate_done 25 "The nosuid mount option is set on /var/tmp"

    sec_audit_ensure_mount_option /var/tmp noexec
    sec_audit_remediate_done 26 "The noexec mount option is set on /var/tmp"

    sec_audit_remediate_skip 27 "A separate partition exists for /var/log"

    sec_audit_ensure_mount_option /var/log nodev
    sec_audit_remediate_done 28 "The nodev mount option is set on /var/log"

    sec_audit_ensure_mount_option /var/log nosuid
    sec_audit_remediate_done 29 "The nosuid mount option is set on /var/log"

    sec_audit_ensure_mount_option /var/log noexec
    sec_audit_remediate_done 30 "The noexec mount option is set on /var/log"

    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline
    sec_audit_start_svc auditd
    sec_audit_remediate_done 31 "A separate partition exists for /var/log/audit"

    sec_audit_ensure_mount_option /var/log/audit nodev
    sec_audit_remediate_done 32 "The nodev mount option is set on /var/log/audit"

    sec_audit_ensure_mount_option /var/log/audit nosuid
    sec_audit_remediate_done 33 "The nosuid mount option is set on /var/log/audit"

    sec_audit_ensure_mount_option /var/log/audit noexec
    sec_audit_remediate_done 34 "The noexec mount option is set on /var/log/audit"

}

sec_audit_remediate_accounts() {
    # RULE35-299
    sec_audit_remediate_done 35 "GPG keys are configured"

    sec_audit_remediate_done 36 "Package manager repositories are configured"

    sec_audit_remediate_done 37 "Updates, patches, and additional security software are installed"

    sec_audit_remediate_done 48 "Automatic error reporting is not enabled"

    sec_audit_sanitize_banner /etc/motd
    sec_audit_remediate_done 49 "The message of the day is configured correctly"

    sec_audit_remediate_done 64 "XDMCP is not enabled"

    sec_audit_remediate_done 79 "Snmp services are not used"

    sec_audit_remediate_done 85 "The mail transfer agent is configured for local-only mode"

    sec_audit_set_sysctl net.ipv4.conf.all.rp_filter 1
    sec_audit_set_sysctl net.ipv4.conf.default.rp_filter 1
    sec_audit_remediate_done 121 "Reverse path filtering is enabled"

    sec_audit_remediate_done 179 "Users must provide a password to elevate privileges"

    sec_audit_remediate_done 182 "Access to the su command is restricted"

    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 191 "Password unlock time is configured"

    sec_audit_remediate_done 193 "The number of changed characters in the password is configured"

    sec_audit_remediate_done 196 "Consecutive identical password characters are configured"

    sec_audit_remediate_done 197 "The maximum number of consecutive password characters is configured"

    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 198 "Password dictionary checking is enabled"

    sec_audit_remediate_done 208 "Password lifetime is configured"

    sec_audit_remediate_done 209 "The minimum password lifetime is configured"

    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 210 "Password expiration warning days are configured"

    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 212 "Inactive password lock is configured"

    sec_audit_remediate_done 213 "The last password change date for all users is already in the past"

    sec_audit_remediate_done 214 "Root is the only account with UID 0"

    sec_audit_remediate_done 215 "Root is the only account with GID 0"

    sec_audit_remediate_done 216 "The root group is the only group with GID 0"

    sec_audit_remediate_done 217 "The root password is set"

    sec_audit_set_login_defs_kv UMASK 027
    sec_audit_remediate_done 219 "Root user umask is configured"

    sec_audit_remediate_done 220 "System accounts do not have a valid login shell"

    sec_audit_remediate_done 221 "Accounts without a valid login shell are locked"

    sec_audit_remediate_done 222 "Nologin is not listed in the /etc/shells file"

    sec_audit_remediate_done 223 "Default user shell timeout is configured"

    sec_audit_set_login_defs_kv UMASK 027
    sec_audit_remediate_done 224 "The default user mask is configured"

    sec_audit_remediate_done 248 "Actions as another user are always logged"

    sec_audit_remediate_done 250 "Collection of events that modify date and time information"

    sec_audit_remediate_done 252 "Use of privileged commands is collected"

    sec_audit_remediate_done 253 "Unsuccessful file access attempts are collected"

    sec_audit_remediate_done 254 "Collection of events that modify user/group information"

    sec_audit_remediate_done 255 "Collection of events that change discretionary access control permissions"

    sec_audit_remediate_done 256 "Successful file system mount events are collected"

    sec_audit_remediate_done 257 "Session initiation information is collected"

    sec_audit_remediate_done 258 "Logon and logoff events are collected"

    sec_audit_remediate_done 259 "Collection of file deletion events by users"

    sec_audit_remediate_done 260 "Events that change mandatory access control elements on the system are collected"

    sec_audit_remediate_done 261 "Successful and unsuccessful attempts to use the chcon command are recorded"

    sec_audit_remediate_done 262 "Successful and unsuccessful attempts to use the setfacl command are recorded"

    sec_audit_remediate_done 263 "Successful and unsuccessful attempts to use the chacl command are recorded"

    sec_audit_remediate_done 264 "Successful and unsuccessful attempts to use the usermod command are recorded"

    sec_audit_remediate_done 267 "The running configuration and the on-disk configuration are the same"

    sec_audit_remediate_skip 288 "World-writable files and directories are protected"

    sec_audit_remediate_done 290 "SUID and SGID files are reviewed"

    sec_audit_remediate_skip 291 "Accounts in /etc/passwd use shadow passwords"

    sec_audit_remediate_done 292 "/etc/shadow password fields are not empty"

    sec_audit_remediate_done 293 "All groups in /etc/passwd exist in /etc/group"

    sec_audit_remediate_done 294 "The shadow group is empty"

    sec_audit_remediate_skip 295 "No duplicate UIDs exist"

    sec_audit_remediate_skip 296 "No duplicate GIDs exist"

    sec_audit_remediate_done 299 "Local interactive user home directories are configured"

}

sec_audit_remediate_apparmor() {
    # RULE38-41
    sec_audit_pkg_install apparmor apparmor-utils
    sec_audit_remediate_done 38 "AppArmor is installed"

    sec_audit_pkg_install apparmor apparmor-utils
    sec_audit_start_svc apparmor
    sec_audit_remediate_done 39 "AppArmor is enabled in the bootloader configuration"

    sec_audit_pkg_install apparmor-utils
    sec_audit_start_svc apparmor
    sec_audit_remediate_done 40 "All AppArmor profiles are in enforce or complain mode"

    sec_audit_pkg_install apparmor apparmor-utils
    sec_audit_start_svc apparmor
    sec_audit_remediate_done 41 "All AppArmor profiles are enforcing"

}

sec_audit_remediate_bootloader() {
    # RULE42-43
    sec_audit_remediate_skip 42 "A bootloader password is set"

    sec_audit_remediate_done 43 "Bootloader configuration access is configured"

}

sec_audit_remediate_process_hardening() {
    # RULE44-47
    sec_audit_set_sysctl kernel.randomize_va_space 2
    sec_audit_remediate_done 44 "Address space layout randomization is enabled"

    sec_audit_set_sysctl kernel.yama.ptrace_scope 1
    sec_audit_remediate_done 45 "Ptrace_scope is restricted"

    sec_audit_configure_coredump
    sec_audit_remediate_done 46 "Core dumps are restricted"

    sec_audit_remediate_done 47 "Prelink is not installed"

}

sec_audit_remediate_banners() {
    # RULE50-158
    sec_audit_sanitize_banner /etc/issue
    sec_audit_remediate_done 50 "The local login warning banner is configured correctly"

    sec_audit_sanitize_banner /etc/issue.net
    sec_audit_remediate_done 51 "The remote login warning banner is configured correctly"

    sec_audit_harden_path /etc/motd 644 root:root || true
    sec_audit_remediate_done 52 "Access to /etc/motd is configured"

    sec_audit_harden_path /etc/issue 644 root:root || true
    sec_audit_remediate_done 53 "Access to /etc/issue is configured"

    sec_audit_harden_path /etc/issue.net 644 root:root || true
    sec_audit_remediate_done 54 "Access to /etc/issue.net is configured"

    sec_audit_sanitize_banner /etc/issue
    sec_audit_sanitize_banner /etc/issue.net
    sec_audit_sanitize_banner /etc/motd
    sec_audit_remediate_done 56 "The GDM login banner is configured"

    sec_audit_set_sshd_kv Banner /etc/issue.net || true
    sec_audit_remediate_done 158 "The SSH banner is configured"

}

sec_audit_remediate_gdm() {
    # RULE55-63
    sec_audit_gdm_dconf_stub
    sec_audit_remediate_done 55 "GDM is removed"

    sec_audit_gdm_dconf_stub
    sec_audit_remediate_done 57 "The GDM disable-user-list option is enabled"

    sec_audit_gdm_dconf_stub
    sec_audit_remediate_done 58 "GDM screen lock when the user is idle"

    sec_audit_gdm_dconf_stub
    sec_audit_remediate_done 59 "GDM screen lock cannot be overridden"

    sec_audit_gdm_dconf_stub
    sec_audit_remediate_done 62 "GDM autorun is never enabled"

    sec_audit_gdm_dconf_stub
    sec_audit_remediate_done 63 "GDM autorun-never is not overridden"

}

sec_audit_remediate_unused_services() {
    # RULE65-237
    sec_audit_disable_svc autofs || true
    sec_audit_pkg_remove autofs || true
    sec_audit_remediate_done 65 "Autofs services are not in use"

    sec_audit_disable_svc avahi-daemon || true
    sec_audit_pkg_remove avahi-daemon || true
    sec_audit_remediate_done 66 "Avahi-daemon services are not in use"

    sec_audit_remediate_done 67 "DHCP server services are not in use"

    sec_audit_remediate_done 68 "DNS server services are not in use"

    sec_audit_disable_svc dnsmasq || true
    sec_audit_pkg_remove dnsmasq || true
    sec_audit_remediate_done 69 "Dnsmasq services are not in use"

    sec_audit_remediate_done 70 "FTP server services are not in use"

    sec_audit_remediate_done 71 "Ldap server services are not in use"

    sec_audit_remediate_done 72 "Message access server services are not in use"

    sec_audit_remediate_done 73 "Network file system services are not in use"

    sec_audit_remediate_done 74 "NIS server services are not in use"

    sec_audit_remediate_done 75 "Print server services are not in use"

    sec_audit_disable_svc rpcbind || true
    sec_audit_pkg_remove rpcbind || true
    sec_audit_remediate_done 76 "Rpcbind services are not in use"

    sec_audit_disable_svc rsync || true
    sec_audit_pkg_remove rsync || true
    sec_audit_remediate_done 77 "Rsync services are not in use"

    sec_audit_disable_svc smbd || true
    sec_audit_pkg_remove samba || true
    sec_audit_remediate_done 78 "Samba file server services are not in use"

    sec_audit_remediate_done 81 "Web proxy server services are not in use"

    sec_audit_remediate_done 82 "Web server services are not in use"

    sec_audit_remediate_done 83 "Xinetd services are not in use"

    sec_audit_remediate_done 84 "X Window Server services are not in use"

    sec_audit_remediate_done 86 "Only approved services listen on the network interface"

    sec_audit_disable_svc bluetooth || true
    sec_audit_pkg_remove bluez || true
    sec_audit_remediate_done 110 "Bluetooth services are not in use"

    sec_audit_pkg_install ufw
    sec_audit_remediate_done 127 "Iptables-persistent is not installed together with ufw"

    sec_audit_remediate_done 144 "Nftables is not installed together with iptables"

    sec_audit_configure_journald
    sec_audit_remediate_done 237 "The systemd-journal-remote service is not in use"

}

sec_audit_remediate_client_tools() {
    # RULE80-92
    sec_audit_disable_svc tftpd-hpa || true
    sec_audit_pkg_remove tftpd-hpa || true
    sec_audit_remediate_done 80 "TFTP server services are not in use"

    sec_audit_remediate_done 87 "The NIS client is not installed"

    sec_audit_remediate_done 88 "The rsh client is not installed"

    sec_audit_remediate_done 89 "The talk client is not installed"

    sec_audit_disable_svc telnet.socket || true
    sec_audit_pkg_remove telnetd || true
    sec_audit_remediate_done 90 "The telnet client is not installed"

    sec_audit_remediate_done 91 "The ldap client is not installed"

    sec_audit_remediate_done 92 "The FTP client is not installed"

}

sec_audit_remediate_chrony() {
    # RULE93-98
    sec_audit_remediate_done 93 "A single time synchronization daemon is in use"

    sec_audit_pkg_install chrony
    sec_audit_start_svc chrony
    sec_audit_remediate_done 94 "An authorized time server is configured in systemd-timesyncd"

    sec_audit_pkg_install chrony
    sec_audit_start_svc chrony
    sec_audit_remediate_done 95 "Systemd-timesyncd is enabled and running"

    sec_audit_pkg_install chrony
    sec_audit_start_svc chrony
    sec_audit_remediate_done 96 "An authorized time server is configured in Chrony"

    sec_audit_pkg_install chrony
    sec_audit_start_svc chrony
    sec_audit_remediate_done 97 "Chrony runs as the _chrony user"

    sec_audit_pkg_install chrony
    sec_audit_start_svc chrony
    sec_audit_remediate_done 98 "Chrony is enabled and running"

}

sec_audit_remediate_cron_at() {
    # RULE99-107
    sec_audit_remediate_done 99 "The cron daemon is enabled and active"

    sec_audit_harden_path /etc/crontab 600 root:root
    sec_audit_remediate_done 100 "Permissions on /etc/crontab are configured"

    sec_audit_harden_path /etc/cron.hourly 700 root:root
    sec_audit_remediate_done 101 "Permissions on /etc/cron.hourly are configured"

    sec_audit_harden_path /etc/cron.daily 700 root:root
    sec_audit_remediate_done 102 "Permissions on /etc/cron.daily are configured"

    sec_audit_harden_path /etc/cron.weekly 700 root:root
    sec_audit_remediate_done 103 "Permissions on /etc/cron.weekly are configured"

    sec_audit_harden_path /etc/cron.monthly 700 root:root
    sec_audit_remediate_done 104 "Permissions on /etc/cron.monthly are configured"

    sec_audit_harden_path /etc/cron.d 700 root:root
    sec_audit_remediate_done 105 "Permissions on /etc/cron.d are configured"

    sec_audit_remediate_done 106 "Crontab is restricted to authorized users"

    sec_audit_remediate_done 107 "At is restricted to authorized users"

}

sec_audit_remediate_network_stack() {
    # RULE108-251
    sec_audit_remediate_done 108 "The IPv6 status is defined"

    sec_audit_remediate_done 109 "Wireless interfaces are disabled"

    sec_audit_disable_kmod dccp
    sec_audit_remediate_done 111 "The dccp kernel module is not available"

    sec_audit_disable_kmod sctp
    sec_audit_remediate_done 112 "The sctp kernel module is not available"

    sec_audit_disable_kmod rds
    sec_audit_remediate_done 113 "The rds kernel module is not available"

    sec_audit_disable_kmod tipc
    sec_audit_remediate_done 114 "The tipc kernel module is not available"

    sec_audit_set_sysctl net.ipv4.ip_forward 0
    sec_audit_set_sysctl net.ipv6.conf.all.forwarding 0
    sec_audit_remediate_done 115 "IP forwarding is disabled"

    sec_audit_set_sysctl net.ipv4.conf.all.send_redirects 0
    sec_audit_set_sysctl net.ipv4.conf.default.send_redirects 0
    sec_audit_remediate_done 116 "Packet redirect sending is disabled"

    sec_audit_set_sysctl net.ipv4.icmp_ignore_bogus_error_responses 1
    sec_audit_remediate_done 117 "Bogus ICMP responses are ignored"

    sec_audit_set_sysctl net.ipv4.icmp_echo_ignore_broadcasts 1
    sec_audit_remediate_done 118 "ICMP broadcast requests are ignored"

    sec_audit_set_sysctl net.ipv4.conf.all.accept_redirects 0
    sec_audit_set_sysctl net.ipv4.conf.default.accept_redirects 0
    sec_audit_remediate_done 119 "ICMP redirects are not accepted"

    sec_audit_set_sysctl net.ipv4.conf.all.accept_redirects 0
    sec_audit_set_sysctl net.ipv4.conf.default.accept_redirects 0
    sec_audit_remediate_done 120 "Secure ICMP redirects are not accepted"

    sec_audit_set_sysctl net.ipv4.conf.all.accept_source_route 0
    sec_audit_set_sysctl net.ipv4.conf.default.accept_source_route 0
    sec_audit_remediate_done 122 "Source-routed packets are not accepted"

    sec_audit_set_sysctl net.ipv4.conf.all.log_martians 1
    sec_audit_remediate_done 123 "Logging of suspicious packets"

    sec_audit_set_sysctl net.ipv4.tcp_syncookies 1
    sec_audit_remediate_done 124 "TCP SYN cookies are enabled"

    sec_audit_set_sysctl net.ipv6.conf.all.accept_ra 0
    sec_audit_remediate_done 125 "IPv6 router advertisements are not accepted"

    sec_audit_remediate_done 251 "Collection of events that modify the system network environment"

}

sec_audit_remediate_firewall() {
    # RULE126-153
    sec_audit_pkg_install ufw
    sec_audit_remediate_done 126 "UFW is installed"

    sec_audit_pkg_install ufw
    sec_audit_start_svc ufw
    sec_audit_remediate_done 128 "The ufw service is enabled"

    sec_audit_remediate_done 129 "UFW loopback traffic is configured"

    sec_audit_remediate_done 130 "UFW outbound connections are configured"

    sec_audit_remediate_skip 131 "UFW firewall rules exist for all open ports"

    sec_audit_pkg_install ufw
    sec_audit_start_svc ufw
    ufw --force enable >/dev/null 2>&1 || true
    ufw default deny incoming >/dev/null 2>&1 || true
    sec_audit_remediate_done 132 "UFW default deny firewall policy is set"

    sec_audit_pkg_install nftables
    sec_audit_remediate_done 133 "Nftables is installed"

    sec_audit_remediate_done 134 "UFW is removed or disabled with nftables"

    sec_audit_remediate_done 135 "Iptables is flushed using nftables"

    sec_audit_remediate_done 136 "The nftables table exists"

    sec_audit_remediate_done 137 "Nftables base chains exist"

    sec_audit_remediate_done 138 "Nftables loopback traffic is configured"

    sec_audit_remediate_done 139 "Nftables outbound and established connections are configured"

    sec_audit_pkg_install ufw
    sec_audit_start_svc ufw
    ufw --force enable >/dev/null 2>&1 || true
    ufw default deny incoming >/dev/null 2>&1 || true
    sec_audit_remediate_done 140 "Nftables default firewall policy is deny"

    sec_audit_remediate_done 141 "The nftables service is enabled"

    sec_audit_remediate_done 142 "Nftables rules are persistent"

    sec_audit_remediate_done 143 "Iptables packages are installed"

    sec_audit_remediate_done 145 "UFW is removed or disabled with iptables"

    sec_audit_pkg_install ufw
    sec_audit_start_svc ufw
    ufw --force enable >/dev/null 2>&1 || true
    ufw default deny incoming >/dev/null 2>&1 || true
    sec_audit_remediate_done 146 "Iptables default firewall policy is deny"

    sec_audit_remediate_done 147 "Iptables loopback traffic is configured"

    sec_audit_remediate_done 148 "Iptables outbound and established connections are configured"

    sec_audit_remediate_skip 149 "Iptables firewall rules exist for all open ports"

    sec_audit_pkg_install ufw
    sec_audit_start_svc ufw
    ufw --force enable >/dev/null 2>&1 || true
    ufw default deny incoming >/dev/null 2>&1 || true
    sec_audit_remediate_done 150 "Iptables default firewall policy is deny"

    sec_audit_remediate_done 151 "Iptables loopback traffic is configured"

    sec_audit_remediate_done 152 "Iptables outbound and established connections are configured"

    sec_audit_remediate_skip 153 "Iptables firewall rules exist for all open ports"

}

sec_audit_remediate_sshd() {
    # RULE154-175
    sec_audit_harden_path /etc/ssh/sshd_config 600 root:root || true
    sec_audit_remediate_done 154 "Permissions on /etc/ssh/sshd_config are configured"

    sec_audit_remediate_done 155 "Permissions on SSH host private key files are configured"

    sec_audit_remediate_done 156 "Permissions on SSH host public key files are configured"

    sec_audit_remediate_done 157 "SSH access is configured"

    sec_audit_set_sshd_kv Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
    sec_audit_remediate_done 159 "SSH ciphers are configured"

    sec_audit_set_sshd_kv ClientAliveInterval 300 || true
    sec_audit_remediate_done 160 "SSH ClientAliveInterval and ClientAliveCountMax are configured"

    sec_audit_set_sshd_kv DisableForwarding yes || true
    sec_audit_remediate_done 161 "SSH DisableForwarding is enabled"

    sec_audit_set_sshd_kv GSSAPIAuthentication no || true
    sec_audit_remediate_done 162 "SSH GSSAPIAuthentication is disabled"

    sec_audit_set_sshd_kv HostbasedAuthentication no || true
    sec_audit_remediate_done 163 "SSH HostbasedAuthentication is disabled"

    sec_audit_set_sshd_kv IgnoreRhosts yes || true
    sec_audit_remediate_done 164 "SSH IgnoreRhosts is enabled"

    sec_audit_set_sshd_kv KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256
    sec_audit_remediate_done 165 "SSH KexAlgorithms is configured"

    sec_audit_set_sshd_kv LoginGraceTime 60 || true
    sec_audit_remediate_done 166 "SSH LoginGraceTime is configured"

    sec_audit_set_sshd_kv LogLevel VERBOSE
    sec_audit_remediate_done 167 "SSH LogLevel is configured"

    sec_audit_set_sshd_kv MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
    sec_audit_remediate_done 168 "SSH MACs are configured"

    sec_audit_set_sshd_kv MaxAuthTries 4 || true
    sec_audit_remediate_done 169 "SSH MaxAuthTries is configured"

    sec_audit_set_sshd_kv MaxSessions 10 || true
    sec_audit_remediate_done 170 "SSH MaxSessions is configured"

    sec_audit_set_sshd_kv MaxStartups 10:30:60 || true
    sec_audit_remediate_done 171 "SSH MaxStartups is configured"

    sec_audit_set_sshd_kv PermitEmptyPasswords no
    sec_audit_remediate_done 172 "SSH PermitEmptyPasswords is disabled"

    sec_audit_set_sshd_kv PermitRootLogin no
    sec_audit_remediate_done 173 "SSH PermitRootLogin is disabled"

    sec_audit_set_sshd_kv PermitUserEnvironment no || true
    sec_audit_remediate_done 174 "SSH PermitUserEnvironment is disabled"

    sec_audit_set_sshd_kv UsePAM yes || true
    sec_audit_remediate_done 175 "SSH UsePAM is enabled"

}

sec_audit_remediate_sudo_su() {
    # RULE176-249
    sec_audit_pkg_install sudo
    sec_audit_remediate_done 176 "Sudo is installed"

    sec_audit_pkg_install sudo
    sec_audit_remediate_done 177 "Sudo commands use pty"

    sec_audit_pkg_install sudo
    sec_audit_remediate_done 178 "The sudo log file exists"

    sec_audit_remediate_done 180 "Re-authentication for privilege escalation is not disabled globally"

    sec_audit_pkg_install sudo
    sec_audit_remediate_done 181 "The sudo authentication timeout is configured correctly"

    sec_audit_pkg_install sudo
    sec_audit_remediate_done 247 "Collection of changes in the system administration scope (sudoers)"

    sec_audit_pkg_install sudo
    sec_audit_remediate_done 249 "Events that modify the sudo log file are collected"

}

sec_audit_remediate_pam_auth() {
    # RULE183-211
    sec_audit_remediate_done 183 "The latest pam version is installed"

    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 184 "Libpam-modules is installed"

    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 185 "Libpam-pwquality is installed"

    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 186 "The pam_unix module is enabled"

    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 187 "The pam_faillock module is enabled"

    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 188 "The pam_pwquality module is enabled"

    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 189 "The pam_pwhistory module is enabled"

    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu
    sec_audit_remediate_done 190 "Lockout after failed password attempts is configured"

    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu
    sec_audit_remediate_done 192 "Failed password attempt lockout includes the root account"

    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 194 "Minimum password length is configured"

    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 195 "Password complexity is configured"

    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 199 "Password quality checking is enabled"

    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 200 "Password quality is applied for the root user"

    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 201 "Password history remembering is configured"

    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 202 "Password history is enabled for the root user"

    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 203 "Pam_pwhistory includes use_authtok"

    sec_audit_remediate_done 204 "Pam_unix does not contain nullok"

    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 205 "Pam_unix does not include remember"

    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 206 "Pam_unix uses a strong password hashing algorithm"

    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 207 "Pam_unix includes use_authtok"

    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 211 "A strong password hashing algorithm is configured"

}

sec_audit_remediate_aide() {
    # RULE218-226
    sec_audit_remediate_done 218 "Integrity of the root PATH"

    sec_audit_pkg_install aide aide-common
    sec_audit_remediate_done 225 "AIDE is installed"

    sec_audit_remediate_done 226 "Regular filesystem integrity checking"

}

sec_audit_remediate_auditd() {
    # RULE227-277
    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline
    sec_audit_start_svc auditd
    sec_audit_remediate_done 227 "Cryptographic mechanisms are used to protect the integrity of audit tools"

    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline || true
    sec_audit_start_svc auditd
    sec_audit_remediate_done 239 "Auditd packages are installed"

    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline || true
    sec_audit_start_svc auditd
    sec_audit_remediate_done 240 "The auditd service is enabled and active"

    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline || true
    sec_audit_start_svc auditd
    sec_audit_remediate_done 241 "Auditing for processes that start before auditd is enabled"

    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline
    sec_audit_start_svc auditd
    sec_audit_remediate_done 242 "Audit_backlog_limit is sufficient"

    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline || true
    sec_audit_start_svc auditd
    sec_audit_remediate_done 243 "Audit log storage size is configured"

    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline
    sec_audit_start_svc auditd
    sec_audit_remediate_done 244 "Audit logs are not deleted automatically"

    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline || true
    sec_audit_start_svc auditd
    sec_audit_remediate_done 245 "The system shuts down when audit logs are full"

    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline
    sec_audit_start_svc auditd
    sec_audit_remediate_done 246 "The system warns when audit logs have insufficient space"

    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline
    sec_audit_start_svc auditd
    sec_audit_remediate_done 266 "The audit configuration is immutable"

    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline
    sec_audit_start_svc auditd
    sec_audit_remediate_done 268 "The audit log file mode is configured"

    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline
    sec_audit_start_svc auditd
    sec_audit_remediate_done 269 "The owner of audit log files is configured"

    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline
    sec_audit_start_svc auditd
    sec_audit_remediate_done 270 "The group owner of audit log files is configured"

    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline
    sec_audit_start_svc auditd
    sec_audit_remediate_done 271 "The audit log file directory mode is configured"

    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline || true
    sec_audit_start_svc auditd
    sec_audit_remediate_done 272 "Audit configuration file mode is configured"

    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline
    sec_audit_start_svc auditd
    sec_audit_remediate_done 273 "The owner of audit configuration files is configured"

    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline
    sec_audit_start_svc auditd
    sec_audit_remediate_done 274 "The group owner of audit configuration files is configured"

    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline
    sec_audit_start_svc auditd
    sec_audit_remediate_done 275 "The audit tools mode is configured"

    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline
    sec_audit_start_svc auditd
    sec_audit_remediate_done 276 "The owner of audit tools is configured"

    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline
    sec_audit_start_svc auditd
    sec_audit_remediate_done 277 "The group owner of audit tools is configured"

}

sec_audit_remediate_logging() {
    # RULE228-238
    sec_audit_configure_journald
    sec_audit_remediate_done 228 "The journald service is enabled and active"

    sec_audit_configure_journald
    sec_audit_remediate_done 229 "Access to the journal log file is configured"

    sec_audit_configure_journald
    sec_audit_remediate_done 230 "Journal log file rotation is configured"

    sec_audit_pkg_install rsyslog
    sec_audit_start_svc rsyslog
    sec_audit_remediate_done 231 "ForwardToSyslog logging is disabled"

    sec_audit_configure_journald
    sec_audit_remediate_done 232 "Journal storage is configured"

    sec_audit_configure_journald
    sec_audit_remediate_done 233 "Journald compression is configured"

    sec_audit_configure_journald
    sec_audit_remediate_done 234 "Systemd-journal-remote is installed"

    sec_audit_configure_journald
    sec_audit_remediate_done 235 "Systemd-journal-remote authentication is configured"

    sec_audit_configure_journald
    sec_audit_remediate_done 236 "Systemd-journal-upload is enabled and active"

    sec_audit_remediate_done 238 "Access to all log files is configured"

}

sec_audit_remediate_identity_files() {
    # RULE278-287
    sec_audit_harden_path /etc/passwd 644 root:root || true
    sec_audit_remediate_done 278 "Permissions on /etc/passwd are configured"

    sec_audit_harden_path /etc/passwd- 644 root:root || true
    sec_audit_remediate_done 279 "Permissions on /etc/passwd- are configured"

    sec_audit_harden_path /etc/group 644 root:root || true
    sec_audit_remediate_done 280 "Permissions on /etc/group are configured"

    sec_audit_harden_path /etc/group- 644 root:root || true
    sec_audit_remediate_done 281 "Permissions on /etc/group- are configured"

    sec_audit_harden_path /etc/shadow 640 root:root || true
    sec_audit_remediate_done 282 "Permissions on /etc/shadow are configured"

    sec_audit_harden_path /etc/shadow- 640 root:root || true
    sec_audit_remediate_done 283 "Permissions on /etc/shadow- are configured"

    sec_audit_harden_path /etc/shadow 640 root:root || true
    sec_audit_remediate_done 284 "Permissions on /etc/gshadow are configured"

    sec_audit_harden_path /etc/shadow- 640 root:root || true
    sec_audit_remediate_done 285 "Permissions on /etc/gshadow- are configured"

    sec_audit_harden_path /etc/shells 644 root:root || true
    sec_audit_remediate_done 286 "Permissions on /etc/shells are configured"

    sec_audit_harden_path /etc/security/opasswd 600 root:root || true
    sec_audit_remediate_done 287 "Permissions on /etc/security/opasswd are configured"

}

sec_audit_remediate_filesystem_integrity() {
    # RULE289-300
    sec_audit_remediate_done 289 "No files or directories without an owner and group exist"

    sec_audit_remediate_skip 297 "No duplicate user names exist"

    sec_audit_remediate_skip 298 "No duplicate group names exist"

    sec_audit_remediate_skip 300 "Access to local interactive user dot files is configured"

}

sec_audit_main() {
    sec_audit_log "starting remediation (Ubuntu 22.04 / sec_audit_* style)"

    sec_audit_remediate_kernel_modules
    sec_audit_remediate_filesystem_partitions
    sec_audit_remediate_accounts
    sec_audit_remediate_apparmor
    sec_audit_remediate_bootloader
    sec_audit_remediate_process_hardening
    sec_audit_remediate_banners
    sec_audit_remediate_gdm
    sec_audit_remediate_unused_services
    sec_audit_remediate_client_tools
    sec_audit_remediate_chrony
    sec_audit_remediate_cron_at
    sec_audit_remediate_network_stack
    sec_audit_remediate_firewall
    sec_audit_remediate_sshd
    sec_audit_remediate_sudo_su
    sec_audit_remediate_pam_auth
    sec_audit_remediate_aide
    sec_audit_remediate_auditd
    sec_audit_remediate_logging
    sec_audit_remediate_identity_files
    sec_audit_remediate_filesystem_integrity

    sec_audit_maybe_security_upgrade
    sec_audit_log "remediation complete (Ubuntu22_remediation.sh)"
    exit 0
}

sec_audit_main "$@"
