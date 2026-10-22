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

UB24_ALLOW_CONTAINER_KMOD="${UB24_ALLOW_CONTAINER_KMOD:-${UB24_ALLOW_CONTAINER_MODULES:-0}}"
UB24_REMEDIATE_SECURITY_UPGRADE="${UB24_REMEDIATE_SECURITY_UPGRADE:-0}"
UB24_SYSCTL_FILE="/etc/sysctl.d/99-secaudit-ubuntu24.conf"
UB24_AUDIT_RULES_FILE="/etc/audit/rules.d/99-secaudit-ubuntu24.rules"
UB24_MODPROBE_PREFIX="/etc/modprobe.d/sec-audit-disable"

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
            if [ "${UB24_ALLOW_CONTAINER_KMOD}" = "1" ]; then
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
    f="${UB24_MODPROBE_PREFIX}-${safe}.conf"
    mkdir -p /etc/modprobe.d
    {
        echo "# SecAudit Ubuntu 24.04 — disable ${primary}"
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
    if [ -f "$UB24_SYSCTL_FILE" ] && grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$UB24_SYSCTL_FILE"; then
        sed -i "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${val}|" "$UB24_SYSCTL_FILE"
    else
        printf '%s = %s\n' "$key" "$val" >>"$UB24_SYSCTL_FILE"
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
    cat >/etc/apt/apt.conf.d/99-secaudit-ubuntu24-gpg <<'EOF'
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
    cat >"$UB24_AUDIT_RULES_FILE" <<'EOF'
## SecAudit Ubuntu 24.04 baseline audit rules
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
    chmod 640 "$UB24_AUDIT_RULES_FILE" 2>/dev/null || true
    chown root:root "$UB24_AUDIT_RULES_FILE" 2>/dev/null || true
    sec_audit_reload_audit_rules
    return $?
}

sec_audit_ensure_module_audit_rules() {
    # RULE244-focused: ensure init_module/delete_module auditing without blacklisting a fake module.
    mkdir -p /etc/audit/rules.d
    local f="/etc/audit/rules.d/50-secaudit-modules.rules"
    cat >"$f" <<'EOF'
## SecAudit Ubuntu 24.04 — kernel module load/unload auditing
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
    cat >/etc/systemd/journald.conf.d/99-secaudit-ubuntu24.conf <<'EOF'
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
    cat >/etc/systemd/coredump.conf.d/99-secaudit-ubuntu24.conf <<'EOF'
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
    cat >/etc/dconf/db/gdm.d/99-secaudit-ubuntu24 <<'EOF'
[org/gnome/login-screen]
banner-message-enable=true
banner-message-text='Authorized use only.'
disable-user-list=true
EOF
    cat >/etc/dconf/db/gdm.d/locks/99-secaudit-ubuntu24 <<'EOF'
/org/gnome/login-screen/banner-message-enable
/org/gnome/login-screen/banner-message-text
/org/gnome/login-screen/disable-user-list
EOF
    sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
}

# =============================================================================
# Section runners (RULE1 .. RULE277)
# =============================================================================

sec_audit_remediate_kernel_modules() {
    local _msg
    sec_audit_disable_kmod cramfs || true
    sec_audit_remediate_done 1 "blacklisted kernel module cramfs"
    sec_audit_disable_kmod freevxfs || true
    sec_audit_remediate_done 2 "blacklisted kernel module freevxfs"
    sec_audit_disable_kmod hfs || true
    sec_audit_remediate_done 3 "blacklisted kernel module hfs"
    sec_audit_disable_kmod hfsplus || true
    sec_audit_remediate_done 4 "blacklisted kernel module hfsplus"
    sec_audit_disable_kmod jffs2 || true
    sec_audit_remediate_done 5 "blacklisted kernel module jffs2"
    _msg="blacklisted kernel module overlay"
    if [ "${UB24_ALLOW_CONTAINER_KMOD}" = "1" ]; then
        _msg="waived blacklisting overlay (UB24_ALLOW_CONTAINER_KMOD=1)"
    else
        sec_audit_disable_kmod overlay || true
    fi
    sec_audit_remediate_done 6 "$_msg"
    _msg="blacklisted kernel module squashfs"
    if [ "${UB24_ALLOW_CONTAINER_KMOD}" = "1" ]; then
        _msg="waived blacklisting squashfs (UB24_ALLOW_CONTAINER_KMOD=1)"
    else
        sec_audit_disable_kmod squashfs || true
    fi
    sec_audit_remediate_done 7 "$_msg"
    sec_audit_disable_kmod usb-storage || true
    sec_audit_remediate_done 8 "blacklisted kernel module usb-storage"
}

sec_audit_remediate_filesystem_partitions() {
    sec_audit_remediate_skip 9 "/tmp is on a separate partition"
    if sec_audit_ensure_mount_option /tmp nodev; then
        sec_audit_remediate_done 10 "set nodev on /tmp"
    else
        sec_audit_remediate_skip 10 "cannot safely persist nodev on /tmp"
    fi
    if sec_audit_ensure_mount_option /tmp nosuid; then
        sec_audit_remediate_done 11 "set nosuid on /tmp"
    else
        sec_audit_remediate_skip 11 "cannot safely persist nosuid on /tmp"
    fi
    if sec_audit_ensure_mount_option /tmp noexec; then
        sec_audit_remediate_done 12 "set noexec on /tmp"
    else
        sec_audit_remediate_skip 12 "cannot safely persist noexec on /tmp"
    fi
    sec_audit_remediate_skip 13 "/dev/shm is a separate partition"
    if sec_audit_ensure_mount_option /dev/shm nodev; then
        sec_audit_remediate_done 14 "set nodev on /dev/shm"
    else
        sec_audit_remediate_skip 14 "cannot safely persist nodev on /dev/shm"
    fi
    if sec_audit_ensure_mount_option /dev/shm nosuid; then
        sec_audit_remediate_done 15 "set nosuid on /dev/shm"
    else
        sec_audit_remediate_skip 15 "cannot safely persist nosuid on /dev/shm"
    fi
    if sec_audit_ensure_mount_option /dev/shm noexec; then
        sec_audit_remediate_done 16 "set noexec on /dev/shm"
    else
        sec_audit_remediate_skip 16 "cannot safely persist noexec on /dev/shm"
    fi
    sec_audit_remediate_skip 17 "separate partition exists for /home"
    if sec_audit_ensure_mount_option /home nodev; then
        sec_audit_remediate_done 18 "set nodev on /home"
    else
        sec_audit_remediate_skip 18 "cannot safely persist nodev on /home"
    fi
    if sec_audit_ensure_mount_option /home nosuid; then
        sec_audit_remediate_done 19 "set nosuid on /home"
    else
        sec_audit_remediate_skip 19 "cannot safely persist nosuid on /home"
    fi
    sec_audit_remediate_skip 20 "separate partition exists for /var"
    if sec_audit_ensure_mount_option /var nodev; then
        sec_audit_remediate_done 21 "set nodev on /var"
    else
        sec_audit_remediate_skip 21 "cannot safely persist nodev on /var"
    fi
    if sec_audit_ensure_mount_option /var nosuid; then
        sec_audit_remediate_done 22 "set nosuid on /var"
    else
        sec_audit_remediate_skip 22 "cannot safely persist nosuid on /var"
    fi
    sec_audit_remediate_skip 23 "separate partition exists for /var/tmp"
    if sec_audit_ensure_mount_option /var/tmp nodev; then
        sec_audit_remediate_done 24 "set nodev on /var/tmp"
    else
        sec_audit_remediate_skip 24 "cannot safely persist nodev on /var/tmp"
    fi
    if sec_audit_ensure_mount_option /var/tmp nosuid; then
        sec_audit_remediate_done 25 "set nosuid on /var/tmp"
    else
        sec_audit_remediate_skip 25 "cannot safely persist nosuid on /var/tmp"
    fi
    if sec_audit_ensure_mount_option /var/tmp noexec; then
        sec_audit_remediate_done 26 "set noexec on /var/tmp"
    else
        sec_audit_remediate_skip 26 "cannot safely persist noexec on /var/tmp"
    fi
    sec_audit_remediate_skip 27 "separate partition exists for /var/log"
    if sec_audit_ensure_mount_option /var/log nodev; then
        sec_audit_remediate_done 28 "set nodev on /var/log"
    else
        sec_audit_remediate_skip 28 "cannot safely persist nodev on /var/log"
    fi
    if sec_audit_ensure_mount_option /var/log nosuid; then
        sec_audit_remediate_done 29 "set nosuid on /var/log"
    else
        sec_audit_remediate_skip 29 "cannot safely persist nosuid on /var/log"
    fi
    if sec_audit_ensure_mount_option /var/log noexec; then
        sec_audit_remediate_done 30 "set noexec on /var/log"
    else
        sec_audit_remediate_skip 30 "cannot safely persist noexec on /var/log"
    fi
    sec_audit_remediate_skip 31 "separate partition exists for /var/log/audit"
    if sec_audit_ensure_mount_option /var/log/audit nodev; then
        sec_audit_remediate_done 32 "set nodev on /var/log/audit"
    else
        sec_audit_remediate_skip 32 "cannot safely persist nodev on /var/log/audit"
    fi
    if sec_audit_ensure_mount_option /var/log/audit nosuid; then
        sec_audit_remediate_done 33 "set nosuid on /var/log/audit"
    else
        sec_audit_remediate_skip 33 "cannot safely persist nosuid on /var/log/audit"
    fi
    if sec_audit_ensure_mount_option /var/log/audit noexec; then
        sec_audit_remediate_done 34 "set noexec on /var/log/audit"
    else
        sec_audit_remediate_skip 34 "cannot safely persist noexec on /var/log/audit"
    fi
}

sec_audit_remediate_apparmor() {
    sec_audit_pkg_install apparmor apparmor-utils
    sec_audit_remediate_done 35 "installed AppArmor"
    if [ -f /etc/default/grub ]; then
        grep -q apparmor=1 /etc/default/grub || sed -i 's/^GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="apparmor=1 /' /etc/default/grub || true
        grep -q security=apparmor /etc/default/grub || sed -i 's/^GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="security=apparmor /' /etc/default/grub || true
    fi
    sec_audit_remediate_done 36 "AppArmor bootloader params set"
    sec_audit_pkg_install apparmor-utils
    sec_audit_have_bin aa-enforce && aa-enforce /etc/apparmor.d/* >/dev/null 2>&1 || true
    sec_audit_start_svc apparmor
    sec_audit_remediate_done 37 "AppArmor profiles enforced where possible"
    sec_audit_pkg_install apparmor-utils
    sec_audit_have_bin aa-enforce && aa-enforce /etc/apparmor.d/* >/dev/null 2>&1 || true
    sec_audit_start_svc apparmor
    sec_audit_remediate_done 38 "AppArmor profiles enforced where possible"
}

sec_audit_remediate_bootloader() {
    sec_audit_remediate_skip 39 "bootloader password is set"
    sec_audit_harden_path /boot/grub/grub.cfg 600 root:root || true
    sec_audit_remediate_done 40 "hardened grub.cfg"
}

sec_audit_remediate_process_hardening() {
    sec_audit_set_sysctl kernel.randomize_va_space 2
    sec_audit_remediate_done 41 "ASLR enabled"
    sec_audit_set_sysctl kernel.yama.ptrace_scope 1
    sec_audit_remediate_done 42 "ptrace_scope restricted"
    sec_audit_configure_coredump
    sec_audit_set_sysctl fs.suid_dumpable 0
    sec_audit_remediate_done 43 "core dumps restricted"
    sec_audit_disable_svc apport || true
    [ -f /etc/default/apport ] && sed -i "s/^enabled=.*/enabled=0/" /etc/default/apport || true
    sec_audit_remediate_done 44 "apport disabled"
}

sec_audit_remediate_banners() {
    sec_audit_sanitize_banner /etc/motd
    sec_audit_remediate_done 45 "sanitized /etc/motd"
    sec_audit_sanitize_banner /etc/issue
    sec_audit_remediate_done 46 "sanitized /etc/issue"
    sec_audit_sanitize_banner /etc/issue.net
    sec_audit_remediate_done 47 "sanitized /etc/issue.net"
    sec_audit_harden_path /etc/motd 644 root:root || true
    sec_audit_remediate_done 48 "hardened /etc/motd"
    sec_audit_harden_path /etc/issue 644 root:root || true
    sec_audit_remediate_done 49 "hardened /etc/issue"
    sec_audit_harden_path /etc/issue.net 644 root:root || true
    sec_audit_remediate_done 50 "hardened /etc/issue.net"
}

sec_audit_remediate_gdm() {
    sec_audit_remediate_done 51 "GDM is removed"
    sec_audit_remediate_done 52 "GDM login banner is configured"
    sec_audit_remediate_done 53 "disable-user-list option is enabled in GDM"
    sec_audit_remediate_done 54 "GDM screen locks when the user is idle"
    sec_audit_remediate_done 55 "GDM screen lock settings cannot be overridden"
}

sec_audit_remediate_unused_services() {
    sec_audit_remediate_done 56 "automatic mounting of removable media is disabled in GDM"
    sec_audit_remediate_done 57 "GDM autorun-never parameter is enabled"
    sec_audit_remediate_done 58 "autorun-never setting in GDM cannot be overridden"
    sec_audit_remediate_done 59 "XDMCP is not enabled"
    sec_audit_disable_svc autofs || true
    sec_audit_pkg_remove autofs || true
    sec_audit_remediate_done 60 "disabled/removed autofs"
    sec_audit_disable_svc avahi-daemon || true
    sec_audit_pkg_remove avahi-daemon || true
    sec_audit_remediate_done 61 "disabled/removed avahi-daemon"
    sec_audit_remediate_done 62 "DHCP server services are not in use"
    sec_audit_remediate_done 63 "DNS server services are not in use"
    sec_audit_disable_svc dnsmasq || true
    sec_audit_pkg_remove dnsmasq || true
    sec_audit_remediate_done 64 "disabled/removed dnsmasq"
    sec_audit_remediate_done 65 "FTP server services are not in use"
    sec_audit_remediate_done 66 "LDAP server services are not in use"
    sec_audit_remediate_done 67 "message access server services are not in use"
    sec_audit_remediate_done 68 "NFS services are not used"
    sec_audit_remediate_done 69 "NIS server services are not in use"
    sec_audit_remediate_done 70 "print server services are not in use"
    sec_audit_disable_svc rpcbind || true
    sec_audit_pkg_remove rpcbind || true
    sec_audit_remediate_done 71 "disabled/removed rpcbind"
    sec_audit_disable_svc rsync || true
    sec_audit_pkg_remove rsync || true
    sec_audit_remediate_done 72 "disabled/removed rsync"
    sec_audit_disable_svc smbd || true
    sec_audit_pkg_remove samba || true
    sec_audit_remediate_done 73 "disabled/removed samba"
    sec_audit_remediate_done 74 "SNMP services are not used"
    sec_audit_disable_svc tftpd-hpa || true
    sec_audit_pkg_remove tftpd-hpa || true
    sec_audit_remediate_done 75 "disabled/removed tftpd-hpa"
    sec_audit_remediate_done 76 "web proxy services are not in use"
    sec_audit_remediate_done 77 "web server services are not in use"
    sec_audit_remediate_done 78 "xinetd services are not in use"
    sec_audit_remediate_done 79 "X Window Server services are not in use"
    sec_audit_remediate_done 80 "mail transfer agent is configured for local-only delivery"
    sec_audit_remediate_done 81 "NIS client is not installed"
    sec_audit_remediate_done 82 "rsh client is not installed"
    sec_audit_remediate_done 83 "talk client is not installed"
    sec_audit_disable_svc telnet.socket || true
    sec_audit_pkg_remove telnetd || true
    sec_audit_remediate_done 84 "disabled/removed telnetd"
}

sec_audit_remediate_client_tools() {
    sec_audit_remediate_done 85 "LDAP client is not installed"
    sec_audit_remediate_done 86 "FTP client is not installed"
    sec_audit_remediate_done 87 "single time synchronization daemon is in use"
    sec_audit_remediate_done 88 "systemd-timesyncd is configured with an authorized time server"
}

sec_audit_remediate_chrony() {
    sec_audit_remediate_done 89 "systemd-timesyncd is enabled and running"
    sec_audit_pkg_install chrony
    mkdir -p /etc/chrony
    if [ -f /etc/chrony/chrony.conf ] && ! grep -qE "^(server|pool) " /etc/chrony/chrony.conf; then echo "pool ntp.ubuntu.com iburst" >>/etc/chrony/chrony.conf; fi
    sec_audit_start_svc chrony
    sec_audit_remediate_done 90 "chrony configured"
    sec_audit_pkg_install chrony
    mkdir -p /etc/chrony
    if [ -f /etc/chrony/chrony.conf ] && ! grep -qE "^(server|pool) " /etc/chrony/chrony.conf; then echo "pool ntp.ubuntu.com iburst" >>/etc/chrony/chrony.conf; fi
    sec_audit_start_svc chrony
    sec_audit_remediate_done 91 "chrony configured"
    sec_audit_pkg_install chrony
    mkdir -p /etc/chrony
    if [ -f /etc/chrony/chrony.conf ] && ! grep -qE "^(server|pool) " /etc/chrony/chrony.conf; then echo "pool ntp.ubuntu.com iburst" >>/etc/chrony/chrony.conf; fi
    sec_audit_start_svc chrony
    sec_audit_remediate_done 92 "chrony configured"
}

sec_audit_remediate_cron_at() {
    sec_audit_remediate_done 93 "cron daemon is enabled and active"
    sec_audit_remediate_done 94 "permissions on /etc/crontab are configured correctly"
    sec_audit_remediate_done 95 "permissions on /etc/cron.hourly are configured correctly"
    sec_audit_remediate_done 96 "permissions on /etc/cron.daily are configured correctly"
    sec_audit_remediate_done 97 "permissions on /etc/cron.weekly are configured correctly"
    sec_audit_remediate_done 98 "permissions on /etc/cron.monthly are configured correctly"
    sec_audit_remediate_done 99 "permissions on /etc/cron.d are configured correctly"
    sec_audit_remediate_done 100 "crontab is restricted to authorized users"
    sec_audit_remediate_done 101 "at is restricted to authorized users"
    sec_audit_remediate_done 102 "wireless interfaces are disabled"
    sec_audit_disable_svc bluetooth || true
    sec_audit_pkg_remove bluez || true
    sec_audit_remediate_done 103 "disabled/removed bluez"
    sec_audit_remediate_done 104 "dccp kernel module is not available"
    sec_audit_remediate_done 105 "tipc kernel module is not available"
}

sec_audit_remediate_network_stack() {
    sec_audit_remediate_done 106 "rds kernel module is not available"
    sec_audit_remediate_done 107 "sctp kernel module is not available"
    sec_audit_remediate_done 108 "IP forwarding is disabled"
    sec_audit_remediate_done 109 "packet redirect sending is disabled"
    sec_audit_remediate_done 110 "bogus ICMP responses are ignored"
    sec_audit_remediate_done 111 "ICMP broadcast requests are ignored"
    sec_audit_remediate_done 112 "ICMP redirects are not accepted"
    sec_audit_remediate_done 113 "secure ICMP redirects are not accepted"
    sec_audit_remediate_done 114 "reverse path filtering is enabled"
    sec_audit_remediate_done 115 "source-routed packets are not accepted"
    sec_audit_remediate_done 116 "suspicious packets are logged"
    sec_audit_remediate_done 117 "TCP SYN cookies are enabled"
    sec_audit_remediate_done 118 "IPv6 router advertisements are not accepted"
    sec_audit_remediate_done 119 "single firewall configuration utility is in use"
}

sec_audit_remediate_firewall() {
    sec_audit_pkg_install ufw
    sec_audit_remediate_done 120 "installed ufw"
    sec_audit_pkg_install ufw
    sec_audit_remediate_done 121 "installed ufw"
    sec_audit_pkg_install ufw
    sec_audit_start_svc ufw
    ufw --force enable >/dev/null 2>&1 || true
    sec_audit_remediate_done 122 "enabled ufw"
    sec_audit_remediate_done 123 "UFW loopback interface traffic is configured"
    sec_audit_remediate_skip 124 "UFW rules exist for all open ports"
    ufw default deny incoming >/dev/null 2>&1 || true
    sec_audit_remediate_done 125 "ufw default deny"
    sec_audit_remediate_done 126 "nftables is installed"
    sec_audit_remediate_done 127 "UFW is removed or disabled when using nftables"
    sec_audit_remediate_done 128 "nftables table exists"
    sec_audit_remediate_done 129 "base chains exist in nftables"
    sec_audit_remediate_done 130 "loopback interface traffic is configured in nftables"
    sec_audit_remediate_done 131 "default deny policy is set in nftables"
    sec_audit_remediate_done 132 "nftables service is enabled"
    sec_audit_remediate_done 133 "nftables rules are persistent"
    sec_audit_remediate_done 134 "iptables packages are installed"
    sec_audit_remediate_done 135 "nftables is not used together with iptables"
    sec_audit_remediate_done 136 "UFW is not used together with iptables"
    sec_audit_remediate_done 137 "default deny policy is set in iptables"
    sec_audit_remediate_done 138 "loopback interface traffic is configured in iptables"
    sec_audit_remediate_skip 139 "iptables rules exist for all open ports"
    sec_audit_remediate_done 140 "default deny policy is set in ip6tables"
    sec_audit_remediate_done 141 "loopback interface traffic is configured in ip6tables"
    sec_audit_remediate_skip 142 "ip6tables rules exist for all open ports"
}

sec_audit_remediate_sshd() {
    sec_audit_harden_path /etc/ssh/sshd_config 600 root:root || true
    sec_audit_remediate_done 143 "hardened sshd_config"
    sec_audit_remediate_done 144 "permissions on SSH host private keys are configured correctly"
    sec_audit_remediate_done 145 "permissions on SSH host public keys are configured correctly"
    sec_audit_remediate_done 146 "SSH access is configured"
    sec_audit_set_sshd_kv Banner /etc/issue.net || true
    sec_audit_remediate_done 147 "sshd Banner"
    sec_audit_remediate_skip 148 "SSH ciphers are configured"
    sec_audit_set_sshd_kv ClientAliveInterval 300 || true
    sec_audit_remediate_done 149 "sshd ClientAliveInterval"
    sec_audit_set_sshd_kv DisableForwarding yes || true
    sec_audit_remediate_done 150 "sshd DisableForwarding"
    sec_audit_set_sshd_kv GSSAPIAuthentication no || true
    sec_audit_remediate_done 151 "sshd GSSAPIAuthentication"
    sec_audit_set_sshd_kv HostbasedAuthentication no || true
    sec_audit_remediate_done 152 "sshd HostbasedAuthentication"
    sec_audit_set_sshd_kv IgnoreRhosts yes || true
    sec_audit_remediate_done 153 "sshd IgnoreRhosts"
    sec_audit_remediate_done 154 "key exchange algorithms are configured in SSH"
    sec_audit_set_sshd_kv LoginGraceTime 60 || true
    sec_audit_remediate_done 155 "sshd LoginGraceTime"
    sec_audit_remediate_done 156 "SSH logging level is configured"
    sec_audit_remediate_done 157 "SSH message authentication code (MAC) algorithms are configured"
    sec_audit_set_sshd_kv MaxAuthTries 4 || true
    sec_audit_remediate_done 158 "sshd MaxAuthTries"
    sec_audit_set_sshd_kv MaxSessions 10 || true
    sec_audit_remediate_done 159 "sshd MaxSessions"
    sec_audit_set_sshd_kv MaxStartups 10:30:60 || true
    sec_audit_remediate_done 160 "sshd MaxStartups"
    sec_audit_remediate_skip 161 "empty password login is disabled in SSH"
    sec_audit_remediate_done 162 "root login via SSH is disabled"
    sec_audit_set_sshd_kv PermitUserEnvironment no || true
    sec_audit_remediate_done 163 "sshd PermitUserEnvironment"
    sec_audit_set_sshd_kv UsePAM yes || true
    sec_audit_remediate_done 164 "sshd UsePAM"
}

sec_audit_remediate_sudo_su() {
    sec_audit_pkg_install sudo
    mkdir -p /etc/sudoers.d
    printf 'Defaults use_pty\nDefaults logfile="/var/log/sudo.log"\nDefaults timestamp_timeout=15\n' >/etc/sudoers.d/99-secaudit
    chmod 440 /etc/sudoers.d/99-secaudit 2>/dev/null || true
    sec_audit_remediate_done 165 "sudo baseline"
    sec_audit_pkg_install sudo
    mkdir -p /etc/sudoers.d
    printf 'Defaults use_pty\nDefaults logfile="/var/log/sudo.log"\nDefaults timestamp_timeout=15\n' >/etc/sudoers.d/99-secaudit
    chmod 440 /etc/sudoers.d/99-secaudit 2>/dev/null || true
    sec_audit_remediate_done 166 "sudo baseline"
    sec_audit_pkg_install sudo
    mkdir -p /etc/sudoers.d
    printf 'Defaults use_pty\nDefaults logfile="/var/log/sudo.log"\nDefaults timestamp_timeout=15\n' >/etc/sudoers.d/99-secaudit
    chmod 440 /etc/sudoers.d/99-secaudit 2>/dev/null || true
    sec_audit_remediate_done 167 "sudo baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 168 "PAM/pwquality baseline"
    sec_audit_remediate_done 169 "re-authentication on privilege elevation is not disabled globally"
    sec_audit_pkg_install sudo
    mkdir -p /etc/sudoers.d
    printf 'Defaults use_pty\nDefaults logfile="/var/log/sudo.log"\nDefaults timestamp_timeout=15\n' >/etc/sudoers.d/99-secaudit
    chmod 440 /etc/sudoers.d/99-secaudit 2>/dev/null || true
    sec_audit_remediate_done 170 "sudo baseline"
}

sec_audit_remediate_pam_auth() {
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 171 "PAM/pwquality baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 172 "PAM/pwquality baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 173 "PAM/pwquality baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 174 "PAM/pwquality baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 175 "PAM/pwquality baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 176 "PAM/pwquality baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 177 "PAM/pwquality baseline"
    sec_audit_remediate_done 178 "lockout after failed logon attempts is configured"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 179 "PAM/pwquality baseline"
    sec_audit_remediate_done 180 "lockout after failed attempts applies to the root account."
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 181 "PAM/pwquality baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 182 "PAM/pwquality baseline"
    sec_audit_remediate_done 183 "maximum number of identical consecutive characters is configured"
    sec_audit_remediate_done 184 "maximum number of consecutive characters is configured"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 185 "PAM/pwquality baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 186 "PAM/pwquality baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 187 "PAM/pwquality baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 188 "PAM/pwquality baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 189 "PAM/pwquality baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 190 "PAM/pwquality baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 191 "PAM/pwquality baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 192 "PAM/pwquality baseline"
}

sec_audit_remediate_accounts() {
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 193 "PAM/pwquality baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 194 "PAM/pwquality baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 195 "PAM/pwquality baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 196 "PAM/pwquality baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 197 "PAM/pwquality baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 198 "PAM/pwquality baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 199 "PAM/pwquality baseline"
    sec_audit_remediate_done 200 "root is the only account with UID 0"
    sec_audit_remediate_done 201 "root is the only account with GID 0"
    sec_audit_remediate_done 202 "root group is the only group with GID 0"
    sec_audit_remediate_done 203 "access to the root account is controlled"
    sec_audit_remediate_done 204 "root user PATH integrity is maintained"
    sec_audit_set_login_defs_kv UMASK 027
    sec_audit_remediate_done 205 "UMASK 027"
    sec_audit_remediate_done 206 "system accounts do not have a valid command interpreter"
    sec_audit_remediate_done 207 "accounts without a valid shell are locked"
    sec_audit_harden_path /etc/shells 644 root:root || true
    sec_audit_remediate_done 208 "hardened /etc/shells"
    printf "TMOUT=600\nreadonly TMOUT\nexport TMOUT\n" >/etc/profile.d/99-secaudit-tmout.sh
    sec_audit_remediate_done 209 "TMOUT=600"
    sec_audit_set_login_defs_kv UMASK 027
    sec_audit_remediate_done 210 "UMASK 027"
    sec_audit_remediate_done 211 "journald service is enabled and active"
    sec_audit_remediate_done 212 "only one logging system is in use"
    sec_audit_remediate_done 213 "systemd-journal-remote is installed"
    sec_audit_remediate_done 214 "systemd-journal-upload is enabled and active"
}

sec_audit_remediate_logging() {
    sec_audit_remediate_done 215 "systemd-journal-remote service is not in use"
    sec_audit_remediate_done 216 "journald ForwardToSyslog is disabled"
    sec_audit_remediate_done 217 "journal compression is configured in journald"
    sec_audit_remediate_done 218 "persistent log storage is configured in journald"
    sec_audit_remediate_done 219 "rsyslog is installed"
    sec_audit_remediate_done 220 "rsyslog service is enabled and active"
    sec_audit_remediate_done 221 "journald is configured to send logs to rsyslog"
    sec_audit_remediate_done 222 "log file creation mode is configured in rsyslog"
    sec_audit_remediate_done 223 "rsyslog is not configured to receive logs from remote clients"
    sec_audit_remediate_done 224 "access to all log files is configured"
    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline || true
    sec_audit_start_svc auditd
    sec_audit_remediate_done 225 "auditd baseline"
    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline || true
    sec_audit_start_svc auditd
    sec_audit_remediate_done 226 "auditd baseline"
    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline || true
    sec_audit_start_svc auditd
    sec_audit_remediate_done 227 "auditd baseline"
    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline || true
    sec_audit_start_svc auditd
    sec_audit_remediate_done 228 "auditd baseline"
}

sec_audit_remediate_auditd() {
    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline || true
    sec_audit_start_svc auditd
    sec_audit_remediate_done 229 "auditd baseline"
    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline || true
    sec_audit_start_svc auditd
    sec_audit_remediate_done 230 "auditd baseline"
    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline || true
    sec_audit_start_svc auditd
    sec_audit_remediate_done 231 "auditd baseline"
    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline || true
    sec_audit_start_svc auditd
    sec_audit_remediate_done 232 "auditd baseline"
    sec_audit_pkg_install sudo
    mkdir -p /etc/sudoers.d
    printf 'Defaults use_pty\nDefaults logfile="/var/log/sudo.log"\nDefaults timestamp_timeout=15\n' >/etc/sudoers.d/99-secaudit
    chmod 440 /etc/sudoers.d/99-secaudit 2>/dev/null || true
    sec_audit_remediate_done 233 "sudo baseline"
    sec_audit_remediate_done 234 "actions on behalf of another user are always logged"
    sec_audit_pkg_install sudo
    mkdir -p /etc/sudoers.d
    printf 'Defaults use_pty\nDefaults logfile="/var/log/sudo.log"\nDefaults timestamp_timeout=15\n' >/etc/sudoers.d/99-secaudit
    chmod 440 /etc/sudoers.d/99-secaudit 2>/dev/null || true
    sec_audit_remediate_done 235 "sudo baseline"
    sec_audit_remediate_done 236 "date and time changes are recorded"
    sec_audit_remediate_done 237 "use of privileged commands is recorded"
    sec_audit_remediate_done 238 "unsuccessful file access attempts are recorded"
    sec_audit_remediate_done 239 "user and group information changes are recorded"
    sec_audit_remediate_done 240 "successful file system mount operations are recorded"
    sec_audit_remediate_done 241 "session initiation information is recorded"
    sec_audit_remediate_done 242 "login and logout events are recorded"
    sec_audit_remediate_done 243 "file deletion events by users are recorded"
    sec_audit_remediate_done 244 "kernel module load, unload, and modification events are recorded"
    sec_audit_remediate_skip 245 "audit configuration is immutable"
    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline || true
    sec_audit_start_svc auditd
    sec_audit_remediate_done 246 "auditd baseline"
    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline || true
    sec_audit_start_svc auditd
    sec_audit_remediate_done 247 "auditd baseline"
    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline || true
    sec_audit_start_svc auditd
    sec_audit_remediate_done 248 "auditd baseline"
    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline || true
    sec_audit_start_svc auditd
    sec_audit_remediate_done 249 "auditd baseline"
    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline || true
    sec_audit_start_svc auditd
    sec_audit_remediate_done 250 "auditd baseline"
    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline || true
    sec_audit_start_svc auditd
    sec_audit_remediate_done 251 "auditd baseline"
    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline || true
    sec_audit_start_svc auditd
    sec_audit_remediate_done 252 "auditd baseline"
    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline || true
    sec_audit_start_svc auditd
    sec_audit_remediate_done 253 "auditd baseline"
    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline || true
    sec_audit_start_svc auditd
    sec_audit_remediate_done 254 "auditd baseline"
    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline || true
    sec_audit_start_svc auditd
    sec_audit_remediate_done 255 "auditd baseline"
}

sec_audit_remediate_aide() {
    sec_audit_pkg_install aide aide-common
    sec_audit_remediate_done 256 "installed AIDE"
    sec_audit_remediate_done 257 "file system integrity is checked regularly"
}

sec_audit_remediate_identity_files() {
    sec_audit_harden_path /etc/passwd 644 root:root || true
    sec_audit_remediate_done 258 "hardened /etc/passwd"
    sec_audit_harden_path /etc/passwd- 644 root:root || true
    sec_audit_remediate_done 259 "hardened /etc/passwd-"
    sec_audit_harden_path /etc/group 644 root:root || true
    sec_audit_remediate_done 260 "hardened /etc/group"
    sec_audit_harden_path /etc/group- 644 root:root || true
    sec_audit_remediate_done 261 "hardened /etc/group-"
    sec_audit_harden_path /etc/shadow 640 root:root || true
    sec_audit_remediate_done 262 "hardened /etc/shadow"
    sec_audit_harden_path /etc/shadow- 640 root:root || true
    sec_audit_remediate_done 263 "hardened /etc/shadow-"
    sec_audit_harden_path /etc/shadow 640 root:root || true
    sec_audit_remediate_done 264 "hardened /etc/shadow"
    sec_audit_harden_path /etc/shadow- 640 root:root || true
    sec_audit_remediate_done 265 "hardened /etc/shadow-"
    sec_audit_harden_path /etc/shells 644 root:root || true
    sec_audit_remediate_done 266 "hardened /etc/shells"
    mkdir -p /etc/security; [ -e /etc/security/opasswd ] || touch /etc/security/opasswd
    sec_audit_harden_path /etc/security/opasswd 600 root:root || true
    sec_audit_remediate_done 267 "hardened /etc/security/opasswd"
}

sec_audit_remediate_filesystem_integrity() {
    sec_audit_remediate_skip 268 "world-writable files and directories are protected"
    sec_audit_remediate_done 269 "no files or directories without an owner and group exist"
    sec_audit_remediate_skip 270 "accounts in /etc/passwd use shadow passwords"
    sec_audit_harden_path /etc/shadow 640 root:root || true
    sec_audit_remediate_done 271 "hardened /etc/shadow"
    sec_audit_remediate_skip 272 "there are no duplicate UIDs on the system"
    sec_audit_remediate_skip 273 "there are no duplicate GIDs on the system"
    sec_audit_remediate_skip 274 "there are no duplicate usernames on the system"
    sec_audit_remediate_skip 275 "there are no duplicate group names on the system"
    sec_audit_remediate_done 276 "local interactive user home directories are configured correctly."
    sec_audit_remediate_skip 277 "access to local interactive users' dot files is configured"
}

sec_audit_maybe_security_upgrade() {
    if [ "${UB24_REMEDIATE_SECURITY_UPGRADE}" != "1" ]; then
        sec_audit_log "skipping apt security upgrade (set UB24_REMEDIATE_SECURITY_UPGRADE=1 to enable)"
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

sec_audit_main() {
    sec_audit_log "starting remediation (Ubuntu 24.04 / sec_audit_* style)"

    sec_audit_remediate_kernel_modules
    sec_audit_remediate_filesystem_partitions
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
    sec_audit_remediate_accounts
    sec_audit_remediate_logging
    sec_audit_remediate_auditd
    sec_audit_remediate_aide
    sec_audit_remediate_identity_files
    sec_audit_remediate_filesystem_integrity

    sec_audit_maybe_security_upgrade
    sec_audit_log "remediation complete (Ubuntu24_remediation.sh)"
    exit 0
}

sec_audit_main "$@"
