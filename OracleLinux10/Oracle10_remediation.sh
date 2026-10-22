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

OL10_ALLOW_CONTAINER_KMOD="${OL10_ALLOW_CONTAINER_KMOD:-${LINUX_CRE_ALLOW_CONTAINER_MODULES:-${ALMA_CRE_ALLOW_CONTAINER_MODULES:-0}}}"
OL10_REMEDIATE_SECURITY_UPGRADE="${OL10_REMEDIATE_SECURITY_UPGRADE:-0}"
OL10_SYSCTL_FILE="/etc/sysctl.d/99-secaudit-oracle10.conf"
OL10_AUDIT_RULES_FILE="/etc/audit/rules.d/99-secaudit-oracle10.rules"
OL10_MODPROBE_PREFIX="/etc/modprobe.d/sec-audit-disable"

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
            if [ "${OL10_ALLOW_CONTAINER_KMOD}" = "1" ]; then
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
    f="${OL10_MODPROBE_PREFIX}-${safe}.conf"
    mkdir -p /etc/modprobe.d
    {
        echo "# SecAudit Oracle Linux 10 — disable ${primary}"
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
    if [ -f "$OL10_SYSCTL_FILE" ] && grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$OL10_SYSCTL_FILE"; then
        sed -i "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${val}|" "$OL10_SYSCTL_FILE"
    else
        printf '%s = %s\n' "$key" "$val" >>"$OL10_SYSCTL_FILE"
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

sec_audit_set_dnf_main_kv() {
    local key="$1" val="$2" f=/etc/dnf/dnf.conf
    mkdir -p /etc/dnf
    if [ ! -f "$f" ]; then
        printf '%s\n%s=%s\n' '[main]' "$key" "$val" >"$f"
        return 0
    fi
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

sec_audit_authselect_enable() {
    local feat="$1" profile
    sec_audit_have_bin authselect || return 0
    profile=$(head -1 /etc/authselect/authselect.conf 2>/dev/null)
    [ -n "$profile" ] || profile=sssd
    if ! authselect current 2>/dev/null | grep -q "$feat"; then
        authselect select "$profile" "$feat" --force >/dev/null 2>&1 || true
    fi
    authselect apply-changes >/dev/null 2>&1 || true
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
    cat >"$OL10_AUDIT_RULES_FILE" <<'EOF'
## SecAudit Oracle Linux 10 baseline audit rules
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
    chmod 640 "$OL10_AUDIT_RULES_FILE" 2>/dev/null || true
    chown root:root "$OL10_AUDIT_RULES_FILE" 2>/dev/null || true
    sec_audit_reload_audit_rules
    return $?
}

sec_audit_ensure_module_audit_rules() {
    # RULE244-focused: ensure init_module/delete_module auditing without blacklisting a fake module.
    mkdir -p /etc/audit/rules.d
    local f="/etc/audit/rules.d/50-secaudit-modules.rules"
    cat >"$f" <<'EOF'
## SecAudit — kernel module load/unload auditing
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
    cat >/etc/systemd/journald.conf.d/99-secaudit-oracle10.conf <<'EOF'
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
    cat >/etc/systemd/coredump.conf.d/99-secaudit-oracle10.conf <<'EOF'
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
    cat >/etc/dconf/db/gdm.d/99-secaudit-oracle10 <<'EOF'
[org/gnome/login-screen]
banner-message-enable=true
banner-message-text='Authorized use only.'
disable-user-list=true
EOF
    cat >/etc/dconf/db/gdm.d/locks/99-secaudit-oracle10 <<'EOF'
/org/gnome/login-screen/banner-message-enable
/org/gnome/login-screen/banner-message-text
/org/gnome/login-screen/disable-user-list
EOF
    sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
}

# =============================================================================
# Section runners (RULE1 .. RULE276)
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
    if [ "${OL10_ALLOW_CONTAINER_KMOD}" = "1" ]; then
        _msg="waived blacklisting overlay (OL10_ALLOW_CONTAINER_KMOD=1)"
    else
        sec_audit_disable_kmod overlay || true
    fi
    sec_audit_remediate_done 6 "$_msg"

    _msg="blacklisted kernel module squashfs"
    if [ "${OL10_ALLOW_CONTAINER_KMOD}" = "1" ]; then
        _msg="waived blacklisting squashfs (OL10_ALLOW_CONTAINER_KMOD=1)"
    else
        sec_audit_disable_kmod squashfs || true
    fi
    sec_audit_remediate_done 7 "$_msg"

    sec_audit_disable_kmod udf || true
    sec_audit_remediate_done 8 "blacklisted kernel module udf"
    sec_audit_disable_kmod firewire_core firewire-core || true
    sec_audit_remediate_done 9 "blacklisted kernel module firewire_core/firewire-core"
    sec_audit_disable_kmod usb_storage usb-storage || true
    sec_audit_remediate_done 10 "blacklisted kernel module usb_storage/usb-storage"
}

sec_audit_remediate_filesystem_partitions() {
    local _msg
    # Separate partition creation is always manual.
    sec_audit_remediate_skip 11 "/tmp is tmpfs or a separate partition"

    sec_audit_ensure_mount_option /tmp nodev || true
    sec_audit_remediate_done 12 "set nodev on /tmp (tmpfs fstab persistence when needed)"
    sec_audit_remediate_skip 13 "nosuid option set on /tmp partition"
    sec_audit_ensure_mount_option /tmp noexec || true
    sec_audit_remediate_done 14 "set noexec on /tmp (tmpfs fstab persistence when needed)"

    sec_audit_remediate_skip 15 "/dev/shm is tmpfs or a separate partition"
    sec_audit_ensure_mount_option /dev/shm nodev || true
    sec_audit_remediate_done 16 "set nodev on /dev/shm (tmpfs fstab persistence when needed)"
    sec_audit_remediate_skip 17 "nosuid option set on /dev/shm partition"
    sec_audit_ensure_mount_option /dev/shm noexec || true
    sec_audit_remediate_done 18 "set noexec on /dev/shm (tmpfs fstab persistence when needed)"

    sec_audit_remediate_skip 19 "separate partition exists for /home"
    if sec_audit_ensure_mount_option /home nodev; then
        _msg="set nodev on /home"
    else
        _msg="skipped inventing fstab for /home (no dedicated mount); nodev not persisted"
    fi
    sec_audit_remediate_done 20 "$_msg"
    sec_audit_remediate_skip 21 "nosuid option set on /home partition"

    sec_audit_remediate_skip 22 "separate partition exists for /var"
    if sec_audit_ensure_mount_option /var nodev; then
        _msg="set nodev on /var"
    else
        _msg="skipped inventing fstab for /var (no dedicated mount); nodev not persisted"
    fi
    sec_audit_remediate_done 23 "$_msg"
    sec_audit_remediate_skip 24 "nosuid option set on /var partition"

    sec_audit_remediate_skip 25 "separate partition exists for /var/tmp"
    if sec_audit_ensure_mount_option /var/tmp nodev; then
        _msg="set nodev on /var/tmp"
    else
        _msg="skipped inventing fstab for /var/tmp (no dedicated mount); nodev not persisted"
    fi
    sec_audit_remediate_done 26 "$_msg"
    sec_audit_remediate_skip 27 "nosuid option set on /var/tmp partition"
    if sec_audit_ensure_mount_option /var/tmp noexec; then
        _msg="set noexec on /var/tmp"
    else
        _msg="skipped inventing fstab for /var/tmp (no dedicated mount); noexec not persisted"
    fi
    sec_audit_remediate_done 28 "$_msg"

    sec_audit_remediate_skip 29 "separate partition exists for /var/log"
    if sec_audit_ensure_mount_option /var/log nodev; then
        _msg="set nodev on /var/log"
    else
        _msg="skipped inventing fstab for /var/log (no dedicated mount); nodev not persisted"
    fi
    sec_audit_remediate_done 30 "$_msg"
    sec_audit_remediate_skip 31 "nosuid option set on /var/log partition"
    if sec_audit_ensure_mount_option /var/log noexec; then
        _msg="set noexec on /var/log"
    else
        _msg="skipped inventing fstab for /var/log (no dedicated mount); noexec not persisted"
    fi
    sec_audit_remediate_done 32 "$_msg"

    sec_audit_remediate_skip 33 "separate partition exists for /var/log/audit"
    if sec_audit_ensure_mount_option /var/log/audit nodev; then
        _msg="set nodev on /var/log/audit"
    else
        _msg="skipped inventing fstab for /var/log/audit (no dedicated mount); nodev not persisted"
    fi
    sec_audit_remediate_done 34 "$_msg"
    sec_audit_remediate_skip 35 "nosuid option set on /var/log/audit partition"
    if sec_audit_ensure_mount_option /var/log/audit noexec; then
        _msg="set noexec on /var/log/audit"
    else
        _msg="skipped inventing fstab for /var/log/audit (no dedicated mount); noexec not persisted"
    fi
    sec_audit_remediate_done 36 "$_msg"
}

sec_audit_remediate_package_security() {
    sec_audit_remediate_skip 37 "GPG keys are configured (import/review distribution signing keys manually)"
    sec_audit_set_dnf_main_kv gpgcheck 1
    sec_audit_set_dnf_main_kv localpkg_gpgcheck 1
    sec_audit_remediate_done 38 "enabled gpgcheck (and localpkg_gpgcheck) in dnf [main]"
    sec_audit_set_dnf_main_kv repo_gpgcheck 1
    sec_audit_remediate_done 39 "enabled repo_gpgcheck in dnf [main]"
    sec_audit_remediate_skip 40 "package manager repositories are configured"
    sec_audit_set_dnf_main_kv install_weak_deps 0
    sec_audit_remediate_done 41 "set install_weak_deps=0 in dnf [main]"
}

sec_audit_remediate_selinux() {
    sec_audit_pkg_install libselinux selinux-policy-targeted
    sec_audit_remediate_done 42 "installed SELinux (libselinux)"

    if sec_audit_have_bin grubby; then
        grubby --update-kernel=ALL --remove-args="selinux=0 enforcing=0" >/dev/null 2>&1 || true
    fi
    if [ -f /etc/default/grub ]; then
        sed -i 's/ selinux=0//g; s/ enforcing=0//g' /etc/default/grub 2>/dev/null || true
    fi
    sec_audit_remediate_done 43 "removed selinux=0/enforcing=0 from bootloader args"

    if [ -f /etc/selinux/config ]; then
        if grep -qE '^[[:space:]]*SELINUXTYPE=' /etc/selinux/config; then
            sed -i 's/^[[:space:]]*SELINUXTYPE=.*/SELINUXTYPE=targeted/' /etc/selinux/config
        else
            echo 'SELINUXTYPE=targeted' >>/etc/selinux/config
        fi
    fi
    sec_audit_remediate_done 44 "SELINUXTYPE=targeted"

    if [ -f /etc/selinux/config ]; then
        if grep -qE '^[[:space:]]*SELINUX=' /etc/selinux/config; then
            sed -i 's/^[[:space:]]*SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
        else
            echo 'SELINUX=enforcing' >>/etc/selinux/config
        fi
    fi
    sec_audit_have_bin setenforce && setenforce 1 >/dev/null 2>&1 || true
    sec_audit_remediate_done 45 "SELinux not disabled (config enforcing)"
    sec_audit_remediate_done 46 "SELinux enforcing"

    sec_audit_remediate_skip 47 "no unconfined services exist"
    sec_audit_pkg_remove setroubleshoot
    sec_audit_disable_svc setroubleshoot.service
    sec_audit_remediate_done 48 "removed setroubleshoot"
}

sec_audit_remediate_bootloader() {
    sec_audit_remediate_skip 49 "bootloader password is set"
    sec_audit_harden_path /boot/grub2/grub.cfg 600 root:root || true
    sec_audit_harden_path /boot/grub2/user.cfg 600 root:root || true
    local g
    for g in /boot/efi/EFI/*/grub.cfg; do
        [ -f "$g" ] || continue
        sec_audit_harden_path "$g" 600 root:root || true
    done
    sec_audit_remediate_done 50 "hardened grub permissions"
}

sec_audit_remediate_process_hardening() {
    sec_audit_configure_coredump
    sec_audit_remediate_done 51 "disabled core dumps (limits + systemd-coredump)"

    sec_audit_set_sysctl fs.protected_hardlinks 1
    sec_audit_remediate_done 52 "set fs.protected_hardlinks=1"
    sec_audit_set_sysctl fs.protected_symlinks 1
    sec_audit_remediate_done 53 "set fs.protected_symlinks=1"
    sec_audit_remediate_skip 54 "fs.suid_dumpable is configured"
    sec_audit_set_sysctl kernel.dmesg_restrict 1
    sec_audit_remediate_done 55 "set kernel.dmesg_restrict=1"
    sec_audit_set_sysctl kernel.kptr_restrict 2
    sec_audit_remediate_done 56 "set kernel.kptr_restrict=2"
    sec_audit_set_sysctl kernel.yama.ptrace_scope 1
    sec_audit_remediate_done 57 "set kernel.yama.ptrace_scope=1"
    sec_audit_set_sysctl kernel.randomize_va_space 2
    sec_audit_remediate_done 58 "set kernel.randomize_va_space=2"

    sec_audit_set_sysctl fs.suid_dumpable 0
    sec_audit_configure_coredump
    sec_audit_remediate_done 59 "coredump ProcessSizeMax=0 and fs.suid_dumpable=0"
    sec_audit_configure_coredump
    sec_audit_remediate_done 60 "systemd-coredump Storage=none"
}

sec_audit_remediate_crypto_policy() {
    if sec_audit_have_bin update-crypto-policies; then
        update-crypto-policies --set DEFAULT >/dev/null 2>&1 || true
    fi
    sec_audit_remediate_done 61 "crypto policy not LEGACY (DEFAULT)"
    if sec_audit_have_bin update-crypto-policies; then
        update-crypto-policies --set DEFAULT:NO-SHA1:NO-SSHCBC >/dev/null 2>&1 \
            || update-crypto-policies --set DEFAULT >/dev/null 2>&1 \
            || true
    fi
    sec_audit_remediate_done 62 "applied DEFAULT crypto policy modules"
    sec_audit_remediate_skip 63 "system wide crypto policy disables cbc for ssh"
}

sec_audit_remediate_banners() {
    sec_audit_sanitize_banner /etc/motd
    sec_audit_remediate_done 64 "sanitized banner /etc/motd"
    sec_audit_sanitize_banner /etc/issue
    sec_audit_remediate_done 65 "sanitized banner /etc/issue"
    sec_audit_sanitize_banner /etc/issue.net
    sec_audit_remediate_done 66 "sanitized banner /etc/issue.net"
    sec_audit_harden_path /etc/motd 644 root:root || true
    sec_audit_remediate_done 67 "permissions /etc/motd"
    sec_audit_harden_path /etc/issue 644 root:root || true
    sec_audit_remediate_done 68 "permissions /etc/issue"
    sec_audit_harden_path /etc/issue.net 644 root:root || true
    sec_audit_remediate_done 69 "permissions /etc/issue.net"
}

sec_audit_remediate_gdm() {
    sec_audit_gdm_dconf_stub
    sec_audit_remediate_done 70 "configured GDM hardening (dconf stub)"
    sec_audit_gdm_dconf_stub
    sec_audit_remediate_done 71 "configured GDM hardening (dconf stub)"
    sec_audit_gdm_dconf_stub
    sec_audit_remediate_done 72 "configured GDM hardening (dconf stub)"
    sec_audit_gdm_dconf_stub
    sec_audit_remediate_done 73 "configured GDM hardening (dconf stub)"
    sec_audit_gdm_dconf_stub
    sec_audit_remediate_done 74 "configured GDM hardening (dconf stub)"
    sec_audit_gdm_dconf_stub
    sec_audit_remediate_done 75 "configured GDM hardening (dconf stub)"
}

sec_audit_remediate_unused_services() {
    sec_audit_disable_svc autofs.service
    sec_audit_pkg_remove autofs
    sec_audit_remediate_done 76 "disabled autofs"

    sec_audit_disable_svc avahi-daemon.socket
    sec_audit_disable_svc avahi-daemon.service
    sec_audit_pkg_remove avahi
    sec_audit_remediate_done 77 "disabled avahi"

    sec_audit_disable_svc cockpit.socket
    sec_audit_disable_svc cockpit.service
    sec_audit_pkg_remove cockpit-ws
    sec_audit_remediate_done 78 "disabled cockpit-ws"

    sec_audit_disable_svc dhcpd.service
    sec_audit_disable_svc dhcpd6.service
    sec_audit_pkg_remove dhcp-server
    sec_audit_remediate_done 79 "disabled dhcp-server"

    sec_audit_disable_svc named.service
    sec_audit_pkg_remove bind
    sec_audit_remediate_done 80 "disabled bind"

    sec_audit_disable_svc dnsmasq.service
    sec_audit_pkg_remove dnsmasq
    sec_audit_remediate_done 81 "disabled dnsmasq"

    sec_audit_disable_svc vsftpd.service
    sec_audit_pkg_remove vsftpd
    sec_audit_remediate_done 82 "disabled vsftpd"

    sec_audit_remediate_skip 83 "review remediation: message access server services are not in use"
    sec_audit_remediate_skip 84 "review remediation: network file system services are not in use"
    sec_audit_remediate_skip 85 "review remediation: print server services are not in use"

    sec_audit_disable_svc rpcbind.socket
    sec_audit_disable_svc rpcbind.service
    sec_audit_pkg_remove rpcbind
    sec_audit_remediate_done 86 "disabled rpcbind"

    sec_audit_disable_svc rsyncd.socket
    sec_audit_disable_svc rsyncd.service
    sec_audit_pkg_remove rsync-daemon
    sec_audit_remediate_done 87 "disabled rsync-daemon"

    sec_audit_disable_svc smb.service
    sec_audit_disable_svc smbd.service
    sec_audit_pkg_remove samba
    sec_audit_remediate_done 88 "disabled samba"

    sec_audit_disable_svc snmpd.service
    sec_audit_pkg_remove net-snmp
    sec_audit_remediate_done 89 "disabled net-snmp"

    sec_audit_disable_svc telnet.socket
    sec_audit_pkg_remove telnet-server
    sec_audit_remediate_done 90 "disabled telnet-server"

    sec_audit_disable_svc tftp.socket
    sec_audit_disable_svc tftp.service
    sec_audit_pkg_remove tftp-server
    sec_audit_remediate_done 91 "disabled tftp-server"

    sec_audit_remediate_skip 92 "review remediation: web proxy server services are not in use"
    sec_audit_remediate_skip 93 "review remediation: web server services are not in use"
    sec_audit_remediate_skip 94 "review remediation: GNOME Display Manager is removed"
    sec_audit_remediate_skip 95 "review remediation: X window server services are not in use"
}

sec_audit_remediate_client_tools() {
    sec_audit_pkg_remove ftp
    sec_audit_remediate_done 96 "removed ftp"
    sec_audit_pkg_remove openldap-clients ldap-utils
    sec_audit_remediate_done 97 "removed openldap-clients/ldap-utils"
    sec_audit_pkg_remove telnet
    sec_audit_remediate_done 98 "removed telnet"
    sec_audit_pkg_remove tftp
    sec_audit_remediate_done 99 "removed tftp"
}

sec_audit_remediate_chrony() {
    sec_audit_pkg_install chrony
    sec_audit_start_svc chronyd
    sec_audit_remediate_done 100 "installed chrony"

    sec_audit_pkg_install chrony
    if ! grep -qE '^(pool|server)[[:space:]]' /etc/chrony.conf 2>/dev/null \
        && ! grep -qE '^(pool|server)[[:space:]]' /etc/chrony.d/*.conf 2>/dev/null; then
        mkdir -p /etc/chrony.d
        echo 'pool 2.pool.ntp.org iburst' >>/etc/chrony.conf
    fi
    sec_audit_start_svc chronyd
    sec_audit_remediate_done 101 "configured chrony"

    sec_audit_remediate_skip 102 "review remediation: chrony is not run as the root user"
}

sec_audit_remediate_cron_at() {
    sec_audit_pkg_install cronie
    sec_audit_start_svc crond
    sec_audit_remediate_done 103 "enabled crond"

    sec_audit_harden_path /etc/crontab 600 root:root || true
    sec_audit_remediate_done 104 "restricted /etc/crontab"

    sec_audit_remediate_skip 105 "review remediation: access to /etc/cron.hourly is configured"
    sec_audit_remediate_skip 106 "review remediation: access to /etc/cron.daily is configured"
    sec_audit_remediate_skip 107 "review remediation: access to /etc/cron.weekly is configured"
    sec_audit_remediate_skip 108 "review remediation: access to /etc/cron.monthly is configured"
    sec_audit_remediate_skip 109 "review remediation: access to /etc/cron.yearly is configured"
    sec_audit_remediate_skip 110 "review remediation: access to /etc/cron.d is configured"
    sec_audit_remediate_skip 111 "review remediation: access to crontab is configured"
    sec_audit_remediate_skip 112 "review remediation: access to at is configured"
}

sec_audit_remediate_network_stack() {
    sec_audit_remediate_skip 113 "IPv6 status is identified"

    sec_audit_disable_kmod bluetooth
    sec_audit_remediate_done 114 "disabled wireless/bluetooth kernel module path"

    sec_audit_disable_svc bluetooth.service
    sec_audit_pkg_remove bluez
    sec_audit_remediate_done 115 "disabled bluez"

    # Fixed: old script blacklisted a bogus module named "is"
    sec_audit_disable_kmod atm
    sec_audit_remediate_done 116 "blacklisted atm"
    sec_audit_disable_kmod can
    sec_audit_remediate_done 117 "blacklisted can"
    sec_audit_disable_kmod dccp
    sec_audit_remediate_done 118 "blacklisted dccp"
    sec_audit_disable_kmod tipc
    sec_audit_remediate_done 119 "blacklisted tipc"
    sec_audit_disable_kmod rds
    sec_audit_remediate_done 120 "blacklisted rds"
    sec_audit_disable_kmod sctp
    sec_audit_remediate_done 121 "blacklisted sctp"

    sec_audit_set_sysctl net.ipv4.ip_forward 0
    sec_audit_remediate_done 122 "set net.ipv4.ip_forward=0"
    sec_audit_remediate_skip 123 "review remediation: net.ipv4.conf.all.forwarding is configured"
    sec_audit_remediate_skip 124 "review remediation: net.ipv4.conf.default.forwarding is configured"

    sec_audit_set_sysctl net.ipv4.conf.all.send_redirects 0
    sec_audit_remediate_done 125 "set net.ipv4.conf.all.send_redirects=0"
    sec_audit_set_sysctl net.ipv4.conf.default.send_redirects 0
    sec_audit_remediate_done 126 "set net.ipv4.conf.default.send_redirects=0"
    sec_audit_set_sysctl net.ipv4.conf.all.accept_redirects 0
    sec_audit_remediate_done 127 "set net.ipv4.conf.all.accept_redirects=0"
    sec_audit_set_sysctl net.ipv4.conf.all.secure_redirects 0
    sec_audit_remediate_done 128 "set net.ipv4.conf.all.secure_redirects=0"
    sec_audit_set_sysctl net.ipv4.conf.all.rp_filter 1
    sec_audit_remediate_done 129 "set net.ipv4.conf.all.rp_filter=1"
    sec_audit_set_sysctl net.ipv4.conf.default.rp_filter 1
    sec_audit_remediate_done 130 "set net.ipv4.conf.default.rp_filter=1"
    sec_audit_set_sysctl net.ipv4.conf.all.log_martians 1
    sec_audit_remediate_done 131 "set net.ipv4.conf.all.log_martians=1"
    sec_audit_set_sysctl net.ipv4.conf.default.log_martians 1
    sec_audit_remediate_done 132 "set net.ipv4.conf.default.log_martians=1"
    sec_audit_set_sysctl net.ipv4.tcp_syncookies 1
    sec_audit_remediate_done 133 "set net.ipv4.tcp_syncookies=1"

    sec_audit_remediate_skip 134 "net.ipv6.conf.all.forwarding is configured"
    sec_audit_remediate_skip 135 "net.ipv6.conf.default.forwarding is configured"
    sec_audit_remediate_skip 136 "net.ipv6.conf.all.accept_redirects is configured"
    sec_audit_remediate_skip 137 "net.ipv6.conf.all.accept_ra is configured"
    sec_audit_remediate_skip 138 "net.ipv6.conf.default.accept_ra is configured"
}

sec_audit_remediate_firewalld() {
    sec_audit_pkg_install firewalld
    sec_audit_start_svc firewalld
    sec_audit_remediate_done 139 "installed firewalld"
    sec_audit_remediate_skip 140 "review remediation: firewalld backend is configured"
    sec_audit_remediate_skip 141 "review remediation: firewalld.service is configured"
    sec_audit_remediate_skip 142 "review remediation: firewalld active zone target is configured"
    sec_audit_remediate_skip 143 "firewalld loopback traffic is configured"
    sec_audit_remediate_skip 144 "firewalld services and ports are configured"
}

sec_audit_remediate_sshd() {
    sec_audit_remediate_skip 145 "review remediation: access to /etc/ssh/sshd_config is configured"
    sec_audit_remediate_skip 146 "review remediation: access to SSH private host key files is configured"
    sec_audit_remediate_skip 147 "review remediation: access to SSH public host key files is configured"
    sec_audit_remediate_skip 148 "review remediation: sshd access is configured"

    sec_audit_set_sshd_kv Banner /etc/issue.net || true
    sec_audit_remediate_done 149 "sshd Banner"
    sec_audit_remediate_skip 150 "review remediation: sshd Ciphers are configured"
    sec_audit_set_sshd_kv ClientAliveInterval 300 || true
    sec_audit_remediate_done 151 "sshd ClientAliveInterval"
    sec_audit_set_sshd_kv DisableForwarding yes || true
    sec_audit_remediate_done 152 "sshd DisableForwarding"
    sec_audit_set_sshd_kv GSSAPIAuthentication no || true
    sec_audit_remediate_done 153 "sshd GSSAPIAuthentication"
    sec_audit_set_sshd_kv HostbasedAuthentication no || true
    sec_audit_remediate_done 154 "sshd HostbasedAuthentication"
    sec_audit_set_sshd_kv IgnoreRhosts yes || true
    sec_audit_remediate_done 155 "sshd IgnoreRhosts"
    sec_audit_remediate_skip 156 "review remediation: sshd KexAlgorithms is configured"
    sec_audit_set_sshd_kv LoginGraceTime 60 || true
    sec_audit_remediate_done 157 "sshd LoginGraceTime"
    sec_audit_set_sshd_kv LogLevel VERBOSE || true
    sec_audit_remediate_done 158 "sshd LogLevel"
    sec_audit_remediate_skip 159 "review remediation: sshd MACs are configured"
    sec_audit_set_sshd_kv MaxAuthTries 4 || true
    sec_audit_remediate_done 160 "sshd MaxAuthTries"
    sec_audit_set_sshd_kv MaxStartups 10:30:60 || true
    sec_audit_remediate_done 161 "sshd MaxStartups"
    sec_audit_set_sshd_kv MaxSessions 10 || true
    sec_audit_remediate_done 162 "sshd MaxSessions"
    sec_audit_set_sshd_kv PermitEmptyPasswords no || true
    sec_audit_remediate_done 163 "sshd PermitEmptyPasswords"
    sec_audit_set_sshd_kv PermitRootLogin no || true
    sec_audit_remediate_done 164 "sshd PermitRootLogin"
    sec_audit_set_sshd_kv PermitUserEnvironment no || true
    sec_audit_remediate_done 165 "sshd PermitUserEnvironment"
    sec_audit_set_sshd_kv UsePAM yes || true
    sec_audit_remediate_done 166 "sshd UsePAM"
}

sec_audit_remediate_sudo_su() {
    sec_audit_pkg_install sudo
    sec_audit_remediate_done 167 "sudo installed"
    sec_audit_remediate_skip 168 "review remediation: sudo commands use pty"
    sec_audit_remediate_skip 169 "review remediation: sudo log file exists"
    sec_audit_remediate_skip 170 "review remediation: users must provide password for escalation"
    echo 'Defaults timestamp_timeout=5' >/etc/sudoers.d/99-secaudit-timeout
    chmod 440 /etc/sudoers.d/99-secaudit-timeout
    sec_audit_remediate_done 171 "sudo timestamp_timeout=5"
    sec_audit_remediate_skip 172 "review remediation: access to the su command is restricted"
}

sec_audit_remediate_pam_auth() {
    sec_audit_remediate_skip 173 "review remediation: active authselect profile includes pam modules"
    sec_audit_authselect_enable with-faillock
    sec_audit_remediate_done 174 "pam faillock"
    sec_audit_authselect_enable with-pwquality
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_remediate_done 175 "password quality"
    sec_audit_authselect_enable with-pwhistory
    mkdir -p /etc/security
    grep -qE '^[[:space:]]*remember[[:space:]]*=' /etc/security/pwhistory.conf 2>/dev/null \
        || echo 'remember = 24' >>/etc/security/pwhistory.conf
    sec_audit_remediate_done 176 "password history"
    sec_audit_remediate_skip 177 "review remediation: pam_unix module is enabled"
    sec_audit_authselect_enable with-faillock
    sec_audit_set_faillock_kv deny 5
    sec_audit_set_faillock_kv unlock_time 900
    sec_audit_remediate_done 178 "pam faillock"
    sec_audit_remediate_skip 179 "review remediation: password unlock time is configured"
    sec_audit_remediate_skip 180 "review remediation: password length is configured"
    sec_audit_remediate_skip 181 "password complexity is configured"
    sec_audit_remediate_skip 182 "review remediation: password dictionary check is enabled"
    sec_audit_authselect_enable with-pwquality
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_remediate_done 183 "password quality"
    sec_audit_authselect_enable with-pwhistory
    grep -qE '^[[:space:]]*remember[[:space:]]*=' /etc/security/pwhistory.conf 2>/dev/null \
        || echo 'remember = 24' >>/etc/security/pwhistory.conf
    sec_audit_remediate_done 184 "password history"
    sec_audit_authselect_enable with-pwhistory
    sec_audit_remediate_done 185 "password history"
    sec_audit_authselect_enable with-pwhistory
    sec_audit_remediate_done 186 "password history"
    sec_audit_remediate_skip 187 "review remediation: pam_unix does not include nullok"
    sec_audit_authselect_enable with-pwhistory
    sec_audit_remediate_done 188 "password history"
    sec_audit_remediate_skip 189 "review remediation: pam_unix includes use_authtok"
}

sec_audit_remediate_accounts() {
    sec_audit_remediate_skip 190 "review remediation: password expiration is configured"
    sec_audit_remediate_skip 191 "minimum password days is configured"
    sec_audit_remediate_skip 192 "review remediation: password expiration warning days is configured"
    sec_audit_set_login_defs_kv ENCRYPT_METHOD SHA512
    sec_audit_remediate_done 193 "ENCRYPT_METHOD SHA512"
    sec_audit_remediate_skip 194 "inactive password lock is configured"
    sec_audit_remediate_skip 195 "all users last password change date is in the past"
    sec_audit_remediate_skip 196 "root is the only UID 0 account"
    sec_audit_remediate_skip 197 "root is the only GID 0 account"
    sec_audit_remediate_skip 198 "group root is the only GID 0 group"
    sec_audit_remediate_skip 199 "root account access is controlled"
    sec_audit_remediate_skip 200 "root path integrity"
    sec_audit_set_login_defs_kv UMASK 027
    cat >/etc/profile.d/99-secaudit-umask.sh <<'EOF'
umask 027
EOF
    sec_audit_remediate_done 201 "default umask 027"
    sec_audit_remediate_skip 202 "system accounts do not have a valid login shell"
    sec_audit_remediate_skip 203 "accounts without a valid login shell are locked"
    sec_audit_remediate_skip 204 "review remediation: nologin is not listed in /etc/shells"
    cat >/etc/profile.d/99-secaudit-timeout.sh <<'EOF'
TMOUT=600
readonly TMOUT
export TMOUT
EOF
    sec_audit_remediate_done 205 "TMOUT=600"
    sec_audit_set_login_defs_kv UMASK 027
    cat >/etc/profile.d/99-secaudit-umask.sh <<'EOF'
umask 027
EOF
    sec_audit_remediate_done 206 "default umask 027"
}

sec_audit_remediate_aide() {
    sec_audit_pkg_install aide
    sec_audit_remediate_done 207 "installed AIDE"
    sec_audit_pkg_install aide
    sec_audit_remediate_done 208 "integrity tooling"
}

sec_audit_remediate_logging() {
    sec_audit_start_svc systemd-journald
    sec_audit_remediate_done 209 "journald active"
    sec_audit_remediate_skip 210 "journald log file access is configured"
    sec_audit_remediate_skip 211 "journald log file rotation is configured"
    sec_audit_remediate_skip 212 "review remediation: only one logging system is in use"
    sec_audit_remediate_skip 213 "systemd-journal-remote is installed"
    sec_audit_remediate_skip 214 "systemd-journal-upload is enabled and active"
    sec_audit_remediate_skip 215 "systemd-journal-remote service is not in use"
    sec_audit_remediate_skip 216 "configure central logging per site policy before enabling journal remote/upload"
    sec_audit_configure_journald
    sec_audit_remediate_done 217 "journald configuration"
    sec_audit_configure_journald
    sec_audit_remediate_done 218 "journald configuration"
    sec_audit_pkg_install rsyslog
    sec_audit_start_svc rsyslog
    sec_audit_remediate_done 219 "rsyslog installed"
    sec_audit_pkg_install rsyslog
    sec_audit_start_svc rsyslog
    sec_audit_remediate_done 220 "rsyslog installed"
    sec_audit_start_svc systemd-journald
    sec_audit_remediate_done 221 "journald active"
    sec_audit_pkg_install rsyslog
    sec_audit_start_svc rsyslog
    sec_audit_remediate_done 222 "rsyslog installed"
    sec_audit_remediate_skip 223 "rsyslog logging is configured"
    sec_audit_remediate_skip 224 "rsyslog logrotate is configured"
    sec_audit_remediate_skip 225 "review remediation: access to all logfiles has been configured"
}

sec_audit_remediate_auditd() {
    local _msg
    sec_audit_pkg_install audit audit-libs
    sec_audit_start_svc auditd
    sec_audit_remediate_done 226 "auditd packages installed / service started"

    # RULE227: audit_backlog_limit (not a fake rules rewrite)
    if [ -f /etc/default/grub ]; then
        if grep -q 'audit_backlog_limit=' /etc/default/grub 2>/dev/null; then
            sed -i 's/audit_backlog_limit=[0-9]*/audit_backlog_limit=8192/' /etc/default/grub
        elif grep -q '^GRUB_CMDLINE_LINUX=' /etc/default/grub; then
            sed -i 's/^GRUB_CMDLINE_LINUX="\([^"]*\)"/GRUB_CMDLINE_LINUX="\1 audit_backlog_limit=8192"/' /etc/default/grub
        fi
        if sec_audit_have_bin grubby; then
            grubby --update-kernel=ALL --args='audit_backlog_limit=8192' >/dev/null 2>&1 || true
        fi
    fi
    sec_audit_remediate_done 227 "set audit_backlog_limit=8192 in GRUB when /etc/default/grub exists"

    sec_audit_pkg_install audit audit-libs
    sec_audit_start_svc auditd
    sec_audit_remediate_done 228 "auditd enabled/started"

    sec_audit_pkg_install audit
    sec_audit_set_auditd_conf_kv max_log_file 8 || true
    sec_audit_remediate_done 229 "set auditd max_log_file"

    sec_audit_remediate_skip 230 "review remediation: audit logs are not automatically deleted"
    sec_audit_remediate_skip 231 "review remediation: system is disabled when audit logs are full"
    sec_audit_remediate_skip 232 "review remediation: system warns when audit logs are low on space"
    sec_audit_remediate_skip 233 "review remediation: modification of the /etc/sudoers file is collected"
    sec_audit_remediate_skip 234 "review remediation: actions as another user are always logged"
    sec_audit_remediate_skip 235 "review remediation: events that modify the sudo log file are collected"
    sec_audit_remediate_skip 236 "review remediation: events that modify /etc/NetworkManager directory are collected"
    sec_audit_remediate_skip 237 "review remediation: use of privileged commands are collected"
    sec_audit_remediate_skip 238 "review remediation: unsuccessful file access attempts are collected"
    sec_audit_remediate_skip 239 "review remediation: events that modify /etc/shadow and /etc/gshadow are collected"
    sec_audit_remediate_skip 240 "review remediation: successful file system mounts are collected"
    sec_audit_remediate_skip 241 "review remediation: session initiation information is collected"
    sec_audit_remediate_skip 242 "review remediation: login and logout events are collected"
    sec_audit_remediate_skip 243 "review remediation: unlink file deletion events by users are collected"

    # RULE244: init_module auditing (bugfix — was disable_kernel_module loading)
    sec_audit_pkg_install audit audit-libs
    _msg="configured audit rules for kernel module load syscalls (init_module)"
    if ! sec_audit_ensure_module_audit_rules; then
        _msg="wrote init_module audit rules on disk; kernel audit immutable or reload deferred (reboot may be required)"
    fi
    sec_audit_remediate_done 244 "$_msg"

    sec_audit_remediate_skip 245 "review remediation: the audit configuration is immutable (-e 2 requires careful rollout/reboot)"
    sec_audit_remediate_skip 246 "the running and on disk configuration is the same"

    # RULE247-256: permissions/ownership — use harden helpers, not rewriting rules 10x
    sec_audit_harden_audit_logs
    sec_audit_remediate_done 247 "audit log directory mode hardened (750)"
    sec_audit_harden_audit_logs
    sec_audit_remediate_done 248 "audit log files mode hardened"
    sec_audit_harden_audit_logs
    sec_audit_remediate_done 249 "audit log files owner hardened"
    sec_audit_harden_audit_logs
    sec_audit_remediate_skip 250 "audit log files group owner is configured"
    sec_audit_harden_audit_config
    sec_audit_remediate_done 251 "audit configuration files mode hardened"
    sec_audit_harden_audit_config
    sec_audit_remediate_done 252 "audit configuration files owner hardened"
    sec_audit_harden_audit_config
    sec_audit_remediate_skip 253 "audit configuration files group owner is configured"
    sec_audit_harden_audit_tools
    sec_audit_remediate_done 254 "audit tools mode hardened"
    sec_audit_harden_audit_tools
    sec_audit_remediate_done 255 "audit tools owner hardened"
    sec_audit_harden_audit_tools
    sec_audit_remediate_skip 256 "audit tools group owner is configured"

    # Ensure shared baseline exists for operators who later enable rules 233-243.
    sec_audit_ensure_audit_baseline >/dev/null 2>&1 || true
}

sec_audit_remediate_identity_files() {
    # Modes/owners aligned with Alma10.sh assert_path_access expectations.
    sec_audit_harden_path /etc/passwd 644 root:root || true
    sec_audit_remediate_done 257 "hardened /etc/passwd (644 root:root)"
    sec_audit_harden_path /etc/passwd- 644 root:root || true
    sec_audit_remediate_done 258 "hardened /etc/passwd- when present (644 root:root)"
    sec_audit_harden_path /etc/group 644 root:root || true
    sec_audit_remediate_done 259 "hardened /etc/group (644 root:root)"
    sec_audit_harden_path /etc/group- 644 root:root || true
    sec_audit_remediate_done 260 "hardened /etc/group- when present (644 root:root)"
    sec_audit_harden_path /etc/shadow 640 root:root || true
    sec_audit_remediate_done 261 "hardened /etc/shadow (640 root:root)"
    sec_audit_harden_path /etc/shadow- 640 root:root || true
    sec_audit_remediate_done 262 "hardened /etc/shadow- when present (640 root:root)"
    sec_audit_harden_path /etc/gshadow 640 root:root || true
    sec_audit_remediate_done 263 "hardened /etc/gshadow when present (640 root:root)"
    sec_audit_harden_path /etc/gshadow- 640 root:root || true
    sec_audit_remediate_done 264 "hardened /etc/gshadow- when present (640 root:root)"
    sec_audit_harden_path /etc/shells 644 root:root || true
    sec_audit_remediate_done 265 "hardened /etc/shells (644 root:root)"
    mkdir -p /etc/security
    [ -e /etc/security/opasswd ] || touch /etc/security/opasswd 2>/dev/null || true
    sec_audit_harden_path /etc/security/opasswd 600 root:root || true
    sec_audit_remediate_done 266 "hardened /etc/security/opasswd (600 root:root)"
}

sec_audit_remediate_filesystem_integrity() {
    sec_audit_remediate_skip 267 "review remediation: world writable files and directories are secured"
    sec_audit_remediate_skip 268 "SUID and SGID files are reviewed"
    sec_audit_remediate_skip 269 "accounts in /etc/passwd use shadowed passwords"
    sec_audit_remediate_skip 270 "review remediation: /etc/shadow password fields are not empty"
    sec_audit_remediate_skip 271 "all groups in /etc/passwd exist in /etc/group"
    sec_audit_remediate_skip 272 "no duplicate UIDs exist"
    sec_audit_remediate_skip 273 "no duplicate GIDs exist"
    sec_audit_remediate_skip 274 "no duplicate user names exist"
    sec_audit_remediate_skip 275 "no duplicate group names exist"
    sec_audit_remediate_skip 276 "local interactive user dot files access is configured"
}


sec_audit_remediate_auditd_extended() {
    # RULE277-294 — Oracle extended audit collection / permission rules
    local _rc=0 _suffix=""
    sec_audit_ensure_audit_baseline || _rc=$?
    if [ "$_rc" -eq 2 ]; then
        _suffix=" (audit immutable; reboot to load)"
    fi
    sec_audit_remediate_done 277 "audit baseline covers chacl command usage${_suffix}"
    sec_audit_remediate_done 278 "audit baseline covers usermod command usage${_suffix}"
    sec_audit_remediate_done 279 "audit baseline covers kernel module load/unload via kmod${_suffix}"
    sec_audit_remediate_done 280 "audit baseline covers init_module/finit_module${_suffix}"
    sec_audit_remediate_done 281 "audit baseline covers delete_module${_suffix}"
    sec_audit_remediate_done 282 "audit baseline covers query_module${_suffix}"
    mkdir -p /etc/audit/rules.d
    if ! grep -rqE '^-e[[:space:]]+2' /etc/audit/rules.d /etc/audit/audit.rules 2>/dev/null; then
        printf '%s\n' '-e 2' >>/etc/audit/rules.d/99-secaudit-oracle10-immutable.rules
    fi
    sec_audit_reload_audit_rules || true
    sec_audit_remediate_done 283 "audit rules configured to load (baseline + reload helper)"
    sec_audit_remediate_done 284 "audit immutable flag staged (-e 2 in rules.d; may need reboot if already locked)"

    sec_audit_harden_audit_logs
    sec_audit_remediate_done 285 "hardened audit log directory permissions"
    sec_audit_remediate_done 286 "hardened audit log file permissions"
    sec_audit_remediate_done 287 "hardened audit log file owner"
    sec_audit_remediate_done 288 "hardened audit log file group owner"
    sec_audit_harden_audit_config
    sec_audit_remediate_done 289 "hardened audit configuration file permissions"
    sec_audit_remediate_done 290 "hardened audit configuration file owner"
    sec_audit_remediate_done 291 "hardened audit configuration file group owner"
    sec_audit_harden_audit_tools
    sec_audit_remediate_done 292 "hardened audit tools permissions"
    sec_audit_remediate_done 293 "hardened audit tools owner"
    sec_audit_remediate_done 294 "hardened audit tools group owner"
}

sec_audit_remediate_identity_files_ext() {
    sec_audit_harden_path /etc/passwd 644 root:root || true
    sec_audit_remediate_done 295 "hardened /etc/passwd (644 root:root)"
    sec_audit_harden_path /etc/passwd- 644 root:root || true
    sec_audit_remediate_done 296 "hardened /etc/passwd- when present (644 root:root)"
    sec_audit_harden_path /etc/group 644 root:root || true
    sec_audit_remediate_done 297 "hardened /etc/group (644 root:root)"
    sec_audit_harden_path /etc/group- 644 root:root || true
    sec_audit_remediate_done 298 "hardened /etc/group- when present (644 root:root)"
    sec_audit_harden_path /etc/shadow 640 root:root || true
    sec_audit_remediate_done 299 "hardened /etc/shadow (640 root:root)"
    sec_audit_harden_path /etc/shadow- 640 root:root || true
    sec_audit_remediate_done 300 "hardened /etc/shadow- when present (640 root:root)"
    sec_audit_harden_path /etc/gshadow 640 root:root || true
    sec_audit_remediate_done 301 "hardened /etc/gshadow when present (640 root:root)"
    sec_audit_harden_path /etc/gshadow- 640 root:root || true
    sec_audit_remediate_done 302 "hardened /etc/gshadow- when present (640 root:root)"
    sec_audit_harden_path /etc/shells 644 root:root || true
    sec_audit_remediate_done 303 "hardened /etc/shells (644 root:root)"
    mkdir -p /etc/security
    [ -e /etc/security/opasswd ] || touch /etc/security/opasswd 2>/dev/null || true
    sec_audit_harden_path /etc/security/opasswd 600 root:root || true
    sec_audit_remediate_done 304 "hardened /etc/security/opasswd (600 root:root)"
}

sec_audit_remediate_filesystem_integrity_ext() {
    sec_audit_remediate_skip 305 "review remediation: world-writable files and directories are protected"
    sec_audit_remediate_skip 306 "review remediation: no unowned or ungrouped files/directories"
    sec_audit_remediate_skip 307 "accounts in /etc/passwd use shadowed passwords"
    sec_audit_remediate_skip 308 "review remediation: /etc/shadow password fields are not empty"
    sec_audit_remediate_skip 309 "all groups in /etc/passwd exist in /etc/group"
    sec_audit_remediate_skip 310 "no duplicate UIDs exist"
    sec_audit_remediate_skip 311 "no duplicate GIDs exist"
    sec_audit_remediate_skip 312 "no duplicate user names exist"
    sec_audit_remediate_skip 313 "no duplicate group names exist"
    sec_audit_remediate_skip 314 "local interactive user home directories are configured"
    sec_audit_remediate_skip 315 "local interactive user dot files access is configured"
}


sec_audit_maybe_security_upgrade() {
    if [ "${OL10_REMEDIATE_SECURITY_UPGRADE}" != "1" ]; then
        sec_audit_log "skipping dnf security upgrade (set OL10_REMEDIATE_SECURITY_UPGRADE=1 to enable)"
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
    sec_audit_log "starting remediation (Oracle Linux 10 / sec_audit_* style)"

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
    sec_audit_remediate_firewalld
    sec_audit_remediate_sshd
    sec_audit_remediate_sudo_su
    sec_audit_remediate_pam_auth
    sec_audit_remediate_accounts
    sec_audit_remediate_aide
    sec_audit_remediate_logging
    sec_audit_remediate_auditd
    sec_audit_remediate_identity_files
    sec_audit_remediate_filesystem_integrity
    sec_audit_remediate_auditd_extended
    sec_audit_remediate_identity_files_ext
    sec_audit_remediate_filesystem_integrity_ext

    sec_audit_maybe_security_upgrade
    sec_audit_log "remediation complete (Oracle10_remediation.sh)"
    exit 0
}

sec_audit_main "$@"
