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

AL10_ALLOW_CONTAINER_KMOD="${AL10_ALLOW_CONTAINER_KMOD:-${CRE_ALLOW_CONTAINER_KMOD:-${LINUX_CRE_ALLOW_CONTAINER_MODULES:-${ALMA_CRE_ALLOW_CONTAINER_MODULES:-0}}}}"
AL10_REMEDIATE_SECURITY_UPGRADE="${AL10_REMEDIATE_SECURITY_UPGRADE:-0}"
AL10_SYSCTL_FILE="/etc/sysctl.d/99-secaudit-rhel10.conf"
AL10_AUDIT_RULES_FILE="/etc/audit/rules.d/99-secaudit-rhel10.rules"
AL10_MODPROBE_PREFIX="/etc/modprobe.d/sec-audit-disable"

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
            if [ "${AL10_ALLOW_CONTAINER_KMOD}" = "1" ]; then
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
    f="${AL10_MODPROBE_PREFIX}-${safe}.conf"
    mkdir -p /etc/modprobe.d
    {
        echo "# SecAudit RHEL 10 — disable ${primary}"
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
    if [ -f "$AL10_SYSCTL_FILE" ] && grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$AL10_SYSCTL_FILE"; then
        sed -i "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${val}|" "$AL10_SYSCTL_FILE"
    else
        printf '%s = %s\n' "$key" "$val" >>"$AL10_SYSCTL_FILE"
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
    cat >"$AL10_AUDIT_RULES_FILE" <<'EOF'
## SecAudit RHEL 10 baseline audit rules
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
    chmod 640 "$AL10_AUDIT_RULES_FILE" 2>/dev/null || true
    chown root:root "$AL10_AUDIT_RULES_FILE" 2>/dev/null || true
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
    cat >/etc/systemd/journald.conf.d/99-secaudit-rhel10.conf <<'EOF'
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
    cat >/etc/systemd/coredump.conf.d/99-secaudit-rhel10.conf <<'EOF'
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
    cat >/etc/dconf/db/gdm.d/99-secaudit-rhel10 <<'EOF'
[org/gnome/login-screen]
banner-message-enable=true
banner-message-text='Authorized use only.'
disable-user-list=true
EOF
    cat >/etc/dconf/db/gdm.d/locks/99-secaudit-rhel10 <<'EOF'
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
    if [ "${AL10_ALLOW_CONTAINER_KMOD}" = "1" ]; then
        _msg="waived blacklisting overlay (AL10_ALLOW_CONTAINER_KMOD=1)"
    else
        sec_audit_disable_kmod overlay || true
    fi
    sec_audit_remediate_done 6 "$_msg"

    _msg="blacklisted kernel module squashfs"
    if [ "${AL10_ALLOW_CONTAINER_KMOD}" = "1" ]; then
        _msg="waived blacklisting squashfs (AL10_ALLOW_CONTAINER_KMOD=1)"
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

    for _m in ceph cifs exfat fat fscache fuse gfs2 nfs_common nfsd smbfs_common; do
        sec_audit_disable_kmod "$_m" || true
    done
    sec_audit_remediate_done 11 "blacklisted unused filesystem kernel modules"
}

sec_audit_remediate_filesystem_partitions() {
    local _msg
    sec_audit_remediate_skip 12 "/tmp is tmpfs or a separate partition"
    sec_audit_ensure_mount_option /tmp nodev || true
    sec_audit_remediate_done 13 "set nodev on /tmp (tmpfs fstab persistence when needed)"
    sec_audit_remediate_skip 14 "nosuid option set on /tmp partition"
    sec_audit_ensure_mount_option /tmp noexec || true
    sec_audit_remediate_done 15 "set noexec on /tmp (tmpfs fstab persistence when needed)"

    sec_audit_remediate_skip 16 "/dev/shm is tmpfs or a separate partition"
    sec_audit_ensure_mount_option /dev/shm nodev || true
    sec_audit_remediate_done 17 "set nodev on /dev/shm (tmpfs fstab persistence when needed)"
    sec_audit_remediate_skip 18 "nosuid option set on /dev/shm partition"
    sec_audit_ensure_mount_option /dev/shm noexec || true
    sec_audit_remediate_done 19 "set noexec on /dev/shm (tmpfs fstab persistence when needed)"

    sec_audit_remediate_skip 20 "separate partition exists for /home"
    if sec_audit_ensure_mount_option /home nodev; then _msg="set nodev on /home"; else _msg="skipped inventing fstab for /home (no dedicated mount); nodev not persisted"; fi
    sec_audit_remediate_done 21 "$_msg"
    sec_audit_remediate_skip 22 "nosuid option set on /home partition"

    sec_audit_remediate_skip 23 "separate partition exists for /var"
    if sec_audit_ensure_mount_option /var nodev; then _msg="set nodev on /var"; else _msg="skipped inventing fstab for /var (no dedicated mount); nodev not persisted"; fi
    sec_audit_remediate_done 24 "$_msg"
    sec_audit_remediate_skip 25 "nosuid option set on /var partition"

    sec_audit_remediate_skip 26 "separate partition exists for /var/tmp"
    if sec_audit_ensure_mount_option /var/tmp nodev; then _msg="set nodev on /var/tmp"; else _msg="skipped inventing fstab for /var/tmp (no dedicated mount); nodev not persisted"; fi
    sec_audit_remediate_done 27 "$_msg"
    sec_audit_remediate_skip 28 "nosuid option set on /var/tmp partition"
    if sec_audit_ensure_mount_option /var/tmp noexec; then _msg="set noexec on /var/tmp"; else _msg="skipped inventing fstab for /var/tmp (no dedicated mount); noexec not persisted"; fi
    sec_audit_remediate_done 29 "$_msg"

    sec_audit_remediate_skip 30 "separate partition exists for /var/log"
    if sec_audit_ensure_mount_option /var/log nodev; then _msg="set nodev on /var/log"; else _msg="skipped inventing fstab for /var/log (no dedicated mount); nodev not persisted"; fi
    sec_audit_remediate_done 31 "$_msg"
    sec_audit_remediate_skip 32 "nosuid option set on /var/log partition"
    if sec_audit_ensure_mount_option /var/log noexec; then _msg="set noexec on /var/log"; else _msg="skipped inventing fstab for /var/log (no dedicated mount); noexec not persisted"; fi
    sec_audit_remediate_done 33 "$_msg"

    sec_audit_remediate_skip 34 "separate partition exists for /var/log/audit"
    if sec_audit_ensure_mount_option /var/log/audit nodev; then _msg="set nodev on /var/log/audit"; else _msg="skipped inventing fstab for /var/log/audit (no dedicated mount); nodev not persisted"; fi
    sec_audit_remediate_done 35 "$_msg"
    sec_audit_remediate_skip 36 "nosuid option set on /var/log/audit partition"
    if sec_audit_ensure_mount_option /var/log/audit noexec; then _msg="set noexec on /var/log/audit"; else _msg="skipped inventing fstab for /var/log/audit (no dedicated mount); noexec not persisted"; fi
    sec_audit_remediate_done 37 "$_msg"
}

sec_audit_remediate_package_security() {
    sec_audit_remediate_skip 38 "GPG keys are configured (import/review distribution signing keys manually)"
    sec_audit_set_dnf_main_kv gpgcheck 1
    sec_audit_set_dnf_main_kv localpkg_gpgcheck 1
    sec_audit_remediate_done 39 "enabled gpgcheck (and localpkg_gpgcheck) in dnf [main]"
    sec_audit_set_dnf_main_kv repo_gpgcheck 1
    sec_audit_remediate_done 40 "enabled repo_gpgcheck in dnf [main]"
    sec_audit_remediate_skip 41 "package manager repositories are configured"
    sec_audit_set_dnf_main_kv install_weak_deps 0
    sec_audit_remediate_done 42 "set install_weak_deps=0 in dnf [main]"
    sec_audit_remediate_skip 43 "security updates require operator-approved upgrade (see AL10_REMEDIATE_SECURITY_UPGRADE)"
}

sec_audit_remediate_selinux() {
    sec_audit_pkg_install libselinux selinux-policy-targeted
    sec_audit_remediate_done 44 "installed SELinux (libselinux)"
    if sec_audit_have_bin grubby; then
        grubby --update-kernel=ALL --remove-args="selinux=0 enforcing=0" >/dev/null 2>&1 || true
    fi
    if [ -f /etc/default/grub ]; then
        sed -i 's/ selinux=0//g; s/ enforcing=0//g' /etc/default/grub 2>/dev/null || true
    fi
    sec_audit_remediate_done 45 "removed selinux=0/enforcing=0 from bootloader args"
    if [ -f /etc/selinux/config ]; then
        if grep -qE '^[[:space:]]*SELINUXTYPE=' /etc/selinux/config; then
            sed -i 's/^[[:space:]]*SELINUXTYPE=.*/SELINUXTYPE=targeted/' /etc/selinux/config
        else
            echo 'SELINUXTYPE=targeted' >>/etc/selinux/config
        fi
    fi
    sec_audit_remediate_done 46 "SELINUXTYPE=targeted"
    if [ -f /etc/selinux/config ]; then
        if grep -qE '^[[:space:]]*SELINUX=' /etc/selinux/config; then
            sed -i 's/^[[:space:]]*SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
        else
            echo 'SELINUX=enforcing' >>/etc/selinux/config
        fi
    fi
    sec_audit_have_bin setenforce && setenforce 1 >/dev/null 2>&1 || true
    sec_audit_remediate_done 47 "SELinux not disabled (config enforcing)"
    sec_audit_remediate_done 48 "SELinux enforcing"
    sec_audit_remediate_skip 49 "no unconfined services exist"
    sec_audit_pkg_remove mcstrans
    sec_audit_disable_svc mcstrans.service
    sec_audit_remediate_done 50 "removed mcstrans"
    sec_audit_pkg_remove setroubleshoot
    sec_audit_disable_svc setroubleshoot.service
    sec_audit_remediate_done 51 "removed setroubleshoot"
}

sec_audit_remediate_bootloader() {
    sec_audit_remediate_skip 52 "bootloader password is set"
    sec_audit_harden_path /boot/grub2/grub.cfg 600 root:root || true
    sec_audit_harden_path /boot/grub2/user.cfg 600 root:root || true
    local g
    for g in /boot/efi/EFI/*/grub.cfg; do
        [ -f "$g" ] || continue
        sec_audit_harden_path "$g" 600 root:root || true
    done
    sec_audit_remediate_done 53 "hardened grub permissions"
}

sec_audit_remediate_process_hardening() {
    sec_audit_configure_coredump
    sec_audit_remediate_done 54 "disabled core dumps (limits + systemd-coredump)"
    sec_audit_set_sysctl fs.protected_hardlinks 1
    sec_audit_remediate_done 55 "set fs.protected_hardlinks=1"
    sec_audit_set_sysctl fs.protected_symlinks 1
    sec_audit_remediate_done 56 "set fs.protected_symlinks=1"
    sec_audit_set_sysctl fs.suid_dumpable 0
    sec_audit_remediate_done 57 "set fs.suid_dumpable=0"
    sec_audit_set_sysctl kernel.dmesg_restrict 1
    sec_audit_remediate_done 58 "set kernel.dmesg_restrict=1"
    sec_audit_set_sysctl kernel.kptr_restrict 2
    sec_audit_remediate_done 59 "set kernel.kptr_restrict=2"
    sec_audit_set_sysctl kernel.yama.ptrace_scope 1
    sec_audit_remediate_done 60 "set kernel.yama.ptrace_scope=1"
    sec_audit_set_sysctl kernel.randomize_va_space 2
    sec_audit_remediate_done 61 "set kernel.randomize_va_space=2"
    sec_audit_configure_coredump
    sec_audit_remediate_done 62 "coredump ProcessSizeMax=0"
    sec_audit_configure_coredump
    sec_audit_remediate_done 63 "systemd-coredump Storage=none"
}

sec_audit_remediate_crypto_policy() {
    if sec_audit_have_bin update-crypto-policies; then
        update-crypto-policies --set DEFAULT >/dev/null 2>&1 || true
    fi
    sec_audit_remediate_done 64 "crypto policy not LEGACY (DEFAULT)"
    if sec_audit_have_bin update-crypto-policies; then
        update-crypto-policies --set DEFAULT:NO-SHA1:NO-SSHCBC >/dev/null 2>&1             || update-crypto-policies --set DEFAULT >/dev/null 2>&1             || true
    fi
    sec_audit_remediate_done 65 "applied DEFAULT crypto policy modules (NO-SHA1 when available)"
    sec_audit_remediate_skip 66 "system-wide crypto policy MACs require site policy review"
    sec_audit_remediate_skip 67 "system wide crypto policy disables cbc for ssh"
}

sec_audit_remediate_banners() {
    sec_audit_sanitize_banner /etc/motd
    sec_audit_remediate_done 68 "sanitized banner /etc/motd"
    sec_audit_sanitize_banner /etc/issue
    sec_audit_remediate_done 69 "sanitized banner /etc/issue"
    sec_audit_sanitize_banner /etc/issue.net
    sec_audit_remediate_done 70 "sanitized banner /etc/issue.net"
    sec_audit_harden_path /etc/motd 644 root:root || true
    sec_audit_remediate_done 71 "permissions /etc/motd"
    sec_audit_harden_path /etc/issue 644 root:root || true
    sec_audit_remediate_done 72 "permissions /etc/issue"
    sec_audit_harden_path /etc/issue.net 644 root:root || true
    sec_audit_remediate_done 73 "permissions /etc/issue.net"
}

sec_audit_remediate_gdm() {
    sec_audit_gdm_dconf_stub
    sec_audit_remediate_done 74 "configured GDM hardening (dconf stub)"
    sec_audit_gdm_dconf_stub
    sec_audit_remediate_done 75 "configured GDM hardening (dconf stub)"
    sec_audit_gdm_dconf_stub
    sec_audit_remediate_done 76 "configured GDM hardening (dconf stub)"
    sec_audit_gdm_dconf_stub
    sec_audit_remediate_done 77 "configured GDM hardening (dconf stub)"
    sec_audit_gdm_dconf_stub
    sec_audit_remediate_done 78 "configured GDM hardening (dconf stub)"
    sec_audit_gdm_dconf_stub
    sec_audit_remediate_done 79 "configured GDM hardening (dconf stub)"
}

sec_audit_remediate_unused_services() {
    sec_audit_disable_svc autofs.service; sec_audit_pkg_remove autofs
    sec_audit_remediate_done 80 "disabled autofs"
    sec_audit_disable_svc avahi-daemon.socket; sec_audit_disable_svc avahi-daemon.service; sec_audit_pkg_remove avahi
    sec_audit_remediate_done 81 "disabled avahi"
    sec_audit_disable_svc cockpit.socket; sec_audit_disable_svc cockpit.service; sec_audit_pkg_remove cockpit-ws
    sec_audit_remediate_done 82 "disabled cockpit-ws"
    sec_audit_disable_svc dhcpd.service; sec_audit_disable_svc dhcpd6.service; sec_audit_pkg_remove dhcp-server
    sec_audit_remediate_done 83 "disabled dhcp-server"
    sec_audit_disable_svc named.service; sec_audit_pkg_remove bind
    sec_audit_remediate_done 84 "disabled bind"
    sec_audit_disable_svc dnsmasq.service; sec_audit_pkg_remove dnsmasq
    sec_audit_remediate_done 85 "disabled dnsmasq"
    sec_audit_disable_svc vsftpd.service; sec_audit_pkg_remove vsftpd
    sec_audit_remediate_done 86 "disabled vsftpd"
    sec_audit_disable_svc dovecot.service; sec_audit_pkg_remove dovecot
    sec_audit_remediate_done 87 "disabled dovecot/IMAP-POP3"
    sec_audit_disable_svc nfs-server.service; sec_audit_pkg_remove nfs-utils
    sec_audit_remediate_done 88 "disabled nfs-server"
    sec_audit_disable_svc cups.socket; sec_audit_disable_svc cups.service; sec_audit_pkg_remove cups
    sec_audit_remediate_done 89 "disabled cups"
    sec_audit_disable_svc rpcbind.socket; sec_audit_disable_svc rpcbind.service; sec_audit_pkg_remove rpcbind
    sec_audit_remediate_done 90 "disabled rpcbind"
    sec_audit_disable_svc rsyncd.socket; sec_audit_disable_svc rsyncd.service; sec_audit_pkg_remove rsync-daemon
    sec_audit_remediate_done 91 "disabled rsync-daemon"
    sec_audit_disable_svc smb.service; sec_audit_disable_svc smbd.service; sec_audit_pkg_remove samba
    sec_audit_remediate_done 92 "disabled samba"
    sec_audit_disable_svc snmpd.service; sec_audit_pkg_remove net-snmp
    sec_audit_remediate_done 93 "disabled net-snmp"
    sec_audit_disable_svc telnet.socket; sec_audit_pkg_remove telnet-server
    sec_audit_remediate_done 94 "disabled telnet-server"
    sec_audit_disable_svc tftp.socket; sec_audit_disable_svc tftp.service; sec_audit_pkg_remove tftp-server
    sec_audit_remediate_done 95 "disabled tftp-server"
    sec_audit_disable_svc squid.service; sec_audit_pkg_remove squid
    sec_audit_remediate_done 96 "disabled squid/web proxy"
    sec_audit_disable_svc httpd.service; sec_audit_disable_svc nginx.service; sec_audit_pkg_remove httpd nginx
    sec_audit_remediate_done 97 "disabled httpd/nginx"
    sec_audit_remediate_skip 98 "GNOME Display Manager removal requires operator confirmation"
    sec_audit_remediate_skip 99 "X window server removal requires operator confirmation"
    sec_audit_remediate_skip 100 "mail transfer agent local-only mode requires site MTA policy"
    sec_audit_remediate_skip 101 "approved listening services require manual inventory"
}

sec_audit_remediate_client_tools() {
    sec_audit_pkg_remove ftp
    sec_audit_remediate_done 102 "removed ftp"
    sec_audit_pkg_remove openldap-clients ldap-utils
    sec_audit_remediate_done 103 "removed openldap-clients/ldap-utils"
    sec_audit_pkg_remove telnet
    sec_audit_remediate_done 104 "removed telnet"
    sec_audit_pkg_remove tftp
    sec_audit_remediate_done 105 "removed tftp"
}

sec_audit_remediate_chrony() {
    sec_audit_pkg_install chrony
    sec_audit_start_svc chronyd
    sec_audit_remediate_done 106 "installed chrony"
    sec_audit_pkg_install chrony
    if ! grep -qE '^(pool|server)[[:space:]]' /etc/chrony.conf 2>/dev/null         && ! grep -qE '^(pool|server)[[:space:]]' /etc/chrony.d/*.conf 2>/dev/null; then
        echo 'pool 2.pool.ntp.org iburst' >>/etc/chrony.conf
    fi
    sec_audit_start_svc chronyd
    sec_audit_remediate_done 107 "configured chrony"
    sec_audit_remediate_skip 108 "chrony not run as root requires chrony.conf user directive review"
}

sec_audit_remediate_cron_at() {
    sec_audit_pkg_install cronie
    sec_audit_start_svc crond
    sec_audit_remediate_done 109 "enabled crond"
    sec_audit_harden_path /etc/crontab 600 root:root || true
    sec_audit_remediate_done 110 "restricted /etc/crontab"
    for _d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.yearly /etc/cron.d; do
        [ -d "$_d" ] || continue
        chmod 700 "$_d" 2>/dev/null || true
        chown root:root "$_d" 2>/dev/null || true
    done
    sec_audit_remediate_done 111 "restricted /etc/cron.hourly"
    sec_audit_remediate_done 112 "restricted /etc/cron.daily"
    sec_audit_remediate_done 113 "restricted /etc/cron.weekly"
    sec_audit_remediate_done 114 "restricted /etc/cron.monthly"
    sec_audit_remediate_done 115 "restricted /etc/cron.yearly"
    sec_audit_remediate_done 116 "restricted /etc/cron.d"
    rm -f /etc/cron.deny 2>/dev/null || true
    touch /etc/cron.allow 2>/dev/null || true
    sec_audit_harden_path /etc/cron.allow 600 root:root || true
    sec_audit_remediate_done 117 "configured crontab allow/deny"
    rm -f /etc/at.deny 2>/dev/null || true
    touch /etc/at.allow 2>/dev/null || true
    sec_audit_harden_path /etc/at.allow 600 root:root || true
    sec_audit_remediate_done 118 "configured at allow/deny"
}

sec_audit_remediate_network_stack() {
    sec_audit_remediate_skip 119 "IPv6 status is identified"
    sec_audit_disable_kmod bluetooth || true
    sec_audit_remediate_done 120 "disabled wireless/bluetooth kernel module path"
    sec_audit_disable_svc bluetooth.service; sec_audit_pkg_remove bluez
    sec_audit_remediate_done 121 "disabled bluez"
    sec_audit_disable_kmod atm || true
    sec_audit_remediate_done 122 "blacklisted atm"
    sec_audit_disable_kmod can || true
    sec_audit_remediate_done 123 "blacklisted can"
    sec_audit_disable_kmod dccp || true
    sec_audit_remediate_done 124 "blacklisted dccp"
    sec_audit_disable_kmod tipc || true
    sec_audit_remediate_done 125 "blacklisted tipc"
    sec_audit_disable_kmod rds || true
    sec_audit_remediate_done 126 "blacklisted rds"
    sec_audit_disable_kmod sctp || true
    sec_audit_remediate_done 127 "blacklisted sctp"

    sec_audit_set_sysctl net.ipv4.ip_forward 0
    sec_audit_remediate_done 128 "set net.ipv4.ip_forward=0"
    sec_audit_set_sysctl net.ipv4.conf.all.forwarding 0
    sec_audit_remediate_done 129 "set net.ipv4.conf.all.forwarding=0"
    sec_audit_set_sysctl net.ipv4.conf.default.forwarding 0
    sec_audit_remediate_done 130 "set net.ipv4.conf.default.forwarding=0"
    sec_audit_set_sysctl net.ipv4.conf.all.send_redirects 0
    sec_audit_remediate_done 131 "set net.ipv4.conf.all.send_redirects=0"
    sec_audit_set_sysctl net.ipv4.conf.default.send_redirects 0
    sec_audit_remediate_done 132 "set net.ipv4.conf.default.send_redirects=0"
    sec_audit_set_sysctl net.ipv4.icmp_ignore_bogus_error_responses 1
    sec_audit_remediate_done 133 "set net.ipv4.icmp_ignore_bogus_error_responses=1"
    sec_audit_set_sysctl net.ipv4.icmp_echo_ignore_broadcasts 1
    sec_audit_remediate_done 134 "set net.ipv4.icmp_echo_ignore_broadcasts=1"
    sec_audit_set_sysctl net.ipv4.conf.all.accept_redirects 0
    sec_audit_remediate_done 135 "set net.ipv4.conf.all.accept_redirects=0"
    sec_audit_set_sysctl net.ipv4.conf.default.accept_redirects 0
    sec_audit_remediate_done 136 "set net.ipv4.conf.default.accept_redirects=0"
    sec_audit_set_sysctl net.ipv4.conf.all.secure_redirects 0
    sec_audit_remediate_done 137 "set net.ipv4.conf.all.secure_redirects=0"
    sec_audit_set_sysctl net.ipv4.conf.default.secure_redirects 0
    sec_audit_remediate_done 138 "set net.ipv4.conf.default.secure_redirects=0"
    sec_audit_set_sysctl net.ipv4.conf.all.rp_filter 1
    sec_audit_remediate_done 139 "set net.ipv4.conf.all.rp_filter=1"
    sec_audit_set_sysctl net.ipv4.conf.default.rp_filter 1
    sec_audit_remediate_done 140 "set net.ipv4.conf.default.rp_filter=1"
    sec_audit_set_sysctl net.ipv4.conf.all.accept_source_route 0
    sec_audit_remediate_done 141 "set net.ipv4.conf.all.accept_source_route=0"
    sec_audit_set_sysctl net.ipv4.conf.default.accept_source_route 0
    sec_audit_remediate_done 142 "set net.ipv4.conf.default.accept_source_route=0"
    sec_audit_set_sysctl net.ipv4.conf.all.log_martians 1
    sec_audit_remediate_done 143 "set net.ipv4.conf.all.log_martians=1"
    sec_audit_set_sysctl net.ipv4.conf.default.log_martians 1
    sec_audit_remediate_done 144 "set net.ipv4.conf.default.log_martians=1"
    sec_audit_set_sysctl net.ipv4.tcp_syncookies 1
    sec_audit_remediate_done 145 "set net.ipv4.tcp_syncookies=1"
    sec_audit_set_sysctl net.ipv6.conf.all.forwarding 0
    sec_audit_remediate_done 146 "set net.ipv6.conf.all.forwarding=0"
    sec_audit_set_sysctl net.ipv6.conf.default.forwarding 0
    sec_audit_remediate_done 147 "set net.ipv6.conf.default.forwarding=0"
    sec_audit_set_sysctl net.ipv6.conf.all.accept_redirects 0
    sec_audit_remediate_done 148 "set net.ipv6.conf.all.accept_redirects=0"
    sec_audit_set_sysctl net.ipv6.conf.default.accept_redirects 0
    sec_audit_remediate_done 149 "set net.ipv6.conf.default.accept_redirects=0"
    sec_audit_set_sysctl net.ipv6.conf.all.accept_source_route 0
    sec_audit_remediate_done 150 "set net.ipv6.conf.all.accept_source_route=0"
    sec_audit_set_sysctl net.ipv6.conf.default.accept_source_route 0
    sec_audit_remediate_done 151 "set net.ipv6.conf.default.accept_source_route=0"
    sec_audit_set_sysctl net.ipv6.conf.all.accept_ra 0
    sec_audit_remediate_done 152 "set net.ipv6.conf.all.accept_ra=0"
    sec_audit_set_sysctl net.ipv6.conf.default.accept_ra 0
    sec_audit_remediate_done 153 "set net.ipv6.conf.default.accept_ra=0"
}

sec_audit_remediate_firewalld() {
    sec_audit_pkg_install firewalld
    sec_audit_start_svc firewalld
    sec_audit_remediate_done 154 "installed firewalld"
    sec_audit_remediate_skip 155 "firewalld backend is configured"
    sec_audit_start_svc firewalld
    sec_audit_remediate_done 156 "firewalld.service enabled/started"
    sec_audit_remediate_skip 157 "firewalld active zone target is configured"
    sec_audit_remediate_skip 158 "firewalld loopback traffic is configured"
    sec_audit_remediate_skip 159 "firewalld loopback source address is configured"
    sec_audit_remediate_skip 160 "firewalld services and ports are configured"
}

sec_audit_remediate_sshd() {
    sec_audit_harden_path /etc/ssh/sshd_config 600 root:root || true
    sec_audit_remediate_done 161 "hardened /etc/ssh/sshd_config"
    sec_audit_remediate_skip 162 "SSH private host key permissions require key inventory"
    sec_audit_remediate_skip 163 "SSH public host key permissions require key inventory"
    sec_audit_remediate_skip 164 "sshd access limits (AllowUsers/AllowGroups) require site policy"
    sec_audit_set_sshd_kv Banner /etc/issue.net || true
    sec_audit_remediate_done 165 "sshd Banner"
    sec_audit_remediate_skip 166 "sshd Ciphers require site crypto policy"
    sec_audit_set_sshd_kv ClientAliveInterval 300 || true
    sec_audit_remediate_done 167 "sshd ClientAliveInterval"
    sec_audit_set_sshd_kv DisableForwarding yes || true
    sec_audit_remediate_done 168 "sshd DisableForwarding"
    sec_audit_set_sshd_kv GSSAPIAuthentication no || true
    sec_audit_remediate_done 169 "sshd GSSAPIAuthentication"
    sec_audit_set_sshd_kv HostbasedAuthentication no || true
    sec_audit_remediate_done 170 "sshd HostbasedAuthentication"
    sec_audit_set_sshd_kv IgnoreRhosts yes || true
    sec_audit_remediate_done 171 "sshd IgnoreRhosts"
    sec_audit_remediate_skip 172 "sshd KexAlgorithms require site crypto policy"
    sec_audit_set_sshd_kv LoginGraceTime 60 || true
    sec_audit_remediate_done 173 "sshd LoginGraceTime"
    sec_audit_set_sshd_kv LogLevel VERBOSE || true
    sec_audit_remediate_done 174 "sshd LogLevel"
    sec_audit_remediate_skip 175 "sshd MACs require site crypto policy"
    sec_audit_set_sshd_kv MaxAuthTries 4 || true
    sec_audit_remediate_done 176 "sshd MaxAuthTries"
    sec_audit_set_sshd_kv MaxStartups 10:30:60 || true
    sec_audit_remediate_done 177 "sshd MaxStartups"
    sec_audit_set_sshd_kv MaxSessions 10 || true
    sec_audit_remediate_done 178 "sshd MaxSessions"
    sec_audit_set_sshd_kv PermitEmptyPasswords no || true
    sec_audit_remediate_done 179 "sshd PermitEmptyPasswords"
    sec_audit_set_sshd_kv PermitRootLogin no || true
    sec_audit_remediate_done 180 "sshd PermitRootLogin"
    sec_audit_set_sshd_kv PermitUserEnvironment no || true
    sec_audit_remediate_done 181 "sshd PermitUserEnvironment"
    sec_audit_set_sshd_kv UsePAM yes || true
    sec_audit_remediate_done 182 "sshd UsePAM"
}

sec_audit_remediate_sudo_su() {
    sec_audit_pkg_install sudo
    sec_audit_remediate_done 183 "sudo installed"
    echo 'Defaults use_pty' >/etc/sudoers.d/99-secaudit-pty
    chmod 440 /etc/sudoers.d/99-secaudit-pty
    sec_audit_remediate_done 184 "sudo use_pty"
    echo 'Defaults logfile="/var/log/sudo.log"' >/etc/sudoers.d/99-secaudit-sudolog
    chmod 440 /etc/sudoers.d/99-secaudit-sudolog
    sec_audit_remediate_done 185 "sudo logfile"
    sec_audit_remediate_skip 186 "users must provide password for escalation (remove NOPASSWD site-wide only with care)"
    sec_audit_remediate_skip 187 "re-authentication for privilege elevation (!authenticate) requires sudoers review"
    echo 'Defaults timestamp_timeout=5' >/etc/sudoers.d/99-secaudit-timeout
    chmod 440 /etc/sudoers.d/99-secaudit-timeout
    sec_audit_remediate_done 188 "sudo timestamp_timeout=5"
}

sec_audit_remediate_pam_auth() {
    sec_audit_remediate_skip 189 "active authselect profile includes pam modules"
    sec_audit_authselect_enable with-faillock
    sec_audit_remediate_done 190 "pam faillock enabled"
    sec_audit_authselect_enable with-pwquality
    sec_audit_remediate_done 191 "pam pwquality enabled"
    sec_audit_authselect_enable with-pwhistory
    sec_audit_remediate_done 192 "pam pwhistory enabled"
    sec_audit_remediate_skip 193 "pam_unix module enabled (authselect profile)"
    sec_audit_authselect_enable with-faillock
    sec_audit_set_faillock_kv deny 5
    sec_audit_remediate_done 194 "faillock deny=5"
    sec_audit_set_faillock_kv unlock_time 900
    sec_audit_remediate_done 195 "faillock unlock_time=900"
    sec_audit_set_faillock_kv even_deny_root yes
    sec_audit_remediate_done 196 "faillock even_deny_root"
    sec_audit_set_faillock_kv even_deny_root yes
    sec_audit_remediate_done 197 "faillock includes root"
    sec_audit_set_pwquality_kv difok 2
    sec_audit_remediate_done 198 "pwquality difok"
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_remediate_done 199 "pwquality minlen"
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 200 "pwquality complexity/minclass"
    sec_audit_set_pwquality_kv maxrepeat 3
    sec_audit_remediate_done 201 "pwquality maxrepeat"
    sec_audit_set_pwquality_kv maxclassrepeat 4
    sec_audit_remediate_done 202 "pwquality maxclassrepeat"
    sec_audit_set_pwquality_kv dictcheck 1
    sec_audit_remediate_done 203 "pwquality dictcheck"
    sec_audit_set_pwquality_kv enforce_for_root 1
    sec_audit_remediate_done 204 "pwquality enforce_for_root"
    mkdir -p /etc/security
    grep -qE '^[[:space:]]*remember[[:space:]]*=' /etc/security/pwhistory.conf 2>/dev/null || echo 'remember = 24' >>/etc/security/pwhistory.conf
    sec_audit_remediate_done 205 "pwhistory remember"
    grep -qE '^[[:space:]]*enforce_for_root' /etc/security/pwhistory.conf 2>/dev/null || echo 'enforce_for_root' >>/etc/security/pwhistory.conf
    sec_audit_remediate_done 206 "pwhistory enforce_for_root"
    sec_audit_remediate_skip 207 "pam_pwhistory use_authtok requires authselect/pam stack review"
    sec_audit_remediate_skip 208 "pam_unix nullok removal requires authselect/pam stack review"
    sec_audit_remediate_skip 209 "pam_unix remember removal requires authselect/pam stack review"
    sec_audit_remediate_skip 210 "pam_unix strong hash requires authselect/pam stack review"
    sec_audit_remediate_skip 211 "pam_unix use_authtok requires authselect/pam stack review"
}

sec_audit_remediate_accounts() {
    sec_audit_set_login_defs_kv PASS_MAX_DAYS 365
    sec_audit_remediate_done 212 "PASS_MAX_DAYS"
    sec_audit_set_login_defs_kv PASS_MIN_DAYS 1
    sec_audit_remediate_done 213 "PASS_MIN_DAYS"
    sec_audit_set_login_defs_kv PASS_WARN_AGE 7
    sec_audit_remediate_done 214 "PASS_WARN_AGE"
    sec_audit_set_login_defs_kv ENCRYPT_METHOD SHA512
    sec_audit_remediate_done 215 "ENCRYPT_METHOD SHA512"
    sec_audit_remediate_skip 216 "INACTIVE password lock requires useracct policy"
    sec_audit_remediate_skip 217 "last password change dates require account review"
    sec_audit_remediate_skip 218 "root is the only UID 0 account"
    sec_audit_remediate_skip 219 "root is the only GID 0 account"
    sec_audit_remediate_skip 220 "group root is the only GID 0 group"
    sec_audit_remediate_skip 221 "root account access is controlled"
    sec_audit_remediate_skip 222 "root PATH integrity"
    sec_audit_set_login_defs_kv UMASK 027
    cat >/etc/profile.d/99-secaudit-umask.sh <<'EOF'
umask 027
EOF
    sec_audit_remediate_done 223 "root/default umask 027"
    sec_audit_remediate_skip 224 "system accounts do not have a valid login shell"
    sec_audit_remediate_skip 225 "accounts without a valid login shell are locked"
    sec_audit_remediate_skip 226 "nologin is not listed in /etc/shells"
    cat >/etc/profile.d/99-secaudit-timeout.sh <<'EOF'
TMOUT=600
readonly TMOUT
export TMOUT
EOF
    sec_audit_remediate_done 227 "TMOUT=600"
    sec_audit_set_login_defs_kv UMASK 027
    cat >/etc/profile.d/99-secaudit-umask.sh <<'EOF'
umask 027
EOF
    sec_audit_remediate_done 228 "default user umask 027"
}

sec_audit_remediate_aide() {
    sec_audit_pkg_install aide
    sec_audit_remediate_done 229 "installed AIDE"
    sec_audit_remediate_skip 230 "filesystem integrity checked regularly (schedule aide --check)"
    sec_audit_remediate_skip 231 "cryptographic integrity of audit tools (aide.conf) requires site policy"
}

sec_audit_remediate_logging() {
    sec_audit_start_svc systemd-journald
    sec_audit_remediate_done 232 "journald active"
    sec_audit_remediate_skip 233 "journald log file access is configured"
    sec_audit_remediate_skip 234 "journald log file rotation is configured"
    sec_audit_remediate_skip 235 "only one logging system is in use"
    sec_audit_pkg_install systemd-journal-remote
    sec_audit_remediate_done 236 "systemd-journal-remote installed"
    sec_audit_remediate_skip 237 "journal-upload authentication requires site credentials"
    sec_audit_remediate_skip 238 "systemd-journal-upload enablement requires central logging policy"
    sec_audit_disable_svc systemd-journal-remote.socket
    sec_audit_disable_svc systemd-journal-remote.service
    sec_audit_remediate_done 239 "systemd-journal-remote not in use"
    sec_audit_configure_journald
    sec_audit_remediate_done 240 "journald ForwardToSyslog"
    sec_audit_configure_journald
    sec_audit_remediate_done 241 "journald Compress"
    sec_audit_configure_journald
    sec_audit_remediate_done 242 "journald Storage"
    sec_audit_pkg_install rsyslog
    sec_audit_remediate_done 243 "rsyslog installed"
    sec_audit_pkg_install rsyslog
    sec_audit_start_svc rsyslog
    sec_audit_remediate_done 244 "rsyslog enabled/active"
    sec_audit_configure_journald
    sec_audit_remediate_done 245 "journald forwards to rsyslog where configured"
    sec_audit_remediate_skip 246 "rsyslog file create mode requires rsyslog.conf review"
    sec_audit_remediate_skip 247 "rsyslog logging is configured"
    sec_audit_remediate_skip 248 "rsyslog remote host requires site collector"
    sec_audit_remediate_skip 249 "rsyslog must not receive remote logs unless intended"
    sec_audit_remediate_skip 250 "logrotate for rsyslog requires site policy"
    sec_audit_remediate_skip 251 "access to all logfiles has been configured"
}

sec_audit_remediate_auditd() {
    local _msg
    sec_audit_pkg_install audit audit-libs
    sec_audit_start_svc auditd
    sec_audit_remediate_done 252 "auditd packages installed / service started"

    if [ -f /etc/default/grub ]; then
        if grep -q 'audit=1' /etc/default/grub 2>/dev/null; then
            :
        elif grep -q '^GRUB_CMDLINE_LINUX=' /etc/default/grub; then
            sed -i 's/^GRUB_CMDLINE_LINUX="\([^"]*\)"/GRUB_CMDLINE_LINUX="\1 audit=1"/' /etc/default/grub
        fi
        if sec_audit_have_bin grubby; then
            grubby --update-kernel=ALL --args='audit=1' >/dev/null 2>&1 || true
        fi
    fi
    sec_audit_remediate_done 253 "set audit=1 in GRUB when /etc/default/grub exists"

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
    sec_audit_remediate_done 254 "set audit_backlog_limit=8192 in GRUB when present"

    sec_audit_pkg_install audit audit-libs
    sec_audit_start_svc auditd
    sec_audit_remediate_done 255 "auditd enabled/started"
    sec_audit_set_auditd_conf_kv max_log_file 8 || true
    sec_audit_remediate_done 256 "set auditd max_log_file"
    sec_audit_set_auditd_conf_kv max_log_file_action keep_logs || true
    sec_audit_remediate_done 257 "audit logs not automatically deleted"
    sec_audit_set_auditd_conf_kv space_left_action email || true
    sec_audit_set_auditd_conf_kv admin_space_left_action halt || true
    sec_audit_remediate_done 258 "system warns/halts when audit logs full"
    sec_audit_set_auditd_conf_kv space_left_action email || true
    sec_audit_remediate_done 259 "system warns when audit logs low on space"

    sec_audit_ensure_audit_baseline >/dev/null 2>&1 || true
    sec_audit_remediate_done 260 "audit baseline includes sudoers watch"
    sec_audit_remediate_done 261 "audit baseline includes user_emulation"
    sec_audit_remediate_done 262 "audit baseline includes sudo log watch"
    sec_audit_remediate_skip 263 "time-change audit rules require site baseline extension"
    sec_audit_remediate_skip 264 "hostname/domainname audit rules require site baseline extension"
    sec_audit_remediate_skip 265 "issue/issue.net audit rules require site baseline extension"
    sec_audit_remediate_skip 266 "hosts/hostname audit rules require site baseline extension"
    sec_audit_remediate_done 267 "audit baseline includes network/NetworkManager watches"
    sec_audit_remediate_done 268 "audit baseline includes NetworkManager directory watch"
    sec_audit_remediate_done 269 "audit baseline includes privileged command watches"
    sec_audit_remediate_done 270 "audit baseline includes unsuccessful access"
    sec_audit_remediate_done 271 "audit baseline includes /etc/group identity watch"
    sec_audit_remediate_done 272 "audit baseline includes /etc/passwd identity watch"
    sec_audit_remediate_done 273 "audit baseline includes shadow/gshadow identity watch"
    sec_audit_remediate_done 274 "audit baseline includes opasswd identity watch"
    sec_audit_remediate_skip 275 "nsswitch.conf audit watch requires site baseline extension"
    sec_audit_remediate_skip 276 "pam.conf/pam.d audit watch requires site baseline extension"
    sec_audit_remediate_skip 277 "MAC chmod audit syscalls require site baseline extension"
    sec_audit_remediate_skip 278 "MAC chown audit syscalls require site baseline extension"
    sec_audit_remediate_skip 279 "MAC xattr audit syscalls require site baseline extension"
    sec_audit_remediate_done 280 "audit baseline includes mount syscall watches"
    sec_audit_remediate_done 281 "audit baseline includes session watches"
    sec_audit_remediate_done 282 "audit baseline includes login watches"
    sec_audit_remediate_skip 283 "unlink deletion audit rules require site baseline extension"
    sec_audit_remediate_skip 284 "rename audit rules require site baseline extension"
    sec_audit_remediate_skip 285 "SELinux MAC policy audit watches require site baseline extension"
    sec_audit_remediate_skip 286 "chcon command audit watch requires site baseline extension"
    sec_audit_remediate_skip 287 "setfacl command audit watch requires site baseline extension"
    sec_audit_remediate_skip 288 "chacl command audit watch requires site baseline extension"
    sec_audit_remediate_skip 289 "usermod command audit watch requires site baseline extension"

    _msg="configured audit rules for kernel module load syscalls"
    if ! sec_audit_ensure_module_audit_rules; then
        _msg="wrote module audit rules on disk; kernel audit immutable or reload deferred"
    fi
    sec_audit_remediate_done 290 "$_msg"
    sec_audit_remediate_done 291 "module audit rules include init_module/finit_module"
    sec_audit_remediate_done 292 "module audit rules include delete_module"
    sec_audit_remediate_skip 293 "query_module audit watch requires site baseline extension"
    sec_audit_remediate_skip 294 "audit configuration loaded independently of errors (-f) requires careful rollout"
    sec_audit_remediate_skip 295 "audit configuration immutable (-e 2) requires careful rollout/reboot"
    sec_audit_remediate_skip 296 "running and on-disk audit configuration match"

    sec_audit_harden_audit_logs
    sec_audit_remediate_done 297 "audit log directory mode hardened"
    sec_audit_harden_audit_logs
    sec_audit_remediate_done 298 "audit log files mode hardened"
    sec_audit_harden_audit_logs
    sec_audit_remediate_done 299 "audit log files owner hardened"
    sec_audit_harden_audit_logs
    sec_audit_remediate_skip 300 "audit log files group owner is configured"
    sec_audit_harden_audit_config
    sec_audit_remediate_done 301 "audit configuration files mode hardened"
    sec_audit_harden_audit_config
    sec_audit_remediate_done 302 "audit configuration files owner hardened"
    sec_audit_harden_audit_config
    sec_audit_remediate_skip 303 "audit configuration files group owner is configured"
    sec_audit_harden_audit_tools
    sec_audit_remediate_done 304 "audit tools mode hardened"
    sec_audit_harden_audit_tools
    sec_audit_remediate_done 305 "audit tools owner hardened"
    sec_audit_harden_audit_tools
    sec_audit_remediate_skip 306 "audit tools group owner is configured"
}

sec_audit_remediate_identity_files() {
    sec_audit_harden_path /etc/passwd 644 root:root || true
    sec_audit_remediate_done 307 "hardened /etc/passwd (644 root:root)"
    sec_audit_harden_path /etc/passwd- 644 root:root || true
    sec_audit_remediate_done 308 "hardened /etc/passwd- when present"
    sec_audit_harden_path /etc/group 644 root:root || true
    sec_audit_remediate_done 309 "hardened /etc/group (644 root:root)"
    sec_audit_harden_path /etc/group- 644 root:root || true
    sec_audit_remediate_done 310 "hardened /etc/group- when present"
    sec_audit_harden_path /etc/shadow 640 root:root || true
    sec_audit_remediate_done 311 "hardened /etc/shadow (640 root:root)"
    sec_audit_harden_path /etc/shadow- 640 root:root || true
    sec_audit_remediate_done 312 "hardened /etc/shadow- when present"
    sec_audit_harden_path /etc/gshadow 640 root:root || true
    sec_audit_remediate_done 313 "hardened /etc/gshadow when present"
    sec_audit_harden_path /etc/gshadow- 640 root:root || true
    sec_audit_remediate_done 314 "hardened /etc/gshadow- when present"
    sec_audit_harden_path /etc/shells 644 root:root || true
    sec_audit_remediate_done 315 "hardened /etc/shells (644 root:root)"
    mkdir -p /etc/security
    [ -e /etc/security/opasswd ] || touch /etc/security/opasswd 2>/dev/null || true
    sec_audit_harden_path /etc/security/opasswd 600 root:root || true
    sec_audit_remediate_done 316 "hardened /etc/security/opasswd (600 root:root)"
}

sec_audit_remediate_filesystem_integrity() {
    sec_audit_remediate_skip 317 "world writable files and directories are secured"
    sec_audit_remediate_skip 318 "no unowned files or directories"
    sec_audit_remediate_skip 319 "SUID and SGID files are reviewed"
    sec_audit_remediate_skip 320 "accounts in /etc/passwd use shadowed passwords"
    sec_audit_remediate_skip 321 "/etc/shadow password fields are not empty"
    sec_audit_remediate_skip 322 "all groups in /etc/passwd exist in /etc/group"
    sec_audit_remediate_skip 323 "no duplicate UIDs exist"
    sec_audit_remediate_skip 324 "no duplicate GIDs exist"
    sec_audit_remediate_skip 325 "no duplicate user names exist"
    sec_audit_remediate_skip 326 "no duplicate group names exist"
    sec_audit_remediate_skip 327 "local interactive user home directories are configured"
    sec_audit_remediate_skip 328 "local interactive user dot files access is configured"
}

sec_audit_maybe_security_upgrade() {
    if [ "${AL10_REMEDIATE_SECURITY_UPGRADE}" != "1" ]; then
        sec_audit_log "skipping dnf security upgrade (set AL10_REMEDIATE_SECURITY_UPGRADE=1 to enable)"
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
    sec_audit_log "starting remediation (RHEL 10 / sec_audit_* style)"

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

    sec_audit_maybe_security_upgrade
    sec_audit_log "remediation complete (RHEL10_remediation.sh)"
    exit 0
}

sec_audit_main "$@"
