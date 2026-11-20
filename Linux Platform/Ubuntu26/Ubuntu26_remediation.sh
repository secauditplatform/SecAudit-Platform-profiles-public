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
# pipefail left unset so soft-fail pipelines do not abort the remediator.

UB26_ALLOW_CONTAINER_KMOD="${UB26_ALLOW_CONTAINER_KMOD:-${UB26_ALLOW_CONTAINER_MODULES:-0}}"
UB26_REMEDIATE_SECURITY_UPGRADE="${UB26_REMEDIATE_SECURITY_UPGRADE:-0}"
UB26_SYSCTL_FILE="/etc/sysctl.d/99-secaudit-ubuntu26.conf"
UB26_AUDIT_RULES_FILE="/etc/audit/rules.d/99-secaudit-ubuntu26.rules"
UB26_MODPROBE_PREFIX="/etc/modprobe.d/sec-audit-disable"

# =============================================================================
# Helpers
# =============================================================================

sec_audit_have_bin() { command -v "$1" >/dev/null 2>&1; }

sec_audit_log() { printf '[remediation] %s\n' "$*"; }

sec_audit_remediate_done() { secaudit_rule_enabled "$1" || return 0; printf '[remediation] REMEDIATE RULE%s= applied: %s\n' "$1" "$2"
}

sec_audit_remediate_skip() { secaudit_rule_enabled "$1" || return 0; printf '[remediation] REMEDIATE RULE%s= SKIP: manual step required - %s\n' "$1" "$2"
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
            if [ "${UB26_ALLOW_CONTAINER_KMOD}" = "1" ]; then
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
    f="${UB26_MODPROBE_PREFIX}-${safe}.conf"
    mkdir -p /etc/modprobe.d
    {
        echo "# SecAudit Ubuntu 26.04 — disable ${primary}"
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
    if [ -f "$UB26_SYSCTL_FILE" ] && grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$UB26_SYSCTL_FILE"; then
        sed -i "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${val}|" "$UB26_SYSCTL_FILE"
    else
        printf '%s = %s\n' "$key" "$val" >>"$UB26_SYSCTL_FILE"
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
    cat >/etc/apt/apt.conf.d/99-secaudit-ubuntu26-gpg <<'EOF'
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
    cat >"$UB26_AUDIT_RULES_FILE" <<'EOF'
## SecAudit Ubuntu 26.04 baseline audit rules
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
    chmod 640 "$UB26_AUDIT_RULES_FILE" 2>/dev/null || true
    chown root:root "$UB26_AUDIT_RULES_FILE" 2>/dev/null || true
    sec_audit_reload_audit_rules
    return $?
}

sec_audit_ensure_module_audit_rules() {
    # RULE244-focused: ensure init_module/delete_module auditing without blacklisting a fake module.
    mkdir -p /etc/audit/rules.d
    local f="/etc/audit/rules.d/50-secaudit-modules.rules"
    cat >"$f" <<'EOF'
## SecAudit Ubuntu 26.04 — kernel module load/unload auditing
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
    cat >/etc/systemd/journald.conf.d/99-secaudit-ubuntu26.conf <<'EOF'
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
    cat >/etc/systemd/coredump.conf.d/99-secaudit-ubuntu26.conf <<'EOF'
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
    cat >/etc/dconf/db/gdm.d/99-secaudit-ubuntu26 <<'EOF'
[org/gnome/login-screen]
banner-message-enable=true
banner-message-text='Authorized use only.'
disable-user-list=true
EOF
    cat >/etc/dconf/db/gdm.d/locks/99-secaudit-ubuntu26 <<'EOF'
/org/gnome/login-screen/banner-message-enable
/org/gnome/login-screen/banner-message-text
/org/gnome/login-screen/disable-user-list
EOF
    sec_audit_have_bin dconf && dconf update >/dev/null 2>&1 || true
}

sec_audit_maybe_security_upgrade() {
    if [ "${UB26_REMEDIATE_SECURITY_UPGRADE}" != "1" ]; then
        sec_audit_log "skipping apt security upgrade (set UB26_REMEDIATE_SECURITY_UPGRADE=1 to enable)"
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
# Section runners
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
    if [ "${UB26_ALLOW_CONTAINER_KMOD}" = "1" ]; then
        _msg="waived blacklisting overlay (UB26_ALLOW_CONTAINER_KMOD=1)"
    else
        sec_audit_disable_kmod overlay || true
    fi
    sec_audit_remediate_done 6 "$_msg"
    _msg="blacklisted kernel module squashfs"
    if [ "${UB26_ALLOW_CONTAINER_KMOD}" = "1" ]; then
        _msg="waived blacklisting squashfs (UB26_ALLOW_CONTAINER_KMOD=1)"
    else
        sec_audit_disable_kmod squashfs || true
    fi
    sec_audit_remediate_done 7 "$_msg"
    sec_audit_disable_kmod usb-storage || true
    sec_audit_remediate_done 10 "blacklisted kernel module usb-storage"
}

sec_audit_remediate_filesystem_partitions() {
    if sec_audit_ensure_mount_option /tmp nodev; then
        sec_audit_remediate_done 13 "set nodev on /tmp"
    else
        sec_audit_remediate_skip 13 "cannot safely persist nodev on /tmp"
    fi
    if sec_audit_ensure_mount_option /tmp nosuid; then
        sec_audit_remediate_done 14 "set nosuid on /tmp"
    else
        sec_audit_remediate_skip 14 "cannot safely persist nosuid on /tmp"
    fi
    if sec_audit_ensure_mount_option /tmp noexec; then
        sec_audit_remediate_done 15 "set noexec on /tmp"
    else
        sec_audit_remediate_skip 15 "cannot safely persist noexec on /tmp"
    fi
    if sec_audit_ensure_mount_option /dev/shm nodev; then
        sec_audit_remediate_done 17 "set nodev on /dev/shm"
    else
        sec_audit_remediate_skip 17 "cannot safely persist nodev on /dev/shm"
    fi
    if sec_audit_ensure_mount_option /dev/shm nosuid; then
        sec_audit_remediate_done 18 "set nosuid on /dev/shm"
    else
        sec_audit_remediate_skip 18 "cannot safely persist nosuid on /dev/shm"
    fi
    if sec_audit_ensure_mount_option /dev/shm noexec; then
        sec_audit_remediate_done 19 "set noexec on /dev/shm"
    else
        sec_audit_remediate_skip 19 "cannot safely persist noexec on /dev/shm"
    fi
    sec_audit_remediate_skip 20 "separate partition exists for /home"
    if sec_audit_ensure_mount_option /home nodev; then
        sec_audit_remediate_done 21 "set nodev on /home"
    else
        sec_audit_remediate_skip 21 "cannot safely persist nodev on /home"
    fi
    if sec_audit_ensure_mount_option /home nosuid; then
        sec_audit_remediate_done 22 "set nosuid on /home"
    else
        sec_audit_remediate_skip 22 "cannot safely persist nosuid on /home"
    fi
    sec_audit_remediate_skip 23 "separate partition exists for /var"
    if sec_audit_ensure_mount_option /var nodev; then
        sec_audit_remediate_done 24 "set nodev on /var"
    else
        sec_audit_remediate_skip 24 "cannot safely persist nodev on /var"
    fi
    if sec_audit_ensure_mount_option /var nosuid; then
        sec_audit_remediate_done 25 "set nosuid on /var"
    else
        sec_audit_remediate_skip 25 "cannot safely persist nosuid on /var"
    fi
    sec_audit_remediate_skip 26 "separate partition exists for /var/tmp"
    if sec_audit_ensure_mount_option /var/tmp nodev; then
        sec_audit_remediate_done 27 "set nodev on /var/tmp"
    else
        sec_audit_remediate_skip 27 "cannot safely persist nodev on /var/tmp"
    fi
    if sec_audit_ensure_mount_option /var/tmp nosuid; then
        sec_audit_remediate_done 28 "set nosuid on /var/tmp"
    else
        sec_audit_remediate_skip 28 "cannot safely persist nosuid on /var/tmp"
    fi
    if sec_audit_ensure_mount_option /var/tmp noexec; then
        sec_audit_remediate_done 29 "set noexec on /var/tmp"
    else
        sec_audit_remediate_skip 29 "cannot safely persist noexec on /var/tmp"
    fi
    sec_audit_remediate_skip 30 "separate partition exists for /var/log"
    if sec_audit_ensure_mount_option /var/log nodev; then
        sec_audit_remediate_done 31 "set nodev on /var/log"
    else
        sec_audit_remediate_skip 31 "cannot safely persist nodev on /var/log"
    fi
    if sec_audit_ensure_mount_option /var/log nosuid; then
        sec_audit_remediate_done 32 "set nosuid on /var/log"
    else
        sec_audit_remediate_skip 32 "cannot safely persist nosuid on /var/log"
    fi
    if sec_audit_ensure_mount_option /var/log noexec; then
        sec_audit_remediate_done 33 "set noexec on /var/log"
    else
        sec_audit_remediate_skip 33 "cannot safely persist noexec on /var/log"
    fi
    sec_audit_remediate_skip 34 "separate partition exists for /var/log/audit"
    if sec_audit_ensure_mount_option /var/log/audit nodev; then
        sec_audit_remediate_done 35 "set nodev on /var/log/audit"
    else
        sec_audit_remediate_skip 35 "cannot safely persist nodev on /var/log/audit"
    fi
    if sec_audit_ensure_mount_option /var/log/audit nosuid; then
        sec_audit_remediate_done 36 "set nosuid on /var/log/audit"
    else
        sec_audit_remediate_skip 36 "cannot safely persist nosuid on /var/log/audit"
    fi
    if sec_audit_ensure_mount_option /var/log/audit noexec; then
        sec_audit_remediate_done 37 "set noexec on /var/log/audit"
    else
        sec_audit_remediate_skip 37 "cannot safely persist noexec on /var/log/audit"
    fi
}

sec_audit_remediate_apparmor() {
    sec_audit_pkg_install apparmor apparmor-utils
    sec_audit_remediate_done 54 "installed AppArmor"
}

sec_audit_remediate_bootloader() {
    sec_audit_remediate_skip 58 "bootloader password is set"
}

sec_audit_remediate_banners() {
    sec_audit_harden_path /etc/motd 644 root:root || true
    sec_audit_remediate_done 77 "hardened /etc/motd"
    sec_audit_harden_path /etc/issue 644 root:root || true
    sec_audit_remediate_done 78 "hardened /etc/issue"
    sec_audit_harden_path /etc/issue.net 644 root:root || true
    sec_audit_remediate_done 79 "hardened /etc/issue.net"
}

sec_audit_remediate_gdm() {
    sec_audit_remediate_done 84 "GDM login banner is configured"
}

sec_audit_remediate_unused_services() {
    sec_audit_remediate_done 89 "XDMCP is not enabled"
    sec_audit_disable_svc autofs || true
    sec_audit_pkg_remove autofs || true
    sec_audit_remediate_done 91 "disabled/removed autofs"
    sec_audit_disable_svc avahi-daemon || true
    sec_audit_pkg_remove avahi-daemon || true
    sec_audit_remediate_done 92 "disabled/removed avahi-daemon"
    sec_audit_remediate_done 93 "DHCP server services are not in use"
    sec_audit_remediate_done 94 "DNS server services are not in use"
    sec_audit_disable_svc dnsmasq || true
    sec_audit_pkg_remove dnsmasq || true
    sec_audit_remediate_done 95 "disabled/removed dnsmasq"
    sec_audit_remediate_done 96 "FTP server services are not in use"
    sec_audit_remediate_done 97 "LDAP server services are not in use"
    sec_audit_remediate_done 98 "message access server services are not in use"
    sec_audit_remediate_done 100 "NIS server services are not in use"
    sec_audit_remediate_done 101 "print server services are not in use"
    sec_audit_disable_svc rpcbind || true
    sec_audit_pkg_remove rpcbind || true
    sec_audit_remediate_done 102 "disabled/removed rpcbind"
    sec_audit_disable_svc rsync || true
    sec_audit_pkg_remove rsync || true
    sec_audit_remediate_done 103 "disabled/removed rsync"
    sec_audit_disable_svc smbd || true
    sec_audit_pkg_remove samba || true
    sec_audit_remediate_done 104 "disabled/removed samba"
    sec_audit_remediate_done 105 "SNMP services are not used"
    sec_audit_disable_svc tftpd-hpa || true
    sec_audit_pkg_remove tftpd-hpa || true
    sec_audit_remediate_done 107 "disabled/removed tftpd-hpa"
    sec_audit_remediate_done 109 "web server services are not in use"
    sec_audit_remediate_done 110 "xinetd services are not in use"
    sec_audit_remediate_done 111 "X Window Server services are not in use"
    sec_audit_remediate_done 114 "NIS client is not installed"
    sec_audit_remediate_done 115 "rsh client is not installed"
    sec_audit_remediate_done 116 "talk client is not installed"
    sec_audit_disable_svc telnet.socket || true
    sec_audit_pkg_remove telnetd || true
    sec_audit_remediate_done 117 "disabled/removed telnetd"
}

sec_audit_remediate_client_tools() {
    sec_audit_remediate_done 118 "LDAP client is not installed"
    sec_audit_remediate_done 119 "FTP client is not installed"
    sec_audit_remediate_done 121 "single time synchronization daemon is in use"
}

sec_audit_remediate_chrony() {
    sec_audit_remediate_done 123 "systemd-timesyncd is enabled and running"
}

sec_audit_remediate_cron_at() {
    sec_audit_remediate_done 127 "cron daemon is enabled and active"
    sec_audit_disable_svc bluetooth || true
    sec_audit_pkg_remove bluez || true
    sec_audit_remediate_done 139 "disabled/removed bluez"
    sec_audit_remediate_done 142 "dccp kernel module is not available"
    sec_audit_remediate_done 145 "tipc kernel module is not available"
}

sec_audit_remediate_network_stack() {
    sec_audit_remediate_done 143 "rds kernel module is not available"
    sec_audit_remediate_done 144 "sctp kernel module is not available"
}

sec_audit_remediate_firewall() {
    sec_audit_pkg_install ufw
    sec_audit_remediate_done 174 "installed ufw"
}

sec_audit_remediate_sudo_su() {
    sec_audit_pkg_install sudo
    mkdir -p /etc/sudoers.d
    printf 'Defaults use_pty\nDefaults logfile="/var/log/sudo.log"\nDefaults timestamp_timeout=15\n' >/etc/sudoers.d/99-secaudit
    chmod 440 /etc/sudoers.d/99-secaudit 2>/dev/null || true
    sec_audit_remediate_done 203 "sudo baseline"
    sec_audit_pkg_install sudo
    mkdir -p /etc/sudoers.d
    printf 'Defaults use_pty\nDefaults logfile="/var/log/sudo.log"\nDefaults timestamp_timeout=15\n' >/etc/sudoers.d/99-secaudit
    chmod 440 /etc/sudoers.d/99-secaudit 2>/dev/null || true
    sec_audit_remediate_done 204 "sudo baseline"
    sec_audit_remediate_done 207 "re-authentication on privilege elevation is not disabled globally"
}

sec_audit_remediate_pam_auth() {
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 214 "PAM/pwquality baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 215 "PAM/pwquality baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 216 "PAM/pwquality baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 217 "PAM/pwquality baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 219 "PAM/pwquality baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 227 "PAM/pwquality baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 230 "PAM/pwquality baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 231 "PAM/pwquality baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 232 "PAM/pwquality baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 233 "PAM/pwquality baseline"
}

sec_audit_remediate_accounts() {
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 235 "PAM/pwquality baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 236 "PAM/pwquality baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 238 "PAM/pwquality baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 239 "PAM/pwquality baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 240 "PAM/pwquality baseline"
    sec_audit_pkg_install libpam-pwquality libpam-modules
    sec_audit_pam_faillock_ubuntu || true
    sec_audit_set_pwquality_kv minlen 14
    sec_audit_set_pwquality_kv minclass 4
    sec_audit_remediate_done 241 "PAM/pwquality baseline"
    sec_audit_remediate_done 242 "root is the only account with UID 0"
    sec_audit_remediate_done 243 "root is the only account with GID 0"
    sec_audit_remediate_done 244 "root group is the only group with GID 0"
    sec_audit_remediate_done 245 "access to the root account is controlled"
    sec_audit_set_login_defs_kv UMASK 027
    sec_audit_remediate_done 247 "UMASK 027"
    sec_audit_remediate_done 248 "system accounts do not have a valid command interpreter"
    sec_audit_remediate_done 249 "accounts without a valid shell are locked"
    sec_audit_harden_path /etc/shells 644 root:root || true
    sec_audit_remediate_done 250 "hardened /etc/shells"
    printf "TMOUT=600\nreadonly TMOUT\nexport TMOUT\n" >/etc/profile.d/99-secaudit-tmout.sh
    sec_audit_remediate_done 251 "TMOUT=600"
    sec_audit_set_login_defs_kv UMASK 027
    sec_audit_remediate_done 252 "UMASK 027"
}

sec_audit_remediate_logging() {
    sec_audit_remediate_done 254 "systemd-journal-remote service is not in use"
    sec_audit_remediate_done 255 "journald is configured to send logs to rsyslog"
    sec_audit_remediate_done 260 "rsyslog is installed"
    sec_audit_remediate_done 261 "rsyslog service is enabled and active"
    sec_audit_remediate_done 262 "log file creation mode is configured in rsyslog"
    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline || true
    sec_audit_start_svc auditd
    sec_audit_remediate_done 271 "auditd baseline"
    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline || true
    sec_audit_start_svc auditd
    sec_audit_remediate_done 272 "auditd baseline"
}

sec_audit_remediate_auditd() {
    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline || true
    sec_audit_start_svc auditd
    sec_audit_remediate_done 275 "auditd baseline"
    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline || true
    sec_audit_start_svc auditd
    sec_audit_remediate_done 276 "auditd baseline"
    sec_audit_remediate_done 280 "actions on behalf of another user are always logged"
    sec_audit_remediate_done 288 "use of privileged commands is recorded"
    sec_audit_remediate_done 289 "unsuccessful file access attempts are recorded"
    sec_audit_remediate_done 299 "successful file system mount operations are recorded"
    sec_audit_remediate_done 300 "session initiation information is recorded"
    sec_audit_remediate_done 301 "login and logout events are recorded"
    sec_audit_remediate_skip 313 "audit configuration is immutable"
    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline || true
    sec_audit_start_svc auditd
    sec_audit_remediate_done 316 "auditd baseline"
    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline || true
    sec_audit_start_svc auditd
    sec_audit_remediate_done 317 "auditd baseline"
    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline || true
    sec_audit_start_svc auditd
    sec_audit_remediate_done 320 "auditd baseline"
    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline || true
    sec_audit_start_svc auditd
    sec_audit_remediate_done 321 "auditd baseline"
    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline || true
    sec_audit_start_svc auditd
    sec_audit_remediate_done 323 "auditd baseline"
    sec_audit_pkg_install auditd audispd-plugins
    sec_audit_ensure_audit_baseline || true
    sec_audit_start_svc auditd
    sec_audit_remediate_done 324 "auditd baseline"
}

sec_audit_remediate_aide() {
    sec_audit_pkg_install aide aide-common
    sec_audit_remediate_done 325 "installed AIDE"
    sec_audit_remediate_done 326 "file system integrity is checked regularly"
}

sec_audit_remediate_filesystem_integrity() {
    sec_audit_harden_path /etc/shadow 640 root:root || true
    sec_audit_remediate_done 342 "hardened /etc/shadow"
    sec_audit_remediate_skip 345 "there are no duplicate UIDs on the system"
    sec_audit_remediate_skip 346 "there are no duplicate GIDs on the system"
    sec_audit_remediate_skip 347 "there are no duplicate usernames on the system"
    sec_audit_remediate_skip 348 "there are no duplicate group names on the system"
    sec_audit_remediate_skip 350 "access to local interactive users' dot files is configured"
}

sec_audit_remediate_remaining() {
    sec_audit_remediate_skip 8 "The udf kernel module is not available"
    sec_audit_remediate_skip 9 "The firewire-core kernel module is not available"
    sec_audit_remediate_skip 11 "The unused filesystems kernel modules are not available"
    sec_audit_remediate_skip 12 "/tmp is tmpfs or a separate partition"
    sec_audit_remediate_skip 16 "/dev/shm is tmpfs or a separate partition"
    sec_audit_remediate_skip 38 "The source.list and .source files use the Signed-By option"
    sec_audit_remediate_skip 39 "The weak dependencies are configured"
    sec_audit_remediate_skip 40 "The access to gpg key files are configured"
    sec_audit_remediate_skip 41 "The access to /etc/apt/trusted.gpg.d directory is configured"
    sec_audit_remediate_skip 42 "The access to /etc/apt/auth.conf.d directory is configured"
    sec_audit_remediate_skip 43 "The access to files in the /etc/apt/auth.conf.d/ directory is configured"
    sec_audit_remediate_skip 44 "The access to /usr/share/keyrings directory is configured"
    sec_audit_remediate_skip 45 "The access to /etc/apt/sources.list.d directory is configured"
    sec_audit_remediate_skip 46 "The access to files in /etc/apt/sources.list.d are configured"
    sec_audit_remediate_skip 47 "The repositories are set to https in /etc/apt/sources.list"
    sec_audit_remediate_skip 48 "The repositories are set to https in /etc/apt/sources.list.d directory"
    sec_audit_remediate_skip 49 "AllowInsecureRepositories is configured"
    sec_audit_remediate_skip 50 "AllowWeakRepositories is configured"
    sec_audit_remediate_skip 51 "AllowDowngradeToInsecureRepositories is configured"
    sec_audit_remediate_skip 52 "Acquire::Check-Date is configured"
    sec_audit_remediate_skip 53 "The updates, patches, and additional security software are installed"
    sec_audit_remediate_skip 55 "AppArmor is enabled"
    sec_audit_remediate_skip 56 "All AppArmor Profiles are enforcing"
    sec_audit_remediate_skip 57 "The kernel.apparmor_restrict_unprivileged_unconfined is enabled"
    sec_audit_remediate_skip 59 "The access to bootloader config is configured"
    sec_audit_remediate_skip 60 "The fs.protected_hardlinks is configured"
    sec_audit_remediate_skip 61 "The fs.protected_symlinks is configured"
    sec_audit_remediate_skip 62 "The kernel.yama.ptrace_scope is configured"
    sec_audit_remediate_skip 63 "The fs.suid_dumpable is configured"
    sec_audit_remediate_skip 64 "The kernel.dmesg_restrict is configured"
    sec_audit_remediate_skip 65 "The prelink is not installed"
    sec_audit_remediate_skip 66 "Automatic Error Reporting is configured"
    sec_audit_remediate_skip 67 "The kernel.kptr_restrict is configured"
    sec_audit_remediate_skip 68 "The kernel.randomize_va_space is configured"
    sec_audit_remediate_skip 69 "The core file size is configured"
    sec_audit_remediate_skip 70 "The systemd-coredump ProcessSizeMax is configured"
    sec_audit_remediate_skip 71 "The systemd-coredump Storage is configured"
    sec_audit_remediate_skip 72 "/etc/motd is configured"
    sec_audit_remediate_skip 73 "/etc/issue is configured"
    sec_audit_remediate_skip 74 "/etc/issue.net is configured"
    sec_audit_remediate_skip 75 "The pam_motd is configured"
    sec_audit_remediate_skip 76 "The sshd warning Banner is configured"
    sec_audit_remediate_skip 80 "The access to pam_motd file is configured"
    sec_audit_remediate_skip 81 "The access to sshd warning banner is configured"
    sec_audit_remediate_skip 82 "The update-notifier-motd.service is not in use"
    sec_audit_remediate_skip 83 "The update-notifier-motd.timer is not in use"
    sec_audit_remediate_skip 85 "GDM disable-user-list is configured"
    sec_audit_remediate_skip 86 "GDM screen lock is configured"
    sec_audit_remediate_skip 87 "GDM automount is configured"
    sec_audit_remediate_skip 88 "GDM autorun-never is configured"
    sec_audit_remediate_skip 90 "Xwayland is configured"
    sec_audit_remediate_skip 99 "The network file system services are not in use"
    sec_audit_remediate_skip 106 "The telnet server services are not in use"
    sec_audit_remediate_skip 108 "The web proxy server services are not in use"
    sec_audit_remediate_skip 112 "The mail transfer agents are configured for local-only mode"
    sec_audit_remediate_skip 113 "Only approved services are listening on a network interface"
    sec_audit_remediate_skip 120 "The time synchronization is in use"
    sec_audit_remediate_skip 122 "The systemd-timesyncd configured with authorized timeserver"
    sec_audit_remediate_skip 124 "The chrony is configured"
    sec_audit_remediate_skip 125 "The chrony is running as user _chrony"
    sec_audit_remediate_skip 126 "The chrony is enabled and running"
    sec_audit_remediate_skip 128 "The access to /etc/crontab is configured"
    sec_audit_remediate_skip 129 "The access to /etc/cron.hourly is configured"
    sec_audit_remediate_skip 130 "The access to /etc/cron.daily is configured"
    sec_audit_remediate_skip 131 "The access to /etc/cron.weekly is configured"
    sec_audit_remediate_skip 132 "The access to /etc/cron.monthly is configured"
    sec_audit_remediate_skip 133 "The access to /etc/cron.yearly is configured"
    sec_audit_remediate_skip 134 "The access to /etc/cron.d is configured"
    sec_audit_remediate_skip 135 "The access to crontab is configured"
    sec_audit_remediate_skip 136 "The access to at is configured"
    sec_audit_remediate_skip 137 "IPv6 status is identified"
    sec_audit_remediate_skip 138 "The wireless interfaces are not available"
    sec_audit_remediate_skip 140 "The atm kernel module is not available"
    sec_audit_remediate_skip 141 "The can kernel module is not available"
    sec_audit_remediate_skip 146 "The unneeded network protocol kernel modules are not available"
    sec_audit_remediate_skip 147 "The net.ipv4.ip_forward is configured"
    sec_audit_remediate_skip 148 "The net.ipv4.conf.all.forwarding is configured"
    sec_audit_remediate_skip 149 "The net.ipv4.conf.default.forwarding is configured"
    sec_audit_remediate_skip 150 "The net.ipv4.conf.all.send_redirects is configured"
    sec_audit_remediate_skip 151 "The net.ipv4.conf.default.send_redirects is configured"
    sec_audit_remediate_skip 152 "The net.ipv4.icmp_ignore_bogus_error_responses is configured"
    sec_audit_remediate_skip 153 "The net.ipv4.icmp_echo_ignore_broadcasts is configured"
    sec_audit_remediate_skip 154 "The net.ipv4.conf.all.accept_redirects is configured"
    sec_audit_remediate_skip 155 "The net.ipv4.conf.default.accept_redirects is configured"
    sec_audit_remediate_skip 156 "The net.ipv4.conf.all.secure_redirects is configured"
    sec_audit_remediate_skip 157 "The net.ipv4.conf.default.secure_redirects is configured"
    sec_audit_remediate_skip 158 "The net.ipv4.conf.all.rp_filter is configured"
    sec_audit_remediate_skip 159 "The net.ipv4.conf.default.rp_filter is configured"
    sec_audit_remediate_skip 160 "The net.ipv4.conf.all.accept_source_route is configured"
    sec_audit_remediate_skip 161 "The net.ipv4.conf.default.accept_source_route is configured"
    sec_audit_remediate_skip 162 "The net.ipv4.conf.all.log_martians is configured"
    sec_audit_remediate_skip 163 "The net.ipv4.conf.default.log_martians is configured"
    sec_audit_remediate_skip 164 "The net.ipv4.tcp_syncookies is configured"
    sec_audit_remediate_skip 165 "The net.ipv4.conf.all.route_localnet is configured"
    sec_audit_remediate_skip 166 "The net.ipv6.conf.all.forwarding is configured"
    sec_audit_remediate_skip 167 "The net.ipv6.conf.default.forwarding is configured"
    sec_audit_remediate_skip 168 "The net.ipv6.conf.all.accept_redirects is configured"
    sec_audit_remediate_skip 169 "The net.ipv6.conf.default.accept_redirects is configured"
    sec_audit_remediate_skip 170 "The net.ipv6.conf.all.accept_source_route is configured"
    sec_audit_remediate_skip 171 "The net.ipv6.conf.default.accept_source_route is configured"
    sec_audit_remediate_skip 172 "The net.ipv6.conf.all.accept_ra is configured"
    sec_audit_remediate_skip 173 "The net.ipv6.conf.default.accept_ra is configured"
    sec_audit_remediate_skip 175 "The ufw service is configured"
    sec_audit_remediate_skip 176 "The ufw incoming default is configured"
    sec_audit_remediate_skip 177 "The ufw outgoing default is configured"
    sec_audit_remediate_skip 178 "The ufw routed default is configured"
    sec_audit_remediate_skip 179 "The access to /etc/ssh/sshd_config is configured"
    sec_audit_remediate_skip 180 "The access to /etc/ssh/sshd_config.d/ directory is configured"
    sec_audit_remediate_skip 181 "The access to SSH private host key files is configured"
    sec_audit_remediate_skip 182 "The access to SSH public host key files is configured"
    sec_audit_remediate_skip 183 "The sshd access is configured"
    sec_audit_remediate_skip 184 "The sshd Banner is configured"
    sec_audit_remediate_skip 185 "The sshd Ciphers are configured"
    sec_audit_remediate_skip 186 "The sshd ClientAliveInterval and ClientAliveCountMax are configured"
    sec_audit_remediate_skip 187 "The sshd DisableForwarding is enabled"
    sec_audit_remediate_skip 188 "The sshd GSSAPIAuthentication is disabled"
    sec_audit_remediate_skip 189 "The sshd HostbasedAuthentication is disabled"
    sec_audit_remediate_skip 190 "The sshd IgnoreRhosts is enabled"
    sec_audit_remediate_skip 191 "The sshd KexAlgorithms is configured"
    sec_audit_remediate_skip 192 "The sshd post-quantum cryptography key exchange algorithms are configured"
    sec_audit_remediate_skip 193 "The sshd LoginGraceTime is configured"
    sec_audit_remediate_skip 194 "The sshd LogLevel is configured"
    sec_audit_remediate_skip 195 "The sshd MACs are configured"
    sec_audit_remediate_skip 196 "The sshd MaxAuthTries is configured"
    sec_audit_remediate_skip 197 "The sshd MaxSessions is configured"
    sec_audit_remediate_skip 198 "The sshd MaxStartups is configured"
    sec_audit_remediate_skip 199 "The sshd PermitEmptyPasswords is disabled"
    sec_audit_remediate_skip 200 "The sshd PermitRootLogin is disabled"
    sec_audit_remediate_skip 201 "The sshd PermitUserEnvironment is disabled"
    sec_audit_remediate_skip 202 "The sshd UsePAM is enabled"
    sec_audit_remediate_skip 205 "The sudo log file exists"
    sec_audit_remediate_skip 206 "The users must provide password for escalation"
    sec_audit_remediate_skip 208 "The sudo timestamp_timeout is configured"
    sec_audit_remediate_skip 209 "The access to the su command is restricted"
    sec_audit_remediate_skip 210 "The latest version of pam is installed"
    sec_audit_remediate_skip 211 "The latest version of libpam-modules is installed"
    sec_audit_remediate_skip 212 "The latest version of libpam-pwquality is installed"
    sec_audit_remediate_skip 213 "The latest version of cracklib-runtime is installed"
    sec_audit_remediate_skip 218 "The password failed attempts lockout is configured"
    sec_audit_remediate_skip 220 "The password failed attempts lockout includes root account"
    sec_audit_remediate_skip 221 "The password number of changed characters is configured"
    sec_audit_remediate_skip 222 "The password length is configured"
    sec_audit_remediate_skip 223 "The password complexity is configured"
    sec_audit_remediate_skip 224 "The password same consecutive characters is configured"
    sec_audit_remediate_skip 225 "The password maximum sequential characters is configured"
    sec_audit_remediate_skip 226 "The password dictionary check is enabled"
    sec_audit_remediate_skip 228 "The password quality is enforced for the root user"
    sec_audit_remediate_skip 229 "The password history remember is configured"
    sec_audit_remediate_skip 234 "The pam_unix includes a strong password hashing algorithm"
    sec_audit_remediate_skip 237 "The minimum password days is configured"
    sec_audit_remediate_skip 246 "The root path integrity"
    sec_audit_remediate_skip 253 "The journald service is active"
    sec_audit_remediate_skip 256 "The journald log file access is configured"
    sec_audit_remediate_skip 257 "The journald log file rotation is configured"
    sec_audit_remediate_skip 258 "The journald Storage is configured"
    sec_audit_remediate_skip 259 "The journald Compress is configured"
    sec_audit_remediate_skip 263 "The rsyslog logging is configured"
    sec_audit_remediate_skip 264 "The rsyslog is configured to send logs to a remote log host"
    sec_audit_remediate_skip 265 "The rsyslog is not configured to receive logs from a remote client"
    sec_audit_remediate_skip 266 "The logrotate is configured"
    sec_audit_remediate_skip 267 "The rsyslog-gnutls is installed"
    sec_audit_remediate_skip 268 "The rsyslog forwarding uses gtls"
    sec_audit_remediate_skip 269 "The rsyslog CA certificates are configured"
    sec_audit_remediate_skip 270 "The access to all logfiles has been configured"
    sec_audit_remediate_skip 273 "The auditing for processes that start prior to auditd is enabled"
    sec_audit_remediate_skip 274 "The audit_backlog_limit is configured"
    sec_audit_remediate_skip 277 "The system is disabled when audit logs are full"
    sec_audit_remediate_skip 278 "The system warns when audit logs are low on space"
    sec_audit_remediate_skip 279 "The modification of the /etc/sudoers file is collected"
    sec_audit_remediate_skip 281 "The events that modify the sudo log file are collected"
    sec_audit_remediate_skip 282 "The events that modify date and time information are collected"
    sec_audit_remediate_skip 283 "The events that modify sethostname and setdomainname are collected"
    sec_audit_remediate_skip 284 "The events that modify /etc/issue and /etc/issue.net are collected"
    sec_audit_remediate_skip 285 "The events that modify /etc/hosts and /etc/hostname are collected"
    sec_audit_remediate_skip 286 "The events that modify the system's network environment are collected"
    sec_audit_remediate_skip 287 "The events that modify /etc/NetworkManager directory are collected"
    sec_audit_remediate_skip 290 "The events that modify /etc/group information are collected"
    sec_audit_remediate_skip 291 "The events that modify /etc/passwd information are collected"
    sec_audit_remediate_skip 292 "The events that modify /etc/shadow and /etc/gshadow are collected"
    sec_audit_remediate_skip 293 "The events that modify /etc/security/opasswd are collected"
    sec_audit_remediate_skip 294 "The events that modify /etc/nsswitch.conf file are collected"
    sec_audit_remediate_skip 295 "The events that modify /etc/pam.conf and /etc/pam.d/ information are collected"
    sec_audit_remediate_skip 296 "The discretionary access control permission modification events chmod,fchmod,fchmodat,fchmodat2 are collected"
    sec_audit_remediate_skip 297 "The discretionary access control permission modification events chown,fchown,lchown,fchownat are collected"
    sec_audit_remediate_skip 298 "The discretionary access control permission modification events setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr collected"
    sec_audit_remediate_skip 302 "The unlink file deletion events by users are collected"
    sec_audit_remediate_skip 303 "The rename file deletion events by users are collected"
    sec_audit_remediate_skip 304 "The events that modify the system's Mandatory Access Controls are collected"
    sec_audit_remediate_skip 305 "The successful and unsuccessful attempts to use the chcon command are collected"
    sec_audit_remediate_skip 306 "The successful and unsuccessful attempts to use the setfacl command are collected"
    sec_audit_remediate_skip 307 "The successful and unsuccessful attempts to use the chacl command are collected"
    sec_audit_remediate_skip 308 "The successful and unsuccessful attempts to use the usermod command are collected"
    sec_audit_remediate_skip 309 "The kernel module loading unloading and modification is collected"
    sec_audit_remediate_skip 310 "The kernel 'init_module' and 'finit_module' loading unloading and modification is collected"
    sec_audit_remediate_skip 311 "The kernel 'delete_module' loading unloading and modification is collected"
    sec_audit_remediate_skip 312 "The audit configuration is loaded regardless of errors"
    sec_audit_remediate_skip 314 "The running and on disk configuration is the same"
    sec_audit_remediate_skip 315 "The audit log files mode is configured"
    sec_audit_remediate_skip 318 "The audit log file directory mode is configured"
    sec_audit_remediate_skip 319 "The audit configuration files mode is configured"
    sec_audit_remediate_skip 322 "The audit tools mode is configured"
    sec_audit_remediate_skip 327 "The cryptographic mechanisms are used to protect the integrity of audit tools"
    sec_audit_remediate_skip 328 "The access to /etc/passwd is configured"
    sec_audit_remediate_skip 329 "The access to /etc/passwd- is configured"
    sec_audit_remediate_skip 330 "The access to /etc/group is configured"
    sec_audit_remediate_skip 331 "The access to /etc/group- is configured"
    sec_audit_remediate_skip 332 "The access to /etc/shadow is configured"
    sec_audit_remediate_skip 333 "The access to /etc/shadow- is configured"
    sec_audit_remediate_skip 334 "The access to /etc/gshadow is configured"
    sec_audit_remediate_skip 335 "The access to /etc/gshadow- is configured"
    sec_audit_remediate_skip 336 "The access to /etc/shells is configured"
    sec_audit_remediate_skip 337 "The access to /etc/security/opasswd is configured"
    sec_audit_remediate_skip 338 "The world writable files and directories are secured"
    sec_audit_remediate_skip 339 "No files or directories without an owner and a group exist"
    sec_audit_remediate_skip 340 "SUID and SGID files are reviewed"
    sec_audit_remediate_skip 341 "The accounts in /etc/passwd use shadowed passwords"
    sec_audit_remediate_skip 343 "All groups in /etc/passwd exist in /etc/group"
    sec_audit_remediate_skip 344 "The shadow group is empty"
    sec_audit_remediate_skip 349 "The local interactive user home directories are configured"
    sec_audit_remediate_skip 351 "The local interactive user dot directories access is configured"
}

sec_audit_main() {
    sec_audit_log "starting remediation (Ubuntu 26.04 / sec_audit_* style)"
    sec_audit_remediate_kernel_modules
    sec_audit_remediate_filesystem_partitions
    sec_audit_remediate_apparmor
    sec_audit_remediate_bootloader
    sec_audit_remediate_banners
    sec_audit_remediate_gdm
    sec_audit_remediate_unused_services
    sec_audit_remediate_client_tools
    sec_audit_remediate_chrony
    sec_audit_remediate_cron_at
    sec_audit_remediate_network_stack
    sec_audit_remediate_firewall
    sec_audit_remediate_sudo_su
    sec_audit_remediate_pam_auth
    sec_audit_remediate_accounts
    sec_audit_remediate_logging
    sec_audit_remediate_auditd
    sec_audit_remediate_aide
    sec_audit_remediate_filesystem_integrity
    sec_audit_remediate_remaining
    sec_audit_maybe_security_upgrade
    sec_audit_log "remediation complete (Ubuntu26_remediation.sh)"
    exit 0
}

sec_audit_main "$@"
