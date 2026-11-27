#!/usr/local/bin/bash

export LC_ALL=C

if [ -z "${BASH_VERSION:-}" ]; then
    if command -v bash >/dev/null 2>&1; then
        exec bash "$0" "$@"
    fi
    printf '%s\n' "ERROR: bash is required." >&2
    exit 1
fi

set +e

FBSD15_SYSCTL_CONF="${FBSD15_SYSCTL_CONF:-/etc/sysctl.conf}"
FBSD15_LOADER_CONF="${FBSD15_LOADER_CONF:-/boot/loader.conf.local}"
FBSD15_SSHD_CONFIG="${FBSD15_SSHD_CONFIG:-/etc/ssh/sshd_config}"
FBSD15_LOGIN_CONF="${FBSD15_LOGIN_CONF:-/etc/login.conf}"
FBSD15_SUDOERS="${FBSD15_SUDOERS:-/usr/local/etc/sudoers}"
FBSD15_SUDOERS_DIR="${FBSD15_SUDOERS_DIR:-/usr/local/etc/sudoers.d}"
FBSD15_SUDOERS_DROPIN="${FBSD15_SUDOERS_DROPIN:-${FBSD15_SUDOERS_DIR}/99-secaudit}"
FBSD15_NEWSYSLOG_CONF="${FBSD15_NEWSYSLOG_CONF:-/etc/newsyslog.conf}"
FBSD15_AUDIT_CONTROL="${FBSD15_AUDIT_CONTROL:-/etc/security/audit_control}"
FBSD15_BANNER_TEXT="${FBSD15_BANNER_TEXT:-Authorized use only. All activity is monitored and logged.}"
FBSD15_RESTORE_REMOVE_BAK="${FBSD15_RESTORE_REMOVE_BAK:-0}"
FBSD15_RESTORE_PACKAGES="${FBSD15_RESTORE_PACKAGES:-0}"

FBSD15_NOTES=()
FBSD15_SKIP=""
FBSD15_FAIL=""
FBSD15_RESTORED=0
FBSD15_REMOVED=0
FBSD15_WARN=()

sec_audit_have_bin() { command -v "$1" >/dev/null 2>&1; }
sec_audit_log() { printf '[restore] %s\n' "$*"; }

sec_audit_rule_start() { FBSD15_NOTES=(); FBSD15_SKIP=""; FBSD15_FAIL=""; }
sec_audit_note() { FBSD15_NOTES+=("$1"); }
sec_audit_skip_note() { FBSD15_SKIP="$1"; }
sec_audit_fail_note() { FBSD15_FAIL="$1"; }
sec_audit_warn() { FBSD15_WARN+=("$1"); }

sec_audit_rule_end() {
    local n="$1" joined=""
    if [ -n "$FBSD15_FAIL" ]; then
        printf '[restore] RESTORE RULE%s= failed: %s\n' "$n" "$FBSD15_FAIL"
        return
    fi
    if [ -n "$FBSD15_SKIP" ]; then
        printf '[restore] RESTORE RULE%s= SKIP: %s\n' "$n" "$FBSD15_SKIP"
        return
    fi
    if [ ${#FBSD15_NOTES[@]} -eq 0 ]; then
        printf '[restore] RESTORE RULE%s= applied: no change required\n' "$n"
        return
    fi
    joined=$(printf '%s; ' "${FBSD15_NOTES[@]}")
    printf '[restore] RESTORE RULE%s= applied: %s\n' "$n" "${joined%; }"
}

# Restore one path from path.secaudit.bak.
# cp-backup case: both exist → overwrite path from bak.
# mv case: only bak exists → move bak back to path.
sec_audit_restore_bak() {
    local f="$1" bak="${1}.secaudit.bak"
    [ -e "$bak" ] || return 1
    if [ -e "$f" ]; then
        cp -p "$bak" "$f" 2>/dev/null || return 1
        if [ "$FBSD15_RESTORE_REMOVE_BAK" = "1" ]; then
            rm -f "$bak" 2>/dev/null
        fi
    else
        mv "$bak" "$f" 2>/dev/null || return 1
    fi
    FBSD15_RESTORED=$((FBSD15_RESTORED + 1))
    return 0
}

sec_audit_restore_if_bak() {
    local f="$1"
    if sec_audit_restore_bak "$f"; then
        sec_audit_note "restored ${f} from ${f}.secaudit.bak"
        return 0
    fi
    return 1
}

sec_audit_remove_path() {
    local f="$1"
    [ -e "$f" ] || return 1
    rm -f "$f" 2>/dev/null || return 1
    FBSD15_REMOVED=$((FBSD15_REMOVED + 1))
    return 0
}

# Created by remediation with no prior content: remove when content matches banner text and no bak.
sec_audit_restore_banner() {
    local f="$1"
    if [ -e "${f}.secaudit.bak" ]; then
        sec_audit_restore_bak "$f" && sec_audit_note "restored ${f} from backup"
        return
    fi
    if [ -f "$f" ] && [ "$(cat "$f" 2>/dev/null)" = "$FBSD15_BANNER_TEXT" ]; then
        if sec_audit_remove_path "$f"; then
            sec_audit_note "removed remediation-created ${f}"
        else
            sec_audit_fail_note "could not remove ${f}"
        fi
        return
    fi
    sec_audit_skip_note "${f} unchanged or not created by remediation"
}

sec_audit_find_baks() {
    local root
    for root in \
        /etc \
        /boot \
        /usr/local/etc \
        /var/cron \
        /var/at \
        /var/yp \
        /root \
        /home
    do
        [ -d "$root" ] || continue
        find "$root" \( -name '*.secaudit.bak' -o -name '.*.secaudit.bak' \) 2>/dev/null
    done
    # shar may live under /usr/bin or /usr/local/bin
    for root in /usr/bin /usr/local/bin /bin; do
        [ -d "$root" ] || continue
        find "$root" -name 'shar.secaudit.bak' 2>/dev/null
    done
}

sec_audit_restore_all_baks() {
    local bak f count=0
    # Longest paths first so *.secaudit.bak.secaudit.bak is discarded before parent bak restore.
    while IFS= read -r bak; do
        [ -n "$bak" ] || continue
        [ -e "$bak" ] || continue
        f="${bak%.secaudit.bak}"
        # Nested bak artifact (remediation bug / re-entry): drop it, do not "restore" onto another bak.
        case "$f" in *.secaudit.bak)
            rm -f "$bak" 2>/dev/null
            FBSD15_REMOVED=$((FBSD15_REMOVED + 1))
            sec_audit_note "removed nested bak ${bak}"
            continue
            ;;
        esac
        if sec_audit_restore_bak "$f"; then
            count=$((count + 1))
            sec_audit_note "${f}"
        else
            sec_audit_warn "failed to restore ${f} from ${bak}"
        fi
    done < <(sec_audit_find_baks | awk '{ print length, $0 }' | sort -nr | cut -d' ' -f2-)
    if [ $count -eq 0 ]; then
        sec_audit_skip_note "no .secaudit.bak files found under known roots"
    else
        # collapse many notes into one summary; individual paths already counted
        FBSD15_NOTES=("restored ${count} path(s) from .secaudit.bak")
    fi
}

sec_audit_apply_sysctl_conf() {
    local f="$FBSD15_SYSCTL_CONF" key val applied=0 failed=0
    [ -f "$f" ] || { sec_audit_skip_note "${f} absent"; return; }
    if ! sec_audit_have_bin sysctl; then
        sec_audit_fail_note "sysctl not available"
        return
    fi
    while IFS= read -r line; do
        case "$line" in ''|\#*) continue ;; esac
        key=${line%%=*}
        val=${line#*=}
        key=$(printf '%s' "$key" | sed 's/[[:space:]]*$//')
        val=$(printf '%s' "$val" | sed 's/^[[:space:]]*//')
        [ -n "$key" ] || continue
        if sysctl -w "${key}=${val}" >/dev/null 2>&1; then
            applied=$((applied + 1))
        else
            failed=$((failed + 1))
        fi
    done < "$f"
    sec_audit_note "sysctl -w applied=${applied} failed=${failed} from ${f}"
}

sec_audit_reload_sshd() {
    if [ ! -f "$FBSD15_SSHD_CONFIG" ]; then
        sec_audit_skip_note "${FBSD15_SSHD_CONFIG} absent"
        return
    fi
    if sec_audit_have_bin sshd && ! sshd -t >/dev/null 2>&1; then
        sec_audit_fail_note "sshd -t failed after restore; fix ${FBSD15_SSHD_CONFIG} before reload"
        return
    fi
    service sshd reload >/dev/null 2>&1
    sec_audit_note "sshd configuration reloaded"
}

sec_audit_reload_auditd() {
    if sec_audit_have_bin sysrc && [ "$(sysrc -n auditd_enable 2>/dev/null)" = "YES" ]; then
        service auditd restart >/dev/null 2>&1
        sec_audit_note "auditd restarted"
    else
        sec_audit_skip_note "auditd not enabled"
    fi
}

sec_audit_cap_mkdb() {
    if [ -f "$FBSD15_LOGIN_CONF" ] && sec_audit_have_bin cap_mkdb; then
        cap_mkdb "$FBSD15_LOGIN_CONF" >/dev/null 2>&1
        sec_audit_note "cap_mkdb ${FBSD15_LOGIN_CONF}"
    else
        sec_audit_skip_note "login.conf or cap_mkdb unavailable"
    fi
}

sec_audit_remove_dropins() {
    local any=0
    if [ -e "$FBSD15_SUDOERS_DROPIN" ]; then
        if sec_audit_remove_path "$FBSD15_SUDOERS_DROPIN"; then
            sec_audit_note "removed ${FBSD15_SUDOERS_DROPIN}"
            any=1
        else
            sec_audit_fail_note "could not remove ${FBSD15_SUDOERS_DROPIN}"
            return
        fi
    fi
    if [ -e "${FBSD15_SUDOERS_DROPIN}.secaudit.bak" ]; then
        rm -f "${FBSD15_SUDOERS_DROPIN}.secaudit.bak" 2>/dev/null && {
            FBSD15_REMOVED=$((FBSD15_REMOVED + 1))
            sec_audit_note "removed ${FBSD15_SUDOERS_DROPIN}.secaudit.bak"
            any=1
        }
    fi
    if [ -e /etc/cron.d/aide ]; then
        if sec_audit_remove_path /etc/cron.d/aide; then
            sec_audit_note "removed /etc/cron.d/aide"
            any=1
        else
            sec_audit_fail_note "could not remove /etc/cron.d/aide"
            return
        fi
    fi
    if [ -f /var/log/sudo.log ] && [ ! -s /var/log/sudo.log ]; then
        sec_audit_remove_path /var/log/sudo.log && sec_audit_note "removed empty /var/log/sudo.log" && any=1
    fi
    if [ $any -eq 0 ]; then
        sec_audit_skip_note "no remediation drop-in artifacts present"
    fi
}

# Undo journal written by FreeBSD15_remediation.sh (sysrc, live sysctl, modes, created files, packages).
sec_audit_replay_journal() {
    local journal="${FBSD15_JOURNAL:-/var/backups/secaudit-fbsd15.journal}"
    local kind id rest mode owner group n=0 pkg_removed=0
    if [ ! -f "$journal" ]; then
        sec_audit_skip_note "no remediation journal"
        return
    fi
    while read -r kind id rest; do
        [ -n "$kind" ] || continue
        case "$kind" in
            \#*) continue ;;
            sysrc)
                if [ "$rest" = "__UNSET__" ] || [ "$rest" = "NONE" ]; then
                    sysrc -f /etc/rc.conf -x "$id" >/dev/null 2>&1 && n=$((n + 1))
                elif [ "$rest" = "__EMPTY__" ]; then
                    sysrc "${id}=" >/dev/null 2>&1 && n=$((n + 1))
                else
                    sysrc "${id}=${rest}" >/dev/null 2>&1 && n=$((n + 1))
                fi
                ;;
            sysctl)
                sysctl -w "${id}=${rest}" >/dev/null 2>&1 && n=$((n + 1))
                ;;
            mode)
                mode=${rest%% *}
                owner=${rest#* }; owner=${owner%% *}
                group=${rest##* }
                [ -e "$id" ] || continue
                chmod "$mode" "$id" 2>/dev/null
                chown "${owner}:${group}" "$id" 2>/dev/null
                n=$((n + 1))
                ;;
            created)
                if [ -e "$id" ] && rm -f "$id" 2>/dev/null; then
                    FBSD15_REMOVED=$((FBSD15_REMOVED + 1))
                    n=$((n + 1))
                fi
                ;;
            pkg_add)
                if sec_audit_have_bin pkg && pkg query %n "$id" >/dev/null 2>&1; then
                    pkg remove -y "$id" >/dev/null 2>&1 && n=$((n + 1))
                    pkg_removed=1
                fi
                ;;
        esac
    done < "$journal"
    if [ "$pkg_removed" = "1" ] && sec_audit_have_bin pkg; then
        pkg autoremove -y >/dev/null 2>&1 && n=$((n + 1))
    fi
    rm -f "$journal"
    sec_audit_note "replayed ${n} journal entries"
}

sec_audit_restore_rc_conf() {
    if [ -e /etc/rc.conf.secaudit.bak ]; then
        if sec_audit_restore_bak /etc/rc.conf; then
            sec_audit_note "restored /etc/rc.conf from backup"
            return
        fi
        sec_audit_fail_note "could not restore /etc/rc.conf"
        return
    fi
    sec_audit_note "rc.conf sysrc changes are reverted from the remediation journal"
}

sec_audit_restore_packages() {
    if [ "$FBSD15_RESTORE_PACKAGES" != "1" ]; then
        sec_audit_skip_note "set FBSD15_RESTORE_PACKAGES=1 to remove sudo/aide installed by remediation and attempt reinstall of removed packages"
        return
    fi
    if ! sec_audit_have_bin pkg; then
        sec_audit_fail_note "pkg not available"
        return
    fi
    local removed="" reinstalled=""
    for p in sudo aide; do
        pkg query %n "$p" >/dev/null 2>&1 || continue
        pkg remove -y "$p" >/dev/null 2>&1 && removed="${removed}${p} "
    done
    # Best-effort reinstall of packages remediation may have removed.
    if pkg install -y \
        vsftpd dovecot cyrus-imapd net-snmp freebsd-telnetd squid \
        freebsd-ftpd freebsd-shar >/dev/null 2>&1; then
        reinstalled="attempted"
    fi
    sec_audit_note "removed=[${removed:-none}] reinstall=${reinstalled:-failed_or_partial}"
    sec_audit_warn "package restore is best-effort; versions and prior install set are unknown"
}

sec_audit_irreversible_notes() {
    sec_audit_note "modes recorded in the remediation journal are restored; home/dotfile normalization is not"
    sec_audit_note "system-account shell changes and empty-password locks are not restored"
    sec_audit_note "pkg upgrades / freebsd-update installs are not rolled back"
    sec_audit_note "kernel modules unloaded at remediate time need reboot or kldload if still disabled in loader.conf after restore"
}

sec_audit_main() {
    sec_audit_log "starting restore (FreeBSD 15 / undo FreeBSD15_remediation.sh)"

    # 1) Restore every .secaudit.bak written or renamed by remediation
    sec_audit_rule_start; sec_audit_restore_all_baks; sec_audit_rule_end 1

    # 2) Banners created from scratch (no bak)
    sec_audit_rule_start; sec_audit_restore_banner /etc/motd; sec_audit_rule_end 2
    sec_audit_rule_start; sec_audit_restore_banner /etc/issue; sec_audit_rule_end 3
    sec_audit_rule_start; sec_audit_restore_banner /etc/issue.net; sec_audit_rule_end 4

    # 3) Drop-ins and empty artifacts created by remediation
    sec_audit_rule_start; sec_audit_remove_dropins; sec_audit_rule_end 5

    # 4) rc.conf (only if site/operator provided a bak; remediation itself does not)
    sec_audit_rule_start; sec_audit_restore_rc_conf; sec_audit_rule_end 6

    # 5) Rebuild derived DBs / live settings from restored files
    sec_audit_rule_start; sec_audit_cap_mkdb; sec_audit_rule_end 7
    sec_audit_rule_start; sec_audit_apply_sysctl_conf; sec_audit_rule_end 8
    sec_audit_rule_start; sec_audit_reload_sshd; sec_audit_rule_end 9
    sec_audit_rule_start
    service inetd reload >/dev/null 2>&1
    service syslogd reload >/dev/null 2>&1
    sec_audit_note "inetd/syslogd reload attempted"
    sec_audit_rule_end 10
    sec_audit_rule_start; sec_audit_reload_auditd; sec_audit_rule_end 11

    # 6) Optional package undo
    sec_audit_rule_start; sec_audit_restore_packages; sec_audit_rule_end 12

    # 7) Journal: prior sysrc/sysctl/mode/created/pkg
    sec_audit_rule_start; sec_audit_replay_journal; sec_audit_rule_end 14

    # 8) Explicit irreversible surface
    sec_audit_rule_start; sec_audit_irreversible_notes; sec_audit_rule_end 13

    if [ ${#FBSD15_WARN[@]} -gt 0 ]; then
        local w
        for w in "${FBSD15_WARN[@]}"; do
            sec_audit_log "WARN: $w"
        done
    fi
    sec_audit_log "restore complete: restored=${FBSD15_RESTORED} removed=${FBSD15_REMOVED}"
    sec_audit_log "loader.conf / kern.vty / *_load=NO changes apply after reboot if restored"
    exit 0
}

sec_audit_main "$@"
