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
FBSD15_SSH_BANNER="${FBSD15_SSH_BANNER:-/etc/issue.net}"
FBSD15_BANNER_TEXT="${FBSD15_BANNER_TEXT:-Authorized use only. All activity is monitored and logged.}"
FBSD15_REMEDIATE_UPDATES="${FBSD15_REMEDIATE_UPDATES:-0}"
FBSD15_SSHD_CIPHERS="${FBSD15_SSHD_CIPHERS:-aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr}"
FBSD15_SSHD_KEX="${FBSD15_SSHD_KEX:-curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512}"
FBSD15_SSHD_MACS="${FBSD15_SSHD_MACS:-hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com}"
FBSD15_SSHD_HOSTKEY="${FBSD15_SSHD_HOSTKEY:-rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519}"
FBSD15_SSHD_PUBKEY="${FBSD15_SSHD_PUBKEY:-rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519}"

FBSD15_NOTES=()
FBSD15_SKIP=""
FBSD15_FAIL=""

sec_audit_have_bin() { command -v "$1" >/dev/null 2>&1; }
sec_audit_log() { printf '[remediation] %s\n' "$*"; }

sec_audit_rule_start() { FBSD15_NOTES=(); FBSD15_SKIP=""; FBSD15_FAIL=""; }
sec_audit_note() { FBSD15_NOTES+=("$1"); }
sec_audit_skip_note() { FBSD15_SKIP="$1"; }
sec_audit_fail_note() { FBSD15_FAIL="$1"; }

sec_audit_rule_end() {
    local n="$1" joined=""
    if [ -n "$FBSD15_FAIL" ]; then
        printf '[remediation] REMEDIATE RULE%s= failed: %s\n' "$n" "$FBSD15_FAIL"
        return
    fi
    if [ -n "$FBSD15_SKIP" ]; then
        printf '[remediation] REMEDIATE RULE%s= SKIP: %s\n' "$n" "$FBSD15_SKIP"
        return
    fi
    if [ ${#FBSD15_NOTES[@]} -eq 0 ]; then
        printf '[remediation] REMEDIATE RULE%s= applied: no change required\n' "$n"
        return
    fi
    joined=$(printf '%s; ' "${FBSD15_NOTES[@]}")
    printf '[remediation] REMEDIATE RULE%s= applied: %s\n' "$n" "${joined%; }"
}

sec_audit_manual() { sec_audit_skip_note "$1"; }

sec_audit_mode() { stat -f %Lp "$1" 2>/dev/null || stat -c %a "$1" 2>/dev/null; }

sec_audit_backup() {
    local f="$1"
    [ -e "$f" ] || return 0
    [ -e "${f}.secaudit.bak" ] && return 0
    cp -p "$f" "${f}.secaudit.bak" 2>/dev/null
}

sec_audit_sed_inplace() {
    local f="$1" expr="$2"
    [ -f "$f" ] || return 1
    if sed --version >/dev/null 2>&1; then
        sed -i -E "$expr" "$f"
    else
        sed -i '' -E "$expr" "$f"
    fi
}

sec_audit_rewrite() {
    local f="$1"; shift
    local mode tmp
    [ -f "$f" ] || return 1
    mode=$(sec_audit_mode "$f")
    tmp="${f}.secaudit.tmp"
    awk "$@" "$f" > "$tmp" 2>/dev/null || { rm -f "$tmp"; return 1; }
    [ -s "$tmp" ] || { rm -f "$tmp"; return 1; }
    mv "$tmp" "$f" || { rm -f "$tmp"; return 1; }
    [ -n "$mode" ] && chmod "$mode" "$f" 2>/dev/null
    return 0
}

sec_audit_ensure_line() {
    local f="$1" line="$2"
    touch "$f" 2>/dev/null || return 1
    grep -qxF -- "$line" "$f" 2>/dev/null && return 0
    printf '%s\n' "$line" >> "$f"
}

sec_audit_set_kv() {
    local f="$1" key="$2" val="$3" sep="${4:-=}" esc
    [ -f "$f" ] || touch "$f" 2>/dev/null
    sec_audit_backup "$f"
    esc=$(printf '%s' "$key" | sed 's/[][\\.*^$/]/\\&/g')
    if grep -Eq "^[[:space:]]*${esc}[[:space:]]*${sep}" "$f" 2>/dev/null; then
        sec_audit_sed_inplace "$f" "s|^[[:space:]]*${esc}[[:space:]]*${sep}.*|${key}${sep}${val}|"
    else
        printf '%s%s%s\n' "$key" "$sep" "$val" >> "$f"
    fi
}

sec_audit_kld_disable() {
    local mod="$1" state="loader entry set"
    sec_audit_set_kv "$FBSD15_LOADER_CONF" "${mod}_load" '"NO"'
    if sec_audit_have_bin kldstat && kldstat -q -m "$mod" 2>/dev/null; then
        if kldunload "$mod" >/dev/null 2>&1; then
            state="module unloaded"
        else
            state="module still loaded, unload or reboot required"
        fi
    fi
    sec_audit_note "${mod}_load=\"NO\" in ${FBSD15_LOADER_CONF}, ${state}"
}

sec_audit_sysctl() {
    local key="$1" val="$2"
    sec_audit_set_kv "$FBSD15_SYSCTL_CONF" "$key" "$val"
    if sec_audit_have_bin sysctl && sysctl -w "${key}=${val}" >/dev/null 2>&1; then
        sec_audit_note "${key}=${val} (persistent and live)"
    else
        sec_audit_fail_note "${key}=${val} written to ${FBSD15_SYSCTL_CONF}, live sysctl failed"
    fi
}

sec_audit_sysrc() {
    local name="$1" val="$2"
    if ! sec_audit_have_bin sysrc; then
        sec_audit_fail_note "sysrc not available"
        return
    fi
    if sysrc "${name}=${val}" >/dev/null 2>&1; then
        sec_audit_note "${name}=${val} in /etc/rc.conf"
    else
        sec_audit_fail_note "could not set ${name}=${val}"
    fi
}

sec_audit_disable_service() {
    local svc="$1"
    if ! sec_audit_have_bin sysrc; then
        sec_audit_fail_note "sysrc not available"
        return
    fi
    sysrc "${svc}_enable=NO" >/dev/null 2>&1
    service "$svc" stop >/dev/null 2>&1
    sec_audit_note "${svc}_enable=NO"
}

sec_audit_pkg_install() {
    if ! sec_audit_have_bin pkg; then
        sec_audit_fail_note "pkg not available"
        return
    fi
    if pkg install -y "$@" >/dev/null 2>&1; then
        sec_audit_note "installed: $*"
    else
        sec_audit_fail_note "package install failed (repository unreachable?): $*"
    fi
}

sec_audit_pkg_remove() {
    local p removed=""
    if ! sec_audit_have_bin pkg; then
        sec_audit_fail_note "pkg not available"
        return
    fi
    for p in "$@"; do
        pkg query %n "$p" >/dev/null 2>&1 || continue
        pkg remove -y "$p" >/dev/null 2>&1 && removed="${removed}${p} "
    done
    if [ -n "$removed" ]; then
        sec_audit_note "removed: ${removed}"
    else
        sec_audit_note "packages absent: $*"
    fi
}

sec_audit_file_perms() {
    local mode="$1" owner="$2" group="$3"; shift 3
    local f any=0
    for f in "$@"; do
        [ -e "$f" ] || continue
        chmod "$mode" "$f" 2>/dev/null
        chown "${owner}:${group}" "$f" 2>/dev/null
        any=1
    done
    if [ $any -eq 1 ]; then
        sec_audit_note "mode=${mode} owner=${owner}:${group} on existing: $*"
    else
        sec_audit_skip_note "target path(s) absent: $*"
    fi
}

sec_audit_sshd_set() {
    local opt="$1" val="$2" file="$FBSD15_SSHD_CONFIG" esc
    if [ ! -f "$file" ]; then
        sec_audit_skip_note "${file} not present"
        return
    fi
    sec_audit_backup "$file"
    esc=$(printf '%s' "$opt" | sed 's/[][\\.*^$/]/\\&/g')
    if grep -Eqi "^[[:space:]]*${esc}[[:space:]]+" "$file" 2>/dev/null; then
        sec_audit_sed_inplace "$file" "s|^[[:space:]]*${esc}[[:space:]]+.*|${opt} ${val}|"
    else
        printf '%s %s\n' "$opt" "$val" >> "$file"
    fi
    if sec_audit_have_bin sshd && ! sshd -t >/dev/null 2>&1; then
        cp -p "${file}.secaudit.bak" "$file" 2>/dev/null
        sec_audit_fail_note "sshd -t rejected the change; ${opt} reverted"
        return
    fi
    service sshd reload >/dev/null 2>&1
    sec_audit_note "${opt} ${val}"
}

sec_audit_banner_file() {
    local file="$1"
    if [ -s "$file" ]; then
        sec_audit_note "${file} present"
        return
    fi
    sec_audit_backup "$file"
    printf '%s\n' "$FBSD15_BANNER_TEXT" > "$file" 2>/dev/null
    chmod 644 "$file" 2>/dev/null
    chown root:wheel "$file" 2>/dev/null
    sec_audit_note "${file} created"
}

sec_audit_fstab_option() {
    local mp="$1" opt="$2" f=/etc/fstab line opts new
    [ -f "$f" ] || { sec_audit_skip_note "${f} absent"; return; }
    line=$(awk -v mp="$mp" '$2==mp{print; exit}' "$f")
    if [ -z "$line" ]; then
        sec_audit_skip_note "no ${f} entry for ${mp} (ZFS dataset or not a separate mount)"
        return
    fi
    opts=$(printf '%s\n' "$line" | awk '{print $4}')
    case ",${opts}," in
        *",${opt},"*)
            sec_audit_note "${opt} already set on ${mp}"
            return
            ;;
    esac
    new="${opts},${opt}"
    sec_audit_backup "$f"
    if ! sec_audit_rewrite "$f" -v mp="$mp" -v o="$new" 'BEGIN{OFS="\t"} $2==mp {$4=o} {print}'; then
        sec_audit_fail_note "could not update ${f} for ${mp}"
        return
    fi
    if sec_audit_have_bin mount && mount -u -o "$opt" "$mp" >/dev/null 2>&1; then
        sec_audit_note "${opt} added to ${f} and remounted ${mp}"
    else
        sec_audit_fail_note "${opt} added to ${f}; remount of ${mp} failed (applies on reboot)"
    fi
}

sec_audit_inetd_disable() {
    local svc="$1" f=/etc/inetd.conf
    if [ ! -f "$f" ]; then
        sec_audit_note "${f} absent, ${svc} not enabled"
        return
    fi
    if ! grep -Eq "^[[:space:]]*${svc}[[:space:]]" "$f"; then
        sec_audit_note "${svc} already disabled in ${f}"
        return
    fi
    sec_audit_backup "$f"
    sec_audit_sed_inplace "$f" "s|^[[:space:]]*(${svc}[[:space:]].*)|# \\1|"
    service inetd reload >/dev/null 2>&1
    sec_audit_note "${svc} commented out in ${f}"
}

sec_audit_audit_flag() {
    local class="$1" f="$FBSD15_AUDIT_CONTROL" flags
    if [ ! -f "$f" ]; then
        sec_audit_skip_note "${f} not present"
        return
    fi
    flags=$(grep -E '^[[:space:]]*flags:' "$f" 2>/dev/null | head -n1 | sed 's/^[[:space:]]*flags:[[:space:]]*//')
    case ",${flags}," in
        *",${class},"*)
            sec_audit_note "flag ${class} already enabled"
            return
            ;;
    esac
    sec_audit_backup "$f"
    if [ -z "$flags" ]; then
        printf 'flags:%s\n' "$class" >> "$f"
    else
        sec_audit_sed_inplace "$f" "s|^[[:space:]]*flags:.*|flags:${flags},${class}|"
    fi
    sec_audit_audit_reload
    sec_audit_note "flag ${class} enabled"
}

sec_audit_audit_reload() {
    if sec_audit_have_bin sysrc && [ "$(sysrc -n auditd_enable 2>/dev/null)" = "YES" ]; then
        service auditd restart >/dev/null 2>&1
    fi
}

sec_audit_pam_option() {
    local module="$1" option="$2" f hit=0
    for f in /etc/pam.d/*; do
        [ -f "$f" ] || continue
        awk -v m="$module" 'index($0, m) > 0 && $0 !~ /^[ \t]*#/ { found = 1; exit } END { exit found ? 0 : 1 }' "$f" || continue
        hit=1
        grep -qF -- "$option" "$f" 2>/dev/null && continue
        sec_audit_backup "$f"
        sec_audit_rewrite "$f" -v m="$module" -v o="$option" \
            '{ if (index($0, m) > 0 && $0 !~ /^[ \t]*#/) $0 = $0 " " o; print }' || hit=0
    done
    if [ $hit -eq 1 ]; then
        sec_audit_note "${option} ensured on ${module} lines"
    else
        sec_audit_skip_note "no active ${module} line in /etc/pam.d; add ${option} manually"
    fi
}

sec_audit_pam_setv() {
    local module="$1" key="$2" val="$3" f hit=0
    for f in /etc/pam.d/*; do
        [ -f "$f" ] || continue
        awk -v m="$module" 'index($0, m) > 0 && $0 !~ /^[ \t]*#/ { found = 1; exit } END { exit found ? 0 : 1 }' "$f" || continue
        hit=1
        sec_audit_backup "$f"
        sec_audit_rewrite "$f" -v m="$module" -v k="$key" -v v="$val" '
            {
                if (index($0, m) > 0 && $0 !~ /^[ \t]*#/) {
                    if (index($0, k "=") > 0) {
                        pat = k "=[^ ]*"
                        if (match($0, pat)) {
                            $0 = substr($0, 1, RSTART - 1) k "=" v substr($0, RSTART + RLENGTH)
                        }
                    } else {
                        $0 = $0 " " k "=" v
                    }
                }
                print
            }'
    done
    if [ $hit -eq 1 ]; then
        sec_audit_note "${key}=${val} set on ${module} lines"
    else
        sec_audit_skip_note "no active ${module} line in /etc/pam.d; add ${key}=${val} manually"
    fi
}

sec_audit_pam_unix_no_nullok() {
    local f touched=0
    for f in /etc/pam.d/passwd /etc/pam.d/system; do
        [ -f "$f" ] || continue
        grep -qF -- 'nullok' "$f" 2>/dev/null || continue
        sec_audit_backup "$f"
        sec_audit_sed_inplace "$f" 's/[[:space:]]+nullok//g' && touched=1
    done
    if [ $touched -eq 1 ]; then
        sec_audit_note "nullok removed from pam_unix lines"
    else
        sec_audit_note "pam_unix lines do not use nullok"
    fi
}

sec_audit_login_conf() {
    local key="$1" val="$2" f="$FBSD15_LOGIN_CONF" mode tmp
    if [ ! -f "$f" ]; then
        sec_audit_skip_note "${f} not present"
        return
    fi
    sec_audit_backup "$f"
    if grep -Eq "^[[:space:]]*:${key}=" "$f" 2>/dev/null; then
        sec_audit_sed_inplace "$f" "s|^[[:space:]]*:${key}=[^:]*|:${key}=${val}|"
    elif grep -Eq '^default:[[:space:]]*\\$' "$f" 2>/dev/null; then
        mode=$(sec_audit_mode "$f")
        tmp="${f}.secaudit.tmp"
        awk -v k="$key" -v v="$val" '
            { print }
            !done && $0 ~ /^default:[[:space:]]*\\$/ { print "\t:" k "=" v ":\\"; done = 1 }
        ' "$f" > "$tmp" 2>/dev/null
        if [ ! -s "$tmp" ]; then
            rm -f "$tmp"
            sec_audit_skip_note "could not edit the default: block of ${f}"
            return
        fi
        mv "$tmp" "$f"
        [ -n "$mode" ] && chmod "$mode" "$f" 2>/dev/null
    else
        sec_audit_skip_note "default: block is single-line in ${f}; add :${key}=${val}: manually"
        return
    fi
    sec_audit_have_bin cap_mkdb && cap_mkdb "$f" >/dev/null 2>&1
    sec_audit_note ":${key}=${val}:"
}

sec_audit_sudoers_dropin() {
    local line="$1" f="$FBSD15_SUDOERS_DROPIN"
    if [ ! -d "$FBSD15_SUDOERS_DIR" ] \
        || ! grep -Eqs "^[[:space:]]*[@#]includedir[[:space:]]+${FBSD15_SUDOERS_DIR}" "$FBSD15_SUDOERS"; then
        f="$FBSD15_SUDOERS"
        sec_audit_backup "$f"
    fi
    if ! sec_audit_ensure_line "$f" "$line"; then
        sec_audit_fail_note "cannot write ${f}"
        return
    fi
    chmod 440 "$f" 2>/dev/null
    chown root:wheel "$f" 2>/dev/null
    if sec_audit_have_bin visudo && ! visudo -cf "$FBSD15_SUDOERS" >/dev/null 2>&1; then
        sec_audit_fail_note "visudo rejected ${f}"
        return
    fi
    sec_audit_note "${line} in ${f}"
}

sec_audit_sudoers_flag() { sec_audit_sudoers_dropin "Defaults $1"; }

sec_audit_sudoers_edit() {
    local expr="$1" msg="$2" f
    if [ ! -f "$FBSD15_SUDOERS" ]; then
        sec_audit_skip_note "${FBSD15_SUDOERS} not present"
        return
    fi
    sec_audit_backup "$FBSD15_SUDOERS"
    sec_audit_sed_inplace "$FBSD15_SUDOERS" "$expr"
    for f in "$FBSD15_SUDOERS_DIR"/*; do
        [ -f "$f" ] || continue
        sec_audit_backup "$f"
        sec_audit_sed_inplace "$f" "$expr"
    done
    if sec_audit_have_bin visudo && ! visudo -cf "$FBSD15_SUDOERS" >/dev/null 2>&1; then
        cp -p "${FBSD15_SUDOERS}.secaudit.bak" "$FBSD15_SUDOERS" 2>/dev/null
        for f in "$FBSD15_SUDOERS_DIR"/*.secaudit.bak; do
            [ -f "$f" ] || continue
            cp -p "$f" "${f%.secaudit.bak}" 2>/dev/null
        done
        sec_audit_fail_note "sudoers syntax check failed, change reverted"
        return
    fi
    sec_audit_note "$msg"
}

sec_audit_newsyslog_modes() {
    local f="$FBSD15_NEWSYSLOG_CONF" line m out=()
    if [ ! -f "$f" ]; then
        sec_audit_skip_note "${f} not present"
        return
    fi
    sec_audit_backup "$f"
    while IFS= read -r line; do
        case "$line" in ''|\#*) out+=("$line"); continue ;; esac
        m=$(printf '%s\n' "$line" | awk '{print $2}')
        case "$m" in ''|*[!0-7]*) out+=("$line"); continue ;; esac
        if (( (8#${m} | 8#644) != 8#644 )); then
            line=$(printf '%s\n' "$line" | awk -v m="$m" '{ for (i = 1; i <= NF; i++) if ($i == m) { $i = "640"; break } } { print }')
        fi
        out+=("$line")
    done < "$f"
    printf '%s\n' "${out[@]}" > "$f"
    sec_audit_note "entries looser than 644 set to 640"
}

sec_audit_cron_allow() {
    local f="$1" deny="$2"
    [ -d "$(dirname "$f")" ] || mkdir -p "$(dirname "$f")" 2>/dev/null
    if ! sec_audit_ensure_line "$f" root; then
        sec_audit_fail_note "cannot write ${f}"
        return
    fi
    chmod 640 "$f" 2>/dev/null
    chown root:wheel "$f" 2>/dev/null
    if [ -n "$deny" ] && [ -e "$deny" ]; then
        mv "$deny" "${deny}.secaudit.bak" 2>/dev/null
    fi
    sec_audit_note "${f} lists only root, ${deny} absent"
}

sec_audit_umask_line() {
    local f="$1" val="$2"
    if grep -Esiq '^[[:space:]]*umask[[:space:]]+' "$f" 2>/dev/null; then
        sec_audit_note "umask already configured in ${f}"
        return
    fi
    if ! sec_audit_ensure_line "$f" "umask ${val}"; then
        sec_audit_fail_note "cannot write ${f}"
        return
    fi
    sec_audit_note "umask ${val} added to ${f}"
}

sec_audit_system_accounts() {
    local user uid shell changed=0
    while IFS=: read -r user _ uid _ _ _ shell; do
        [ -n "$user" ] || continue
        case "$user" in root|toor|uucp) continue ;; esac
        [ "$uid" -lt 1000 ] 2>/dev/null || continue
        case "$shell" in /usr/sbin/nologin|/sbin/nologin|/bin/false) continue ;; esac
        sec_audit_have_bin pw && pw usermod "$user" -s /usr/sbin/nologin >/dev/null 2>&1 && changed=$((changed + 1))
    done < /etc/passwd
    if [ $changed -gt 0 ]; then
        sec_audit_note "nologin shell set on ${changed} system account(s)"
    else
        sec_audit_note "system accounts already use a non-login shell"
    fi
}

sec_audit_ssh_host_keys() {
    local kind="$1" mode="$2" group="$3" f changed=0
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        chmod "$mode" "$f" 2>/dev/null
        chown root "$f" 2>/dev/null
        [ "$group" != "-" ] && chgrp "$group" "$f" 2>/dev/null
        changed=$((changed + 1))
    done < <(find /etc/ssh -type f -name "$kind" 2>/dev/null)
    if [ $changed -gt 0 ]; then
        sec_audit_note "mode=${mode} on ${changed} ${kind} file(s)"
    else
        sec_audit_skip_note "no ${kind} files under /etc/ssh"
    fi
}

sec_audit_audit_dir() { awk -F: '$1=="dir"{print $2; exit}' "$FBSD15_AUDIT_CONTROL" 2>/dev/null; }

sec_audit_audit_logs() {
    local mode="$1" owner="$2" group="$3" adir f changed=0
    adir=$(sec_audit_audit_dir)
    [ -n "$adir" ] || adir=/var/audit
    if [ ! -d "$adir" ]; then
        sec_audit_skip_note "${adir} not present"
        return
    fi
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        chmod "$mode" "$f" 2>/dev/null
        chown "${owner}:${group}" "$f" 2>/dev/null
        changed=$((changed + 1))
    done < <(find "$adir" -type f 2>/dev/null | head -n 500)
    if [ $changed -gt 0 ]; then
        sec_audit_note "${changed} audit log file(s) set to mode=${mode} ${owner}:${group}"
    else
        sec_audit_note "no audit log files to adjust in ${adir}"
    fi
}

sec_audit_local_homes() {
    local user uid home shell changed=0 missing=0
    while IFS=: read -r user _ uid _ _ _ home shell; do
        [ -n "$user" ] || continue
        [ "$uid" -ge 1000 ] 2>/dev/null || continue
        [ "$uid" -lt 65534 ] 2>/dev/null || continue
        case "$shell" in */nologin|/bin/false) continue ;; esac
        if [ ! -d "$home" ]; then
            missing=$((missing + 1))
            continue
        fi
        chown "$user" "$home" 2>/dev/null
        chmod 750 "$home" 2>/dev/null
        changed=$((changed + 1))
    done < /etc/passwd
    sec_audit_note "${changed} home directorie(s) owned by their user with mode 750; ${missing} missing home(s) need manual creation"
}

sec_audit_dotfiles() {
    local user home f base updated=0 renamed=0
    while IFS=: read -r user _ uid _ _ _ home shell; do
        [ -n "$user" ] || continue
        [ "$uid" -ge 1000 ] 2>/dev/null || continue
        [ "$uid" -lt 65534 ] 2>/dev/null || continue
        case "$shell" in */nologin|/bin/false) continue ;; esac
        [ -d "$home" ] || continue
        for f in .forward .rhost .rhosts .netrc; do
            [ -e "$home/$f" ] || continue
            mv "$home/$f" "$home/${f}.secaudit.bak" 2>/dev/null && renamed=$((renamed + 1))
        done
        for f in "$home"/.[!.]*; do
            [ -f "$f" ] || continue
            base=$(basename "$f")
            chown "$user" "$f" 2>/dev/null
            case "$base" in
                .sh_history|.history|.bash_history) chmod 600 "$f" 2>/dev/null ;;
                *) chmod 644 "$f" 2>/dev/null ;;
            esac
            updated=$((updated + 1))
        done
    done < /etc/passwd
    sec_audit_note "${updated} dot file(s) normalized, ${renamed} legacy trust file(s) renamed"
}

sec_audit_rule_1() { sec_audit_kld_disable ext2fs; }
sec_audit_rule_2() { sec_audit_kld_disable msdosfs; }
sec_audit_rule_3() {
    sec_audit_manual "zfs may carry the root filesystem; drop zfs support only after confirming no pooled storage is in use"
}

sec_audit_pkgbase_state() {
    if grep -hs -A6 'FreeBSD-base' /etc/pkg/FreeBSD.conf /usr/local/etc/pkg/repos/*.conf 2>/dev/null \
        | grep -Eqi 'enabled[[:space:]]*[:=][[:space:]]*"?yes'; then
        return 0
    fi
    sec_audit_have_bin pkg || return 1
    [ -n "$(pkg query -g %n 'FreeBSD-base*' 2>/dev/null)$(pkg query -g %n 'FreeBSD-set-*' 2>/dev/null)" ]
}

sec_audit_pkg_remove_glob() {
    local pattern name found=()
    if ! sec_audit_have_bin pkg; then
        sec_audit_fail_note "pkg not available"
        return
    fi
    for pattern in "$@"; do
        while IFS= read -r name; do
            [ -n "$name" ] && found+=("$name")
        done < <(pkg query -g %n "$pattern" 2>/dev/null)
    done
    if [ ${#found[@]} -eq 0 ]; then
        sec_audit_note "no matching packages installed: $*"
        return
    fi
    if pkg remove -y "${found[@]}" >/dev/null 2>&1; then
        sec_audit_note "removed: ${found[*]}"
    else
        sec_audit_fail_note "could not remove: ${found[*]}"
    fi
}

sec_audit_audit_expire_after() {
    local f="$FBSD15_AUDIT_CONTROL" ea
    if [ ! -f "$f" ]; then
        sec_audit_skip_note "${f} not present"
        return
    fi
    ea=$(awk -F: '$1=="expire-after"{gsub(/[ \t]/,"",$2); print $2; exit}' "$f" 2>/dev/null)
    if [ -z "$ea" ]; then
        sec_audit_note "expire-after is not set, audit logs are not removed automatically"
        return
    fi
    if [ "$ea" = "0" ]; then
        sec_audit_note "expire-after=0, audit logs are not removed automatically"
        return
    fi
    sec_audit_backup "$f"
    sec_audit_sed_inplace "$f" 's|^expire-after:.*|expire-after:0|'
    sec_audit_audit_reload
    sec_audit_note "expire-after changed from ${ea} to 0"
}

sec_audit_umask_secure() {
    local anchor="$1" f v found=0 changed=0
    shift
    for f in "$@"; do
        [ -e "$f" ] || continue
        v=$(grep -Eoi 'umask[[:space:]=]+[0-7][0-7][0-7][0-7]?' "$f" 2>/dev/null | tail -n1 | grep -Eo '[0-7][0-7][0-7][0-7]?')
        [ -n "$v" ] || continue
        found=1
        if (( (8#${v} & 8#022) != 8#022 )); then
            changed=1
        fi
    done
    for f in "$@"; do
        [ -e "$f" ] || continue
        grep -Eq 'umask[[:space:]=]+[0-7][0-7][0-7][0-7]?' "$f" 2>/dev/null || continue
        sec_audit_backup "$f"
        sec_audit_sed_inplace "$f" 's/(umask[[:space:]=]+)[0-7][0-7][0-7][0-7]?/\1027/'
        if [ "$f" = "$FBSD15_LOGIN_CONF" ] && sec_audit_have_bin cap_mkdb; then
            cap_mkdb "$f" >/dev/null 2>&1
        fi
    done
    if [ $found -eq 0 ]; then
        if sec_audit_ensure_line "$anchor" "umask 027"; then
            sec_audit_note "umask 027 added to ${anchor}"
        else
            sec_audit_fail_note "cannot write ${anchor}"
        fi
    elif [ $changed -eq 1 ]; then
        sec_audit_note "permissive umask values replaced with 027"
    else
        sec_audit_note "existing umask already denies group and other write"
    fi
}

sec_audit_main() {
    sec_audit_log "starting remediation (FreeBSD 15 / sec_audit_* style)"

    sec_audit_rule_start; sec_audit_rule_1; sec_audit_rule_end 1
    sec_audit_rule_start; sec_audit_rule_2; sec_audit_rule_end 2
    sec_audit_rule_start; sec_audit_rule_3; sec_audit_rule_end 3
    sec_audit_rule_start; sec_audit_manual "create a dedicated /tmp mount, or set tmpmfs=YES in /etc/rc.conf"; sec_audit_rule_end 4
    sec_audit_rule_start; sec_audit_fstab_option /tmp nosuid; sec_audit_rule_end 5
    sec_audit_rule_start; sec_audit_fstab_option /tmp noexec; sec_audit_rule_end 6
    sec_audit_rule_start; sec_audit_manual "create a dedicated /home mount in /etc/fstab"; sec_audit_rule_end 7
    sec_audit_rule_start; sec_audit_fstab_option /home nosuid; sec_audit_rule_end 8
    sec_audit_rule_start; sec_audit_manual "create a dedicated /var mount in /etc/fstab"; sec_audit_rule_end 9
    sec_audit_rule_start; sec_audit_fstab_option /var nosuid; sec_audit_rule_end 10
    sec_audit_rule_start; sec_audit_manual "create a dedicated /var/tmp mount in /etc/fstab"; sec_audit_rule_end 11
    sec_audit_rule_start; sec_audit_fstab_option /var/tmp nosuid; sec_audit_rule_end 12
    sec_audit_rule_start; sec_audit_fstab_option /var/tmp noexec; sec_audit_rule_end 13
    sec_audit_rule_start; sec_audit_manual "create a dedicated /var/log mount in /etc/fstab"; sec_audit_rule_end 14
    sec_audit_rule_start; sec_audit_fstab_option /var/log nosuid; sec_audit_rule_end 15
    sec_audit_rule_start; sec_audit_fstab_option /var/log noexec; sec_audit_rule_end 16
    sec_audit_rule_start; sec_audit_manual "create a dedicated /var/audit mount in /etc/fstab"; sec_audit_rule_end 17
    sec_audit_rule_start; sec_audit_fstab_option /var/audit nosuid; sec_audit_rule_end 18
    sec_audit_rule_start; sec_audit_fstab_option /var/audit noexec; sec_audit_rule_end 19

    sec_audit_rule_start; sec_audit_manual "verify freebsd-update and pkg trust anchors against the vendor-signed fingerprints"; sec_audit_rule_end 20
    sec_audit_rule_start; sec_audit_manual "configure pkg repositories in /usr/local/etc/pkg/repos/*.conf for the site mirror"; sec_audit_rule_end 21
    sec_audit_rule_start
    if [ "$FBSD15_REMEDIATE_UPDATES" = "1" ]; then
        if sec_audit_pkgbase_state; then
            if sec_audit_have_bin pkg && pkg upgrade -y >/dev/null 2>&1; then
                sec_audit_note "pkg upgrade executed for the pkgbase system"
            else
                sec_audit_fail_note "pkg upgrade failed on the pkgbase system"
            fi
        elif sec_audit_have_bin freebsd-update; then
            freebsd-update fetch install >/dev/null 2>&1
            sec_audit_have_bin pkg && pkg upgrade -y >/dev/null 2>&1
            sec_audit_note "freebsd-update and pkg upgrades executed"
        else
            sec_audit_fail_note "neither freebsd-update nor pkg is available"
        fi
    else
        sec_audit_skip_note "set FBSD15_REMEDIATE_UPDATES=1 to install pending base-system and package updates"
    fi
    sec_audit_rule_end 22
    sec_audit_rule_start; sec_audit_manual "set a bootloader password interactively; the password is site-specific"; sec_audit_rule_end 23
    sec_audit_rule_start; sec_audit_file_perms 600 root wheel /boot/loader.conf /boot/loader.conf.local; sec_audit_rule_end 24
    sec_audit_rule_start; sec_audit_sysctl kern.elf64.aslr.enable 1; sec_audit_rule_end 25
    sec_audit_rule_start; sec_audit_sysrc savecore_enable NO; sec_audit_rule_end 26
    sec_audit_rule_start; sec_audit_sysrc dumpdev NO; sec_audit_rule_end 27
    sec_audit_rule_start; sec_audit_banner_file /etc/motd; sec_audit_rule_end 28
    sec_audit_rule_start; sec_audit_banner_file /etc/issue; sec_audit_rule_end 29
    sec_audit_rule_start; sec_audit_banner_file /etc/issue.net; sec_audit_rule_end 30
    sec_audit_rule_start; sec_audit_file_perms 644 root wheel /etc/motd; sec_audit_rule_end 31
    sec_audit_rule_start; sec_audit_file_perms 644 root wheel /etc/issue; sec_audit_rule_end 32

    sec_audit_rule_start
    if sec_audit_have_bin sysrc && sysrc ntpd_enable=YES >/dev/null 2>&1; then
        service ntpd start >/dev/null 2>&1
        sec_audit_note "ntpd_enable=YES, ntpd started"
    else
        sec_audit_fail_note "could not enable ntpd"
    fi
    sec_audit_rule_end 33
    sec_audit_rule_start; sec_audit_disable_service autofs; sec_audit_rule_end 34
    sec_audit_rule_start; sec_audit_inetd_disable ftp; sec_audit_pkg_remove vsftpd; sec_audit_rule_end 35
    sec_audit_rule_start; sec_audit_pkg_remove dovecot cyrus-imapd; sec_audit_disable_service dovecot; sec_audit_rule_end 36
    sec_audit_rule_start; sec_audit_disable_service nfs; sec_audit_rule_end 37
    sec_audit_rule_start; sec_audit_disable_service nis; sec_audit_rule_end 38
    sec_audit_rule_start; sec_audit_disable_service rpcbind; sec_audit_rule_end 39
    sec_audit_rule_start; sec_audit_pkg_remove net-snmp; sec_audit_disable_service snmpd; sec_audit_rule_end 40
    sec_audit_rule_start; sec_audit_inetd_disable telnet; sec_audit_pkg_remove freebsd-telnetd; sec_audit_rule_end 41
    sec_audit_rule_start; sec_audit_inetd_disable tftp; sec_audit_rule_end 42
    sec_audit_rule_start; sec_audit_pkg_remove squid; sec_audit_disable_service squid; sec_audit_rule_end 43
    sec_audit_rule_start; sec_audit_manual "reconfigure the MTA to listen on loopback only (for example inet_interfaces = loopback-only)"; sec_audit_rule_end 44
    sec_audit_rule_start; sec_audit_manual "review the listening-service inventory and stop anything not approved by site policy"; sec_audit_rule_end 45
    sec_audit_rule_start; sec_audit_manual "informational check: record whether IPv6 is enabled for this host"; sec_audit_rule_end 46

    sec_audit_rule_start; sec_audit_kld_disable sctp; sec_audit_rule_end 47
    sec_audit_rule_start; sec_audit_sysctl net.inet.ip.forwarding 0; sec_audit_sysctl net.inet6.ip6.forwarding 0; sec_audit_rule_end 48
    sec_audit_rule_start; sec_audit_sysctl net.inet.ip.redirect 0; sec_audit_sysctl net.inet6.ip6.redirect 0; sec_audit_rule_end 49
    sec_audit_rule_start; sec_audit_sysctl net.inet.icmp.bmcastecho 0; sec_audit_sysctl net.inet.icmp.tstamprepl 0; sec_audit_rule_end 50
    sec_audit_rule_start; sec_audit_sysctl net.inet.icmp.drop_redirect 1; sec_audit_sysctl net.inet6.icmp6.rediraccept 0; sec_audit_rule_end 51
    sec_audit_rule_start; sec_audit_sysctl net.inet.ip.accept_sourceroute 0; sec_audit_rule_end 52
    sec_audit_rule_start; sec_audit_sysctl net.inet.tcp.syncookies 1; sec_audit_rule_end 53
    sec_audit_rule_start; sec_audit_sysctl net.inet6.ip6.accept_rtadv 0; sec_audit_rule_end 54
    sec_audit_rule_start; sec_audit_manual "enabling ipfw without a reviewed rule set can lock out the host; load the site rule set first"; sec_audit_rule_end 55
    sec_audit_rule_start; sec_audit_manual "keep exactly one of firewall_enable, ipfilter_enable and pf_enable per site design"; sec_audit_rule_end 56

    sec_audit_rule_start; sec_audit_file_perms 600 root wheel /etc/crontab; sec_audit_rule_end 57
    sec_audit_rule_start; sec_audit_file_perms 700 root wheel /etc/cron.d; sec_audit_rule_end 58
    sec_audit_rule_start; sec_audit_cron_allow /var/cron/allow /var/cron/deny; sec_audit_rule_end 59
    sec_audit_rule_start; sec_audit_cron_allow /var/at/at.allow /var/at/at.deny; sec_audit_rule_end 60

    sec_audit_rule_start; sec_audit_file_perms 600 root wheel /etc/ssh/sshd_config; sec_audit_rule_end 61
    sec_audit_rule_start; sec_audit_ssh_host_keys 'ssh_host_*_key' 600 -; sec_audit_rule_end 62
    sec_audit_rule_start; sec_audit_ssh_host_keys 'ssh_host_*_key.pub' 644 wheel; sec_audit_rule_end 63
    sec_audit_rule_start; sec_audit_manual "define AllowUsers, AllowGroups, DenyUsers or DenyGroups for the site account policy"; sec_audit_rule_end 64
    sec_audit_rule_start; sec_audit_sshd_set Banner "$FBSD15_SSH_BANNER"; sec_audit_rule_end 65
    sec_audit_rule_start; sec_audit_sshd_set Ciphers "$FBSD15_SSHD_CIPHERS"; sec_audit_rule_end 66
    sec_audit_rule_start; sec_audit_sshd_set ClientAliveInterval 300; sec_audit_sshd_set ClientAliveCountMax 3; sec_audit_rule_end 67
    sec_audit_rule_start; sec_audit_sshd_set DisableForwarding yes; sec_audit_rule_end 68
    sec_audit_rule_start; sec_audit_sshd_set HostbasedAuthentication no; sec_audit_rule_end 69
    sec_audit_rule_start; sec_audit_sshd_set IgnoreRhosts yes; sec_audit_rule_end 70
    sec_audit_rule_start; sec_audit_sshd_set KexAlgorithms "$FBSD15_SSHD_KEX"; sec_audit_rule_end 71
    sec_audit_rule_start; sec_audit_sshd_set LoginGraceTime 60; sec_audit_rule_end 72
    sec_audit_rule_start; sec_audit_sshd_set LogLevel INFO; sec_audit_rule_end 73
    sec_audit_rule_start; sec_audit_sshd_set MACs "$FBSD15_SSHD_MACS"; sec_audit_rule_end 74
    sec_audit_rule_start; sec_audit_sshd_set MaxAuthTries 4; sec_audit_rule_end 75
    sec_audit_rule_start; sec_audit_sshd_set MaxSessions 10; sec_audit_rule_end 76
    sec_audit_rule_start; sec_audit_sshd_set MaxStartups 10:30:60; sec_audit_rule_end 77
    sec_audit_rule_start; sec_audit_sshd_set PermitEmptyPasswords no; sec_audit_rule_end 78
    sec_audit_rule_start; sec_audit_sshd_set PermitRootLogin no; sec_audit_rule_end 79
    sec_audit_rule_start; sec_audit_sshd_set PermitUserEnvironment no; sec_audit_rule_end 80
    sec_audit_rule_start; sec_audit_sshd_set UsePAM yes; sec_audit_rule_end 81

    sec_audit_rule_start; sec_audit_pkg_install sudo; sec_audit_rule_end 82
    sec_audit_rule_start; sec_audit_sudoers_flag use_pty; sec_audit_rule_end 83
    sec_audit_rule_start
    sec_audit_sudoers_flag "logfile=/var/log/sudo.log"
    touch /var/log/sudo.log 2>/dev/null
    chmod 600 /var/log/sudo.log 2>/dev/null
    chown root:wheel /var/log/sudo.log 2>/dev/null
    sec_audit_rule_end 84
    sec_audit_rule_start; sec_audit_sudoers_edit 's/NOPASSWD/PASSWD/g' "NOPASSWD replaced with PASSWD"; sec_audit_rule_end 85
    sec_audit_rule_start; sec_audit_sudoers_edit 's/!authenticate/authenticate/g' "!authenticate removed"; sec_audit_rule_end 86
    sec_audit_rule_start; sec_audit_sudoers_flag "timestamp_timeout=5"; sec_audit_rule_end 87
    sec_audit_rule_start; sec_audit_pam_option pam_group.so 'group=wheel'; sec_audit_rule_end 88
    sec_audit_rule_start
    for f in /etc/pam.d/*; do
        [ -f "$f" ] || continue
        grep -qF 'pam_passwdqc.so' "$f" 2>/dev/null || continue
        sec_audit_backup "$f"
        sec_audit_sed_inplace "$f" 's/[[:space:]]+minlen=[^[:space:]]+//g'
    done
    sec_audit_pam_setv pam_passwdqc.so min 14
    sec_audit_rule_end 89
    sec_audit_rule_start; sec_audit_pam_setv pam_passwdqc.so enforce everyone; sec_audit_rule_end 90
    sec_audit_rule_start; sec_audit_pam_unix_no_nullok; sec_audit_rule_end 91

    sec_audit_rule_start; sec_audit_login_conf passwd_format sha512; sec_audit_rule_end 92
    sec_audit_rule_start; sec_audit_login_conf passwordtime 365d; sec_audit_rule_end 93
    sec_audit_rule_start; sec_audit_login_conf warnpassword 7d; sec_audit_rule_end 94
    sec_audit_rule_start
    if sec_audit_have_bin pw && pw usermod root -g wheel >/dev/null 2>&1; then
        sec_audit_note "root primary group set to wheel (GID 0)"
    else
        sec_audit_fail_note "could not set the root account group"
    fi
    sec_audit_rule_end 95
    sec_audit_rule_start; sec_audit_umask_secure /root/.profile /root/.profile /root/.shrc /root/.cshrc /root/.login /etc/csh.cshrc /etc/profile; sec_audit_rule_end 96
    sec_audit_rule_start; sec_audit_system_accounts; sec_audit_rule_end 97
    sec_audit_rule_start
    if [ -f /etc/shells ] && grep -Eq '/nologin\b' /etc/shells 2>/dev/null; then
        sec_audit_backup /etc/shells
        sec_audit_sed_inplace /etc/shells '/\/nologin$/d'
        sec_audit_note "nologin removed from /etc/shells"
    else
        sec_audit_note "/etc/shells does not list nologin"
    fi
    sec_audit_rule_end 98
    sec_audit_rule_start; sec_audit_umask_secure /etc/profile /etc/login.conf /etc/profile /etc/csh.cshrc /etc/profile.d/*.sh; sec_audit_rule_end 99

    sec_audit_rule_start; sec_audit_sysrc syslogd_enable YES; sec_audit_rule_end 100
    sec_audit_rule_start
    if sec_audit_have_bin sysrc && sysrc syslogd_enable=YES >/dev/null 2>&1; then
        service syslogd start >/dev/null 2>&1
        sec_audit_note "syslogd_enable=YES, syslogd started"
    else
        sec_audit_fail_note "could not enable syslogd"
    fi
    sec_audit_rule_end 101
    sec_audit_rule_start; sec_audit_newsyslog_modes; sec_audit_rule_end 102
    sec_audit_rule_start
    if [ -f /etc/syslog.conf ] || ls /etc/syslog.d/*.conf >/dev/null 2>&1; then
        mkdir -p /var/log 2>/dev/null
        chmod 755 /var/log 2>/dev/null
        sec_audit_note "syslog configuration present, /var/log available"
    else
        sec_audit_skip_note "no syslog configuration found; restore the base /etc/syslog.conf"
    fi
    sec_audit_rule_end 103
    sec_audit_rule_start; sec_audit_manual "add an *.* @loghost entry to /etc/syslog.conf for the site log collector"; sec_audit_rule_end 104
    sec_audit_rule_start; sec_audit_sysrc syslogd_flags '-s'; sec_audit_rule_end 105
    sec_audit_rule_start
    if [ -f "$FBSD15_NEWSYSLOG_CONF" ]; then
        sec_audit_note "${FBSD15_NEWSYSLOG_CONF} present"
    else
        sec_audit_skip_note "${FBSD15_NEWSYSLOG_CONF} missing; restore the base newsyslog configuration"
    fi
    sec_audit_rule_end 106
    sec_audit_rule_start; sec_audit_file_perms 640 root wheel /var/log/messages /var/log/cron /var/log/auth.log /var/log/maillog; sec_audit_rule_end 107

    sec_audit_rule_start; sec_audit_sysrc auditd_enable YES; sec_audit_rule_end 108
    sec_audit_rule_start
    if [ -f "$FBSD15_AUDIT_CONTROL" ]; then
        sec_audit_backup "$FBSD15_AUDIT_CONTROL"
        grep -Eq '^filesz:' "$FBSD15_AUDIT_CONTROL" || printf 'filesz:20M\n' >> "$FBSD15_AUDIT_CONTROL"
        sec_audit_audit_reload
        sec_audit_note "filesz:20M in ${FBSD15_AUDIT_CONTROL}"
    else
        sec_audit_skip_note "${FBSD15_AUDIT_CONTROL} not present"
    fi
    sec_audit_rule_end 109
    sec_audit_rule_start; sec_audit_audit_expire_after; sec_audit_rule_end 110
    sec_audit_rule_start; sec_audit_audit_flag aa; sec_audit_rule_end 111
    sec_audit_rule_start
    sec_audit_audit_flag fa; sec_audit_audit_flag fc; sec_audit_audit_flag fd
    sec_audit_audit_flag fm; sec_audit_audit_flag fr; sec_audit_audit_flag fw
    sec_audit_rule_end 112
    sec_audit_rule_start; sec_audit_audit_flag pc; sec_audit_rule_end 113
    sec_audit_rule_start; sec_audit_audit_flag fm; sec_audit_audit_flag fa; sec_audit_rule_end 114
    sec_audit_rule_start; sec_audit_audit_flag ad; sec_audit_rule_end 115
    sec_audit_rule_start; sec_audit_audit_flag lo; sec_audit_rule_end 116
    sec_audit_rule_start; sec_audit_audit_flag fd; sec_audit_rule_end 117
    sec_audit_rule_start; sec_audit_audit_flag aa; sec_audit_audit_flag ad; sec_audit_rule_end 118
    sec_audit_rule_start
    adir=$(sec_audit_audit_dir)
    [ -n "$adir" ] || adir=/var/audit
    if [ -d "$adir" ]; then
        chmod 750 "$adir" 2>/dev/null
        chown root:wheel "$adir" 2>/dev/null
        sec_audit_note "${adir} mode=750 root:wheel"
    else
        sec_audit_skip_note "${adir} not present"
    fi
    sec_audit_rule_end 119
    sec_audit_rule_start; sec_audit_audit_logs 640 root wheel; sec_audit_rule_end 120
    sec_audit_rule_start; sec_audit_audit_logs 640 root wheel; sec_audit_rule_end 121
    sec_audit_rule_start; sec_audit_audit_logs 640 root wheel; sec_audit_rule_end 122
    sec_audit_rule_start; sec_audit_file_perms 600 root wheel /etc/security/audit_control /etc/security/audit_user; sec_audit_rule_end 123
    sec_audit_rule_start; sec_audit_file_perms 444 root wheel /etc/security/audit_event /etc/security/audit_class; sec_audit_rule_end 124
    sec_audit_rule_start; sec_audit_file_perms 444 root wheel /etc/security/audit_event /etc/security/audit_class; sec_audit_rule_end 125
    sec_audit_rule_start; sec_audit_file_perms 555 root wheel /usr/sbin/audit /usr/sbin/auditd /usr/sbin/auditreduce /usr/sbin/praudit; sec_audit_rule_end 126
    sec_audit_rule_start; sec_audit_file_perms 555 root wheel /usr/sbin/audit /usr/sbin/auditd /usr/sbin/auditreduce /usr/sbin/praudit; sec_audit_rule_end 127
    sec_audit_rule_start; sec_audit_file_perms 555 root wheel /usr/sbin/audit /usr/sbin/auditd /usr/sbin/auditreduce /usr/sbin/praudit; sec_audit_rule_end 128

    sec_audit_rule_start; sec_audit_pkg_install aide; sec_audit_rule_end 129
    sec_audit_rule_start
    if [ -d /etc/cron.d ]; then
        sec_audit_ensure_line /etc/cron.d/aide '0 5 * * * root /usr/local/bin/aide --check -q'
        chmod 644 /etc/cron.d/aide 2>/dev/null
        chown root:wheel /etc/cron.d/aide 2>/dev/null
        sec_audit_note "daily AIDE check in /etc/cron.d/aide"
    else
        sec_audit_skip_note "/etc/cron.d not present; schedule the AIDE check manually"
    fi
    sec_audit_rule_end 130

    sec_audit_rule_start; sec_audit_file_perms 644 root wheel /etc/passwd; sec_audit_rule_end 131
    sec_audit_rule_start; sec_audit_file_perms 644 root wheel /etc/group; sec_audit_rule_end 132
    sec_audit_rule_start; sec_audit_file_perms 600 root wheel /etc/master.passwd; sec_audit_rule_end 133
    sec_audit_rule_start; sec_audit_file_perms 644 root wheel /etc/shells; sec_audit_rule_end 134
    sec_audit_rule_start; sec_audit_manual "review the world-writable inventory; bulk mode changes can break applications"; sec_audit_rule_end 135
    sec_audit_rule_start; sec_audit_manual "review unowned and ungrouped paths and reassign them explicitly"; sec_audit_rule_end 136
    sec_audit_rule_start; sec_audit_manual "review the SUID/SGID inventory against site policy"; sec_audit_rule_end 137

    sec_audit_rule_start
    if sec_audit_have_bin pwd_mkdb && [ -f /etc/master.passwd ]; then
        pwd_mkdb -p /etc/master.passwd >/dev/null 2>&1
        sec_audit_note "/etc/passwd rebuilt from /etc/master.passwd"
    else
        sec_audit_fail_note "pwd_mkdb not available"
    fi
    sec_audit_rule_end 138
    sec_audit_rule_start
    locked=0
    if sec_audit_have_bin pw; then
        while IFS= read -r user; do
            [ -n "$user" ] || continue
            pw lock "$user" >/dev/null 2>&1 && locked=$((locked + 1))
        done < <(awk -F: '($2 == ""){print $1}' /etc/master.passwd 2>/dev/null)
        sec_audit_note "empty-password account(s) locked: ${locked}"
    else
        sec_audit_fail_note "pw not available"
    fi
    sec_audit_rule_end 139
    sec_audit_rule_start; sec_audit_manual "create the /etc/group entries named in /etc/passwd after confirming the intended names"; sec_audit_rule_end 140
    sec_audit_rule_start; sec_audit_manual "resolve duplicate UIDs by hand; merging accounts is not safe to automate"; sec_audit_rule_end 141
    sec_audit_rule_start; sec_audit_manual "resolve duplicate GIDs by hand; merging groups is not safe to automate"; sec_audit_rule_end 142
    sec_audit_rule_start; sec_audit_manual "resolve duplicate user names by hand"; sec_audit_rule_end 143
    sec_audit_rule_start; sec_audit_manual "resolve duplicate group names by hand"; sec_audit_rule_end 144
    sec_audit_rule_start; sec_audit_manual "fix the root PATH in the root shell start-up files per site layout"; sec_audit_rule_end 145
    sec_audit_rule_start; sec_audit_manual "keep UID 0 for root only; decide on the optional toor account per site policy"; sec_audit_rule_end 146
    sec_audit_rule_start; sec_audit_local_homes; sec_audit_rule_end 147
    sec_audit_rule_start; sec_audit_dotfiles; sec_audit_rule_end 148

    sec_audit_rule_start
    if sec_audit_pkgbase_state; then
        if sec_audit_have_bin freebsd-update; then
            if sec_audit_have_bin pkg && pkg remove -y freebsd-update >/dev/null 2>&1; then
                sec_audit_note "pkgbase detected, freebsd-update package removed"
            else
                sec_audit_fail_note "pkgbase detected, remove the freebsd-update package so base is managed by pkg"
            fi
        else
            sec_audit_note "pkgbase detected and freebsd-update absent"
        fi
    else
        sec_audit_note "distribution-set installation, base is not managed by pkg"
    fi
    sec_audit_rule_end 149
    sec_audit_rule_start; sec_audit_manual "enable signature_type pubkey or fingerprints with trusted keys for every enabled repository"; sec_audit_rule_end 150
    sec_audit_rule_start
    dsa_moved=0
    for f in /etc/ssh/ssh_host_dsa_key /etc/ssh/ssh_host_dsa_key.pub; do
        [ -e "$f" ] || continue
        mv "$f" "${f}.secaudit.bak" 2>/dev/null && dsa_moved=$((dsa_moved + 1))
    done
    if grep -Eqi '^[[:space:]]*HostKey[[:space:]].*ssh_host_dsa_key' "$FBSD15_SSHD_CONFIG" 2>/dev/null; then
        sec_audit_backup "$FBSD15_SSHD_CONFIG"
        sec_audit_sed_inplace "$FBSD15_SSHD_CONFIG" '/ssh_host_dsa_key/d'
        dsa_moved=$((dsa_moved + 1))
    fi
    if [ $dsa_moved -gt 0 ]; then
        service sshd reload >/dev/null 2>&1
        sec_audit_note "DSA host keys and HostKey entries removed"
    else
        sec_audit_note "no DSA host keys present"
    fi
    sec_audit_rule_end 151
    sec_audit_rule_start
    sec_audit_sshd_set Ciphers "$FBSD15_SSHD_CIPHERS"
    sec_audit_sshd_set KexAlgorithms "$FBSD15_SSHD_KEX"
    sec_audit_sshd_set HostKeyAlgorithms "$FBSD15_SSHD_HOSTKEY"
    sec_audit_sshd_set PubkeyAcceptedAlgorithms "$FBSD15_SSHD_PUBKEY"
    sec_audit_rule_end 152
    sec_audit_rule_start; sec_audit_pkg_remove_glob 'freebsd-ftpd*' 'vsftpd*' 'proftpd*' 'pure-ftpd*'; sec_audit_rule_end 153
    sec_audit_rule_start
    sec_audit_pkg_remove_glob 'freebsd-shar*'
    if sec_audit_have_bin shar; then
        shar_path=$(command -v shar)
        if mv "$shar_path" "${shar_path}.secaudit.bak" 2>/dev/null; then
            sec_audit_note "shar moved to ${shar_path}.secaudit.bak"
        else
            sec_audit_fail_note "shar remains at ${shar_path}"
        fi
    else
        sec_audit_note "shar is absent"
    fi
    sec_audit_rule_end 154
    sec_audit_rule_start
    vty=$(sysctl -n kern.vty 2>/dev/null)
    case "$vty" in
        sc|"")
            sec_audit_set_kv "$FBSD15_LOADER_CONF" kern.vty '"vt"'
            sec_audit_note "kern.vty=\"vt\" in ${FBSD15_LOADER_CONF}, reboot required"
            ;;
        *)
            sec_audit_note "console driver ${vty}"
            ;;
    esac
    sec_audit_rule_end 155
    sec_audit_rule_start; sec_audit_manual "upgrade the base system to OpenSSL 3.5 or newer and reboot"; sec_audit_rule_end 156
    sec_audit_rule_start
    pk_moved=0
    for f in /etc/publickey /var/yp/publickey; do
        [ -e "$f" ] || continue
        mv "$f" "${f}.secaudit.bak" 2>/dev/null && pk_moved=$((pk_moved + 1))
    done
    if [ $pk_moved -gt 0 ]; then
        sec_audit_note "legacy publickey database moved to .secaudit.bak"
    else
        sec_audit_note "legacy publickey database is absent"
    fi
    sec_audit_rule_end 157
    sec_audit_rule_start; sec_audit_manual "switch Kerberos to the MIT krb5 implementation and revalidate the KDC and client configuration"; sec_audit_rule_end 158
    sec_audit_rule_start
    sec_audit_file_perms 555 root wheel /usr/sbin/audit /usr/sbin/auditd /usr/sbin/auditdistd /usr/sbin/auditreduce /usr/sbin/praudit
    sec_audit_file_perms 600 root wheel /etc/security/audit_control /etc/security/audit_user
    sec_audit_file_perms 644 root wheel /etc/security/audit_warn
    sec_audit_file_perms 444 root wheel /etc/security/audit_event /etc/security/audit_class
    sec_audit_rule_end 159

    sec_audit_log "remediation complete (FreeBSD15_remediation.sh)"
    exit 0
}

sec_audit_main "$@"
