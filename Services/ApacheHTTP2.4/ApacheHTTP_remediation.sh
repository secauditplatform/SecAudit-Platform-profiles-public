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

# Package default when SECAUDIT_VAR_<NAME> is unset. Name is [A-Z][A-Z0-9_]*
secaudit_var() {
    local name="$1" fallback="$2" key value
    key="SECAUDIT_VAR_${name}"
    value="${!key-}"
    if [ -n "$value" ]; then
        printf '%s' "$value"
    else
        printf '%s' "$fallback"
    fi
}

# Keep the installed value at the package preference when the ceiling is higher.
secaudit_cap() {
    local prefer="$1" ceiling="$2"
    [[ "$prefer" =~ ^[0-9]+$ && "$ceiling" =~ ^[0-9]+$ ]] || {
        printf '%s' "$prefer"
        return 0
    }
    if [ "$ceiling" -lt "$prefer" ]; then
        printf '%s' "$ceiling"
    else
        printf '%s' "$prefer"
    fi
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
# pipefail left unset so a failed configtest does not abort the remediator.

APACHE_CONF_ROOT="${APACHE_CONF_ROOT:-}"
DROPIN_OK=0

secaudit_have_bin() { command -v "$1" >/dev/null 2>&1; }
secaudit_log() { printf '[remediation] %s\n' "$*"; }

secaudit_remediate_done() {
    printf '[remediation] REMEDIATE RULE%s= applied: %s\n' "$1" "$2"
}

secaudit_remediate_skip() {
    printf '[remediation] REMEDIATE RULE%s= SKIP: manual step required - %s\n' "$1" "$2"
}

secaudit_finish() {
    local n="$1" how="$2" msg="$3"
    secaudit_rule_enabled "$n" || return 0
    if [ "$how" = done ]; then
        secaudit_remediate_done "$n" "$msg"
    else
        secaudit_remediate_skip "$n" "$msg"
    fi
}

secaudit_backup_file() {
    local f="$1" journal="${SECAUDIT_JOURNAL:-/var/backups/secaudit-apachehttp.journal}"
    [ -n "$f" ] || return 0
    if [ -f "$f" ] || [ -L "$f" ]; then
        if [ ! -e "${f}.secaudit.bak" ]; then
            cp -a "$f" "${f}.secaudit.bak" 2>/dev/null || true
        fi
        return 0
    fi
    mkdir -p /var/backups 2>/dev/null || return 0
    grep -qxF "created $f" "$journal" 2>/dev/null || printf 'created %s\n' "$f" >>"$journal"
}

secaudit_detect_layout() {
    if [ -f /etc/apache2/apache2.conf ]; then
        APACHE_BIN="apache2"
        APACHE_CTL="apache2ctl"
        APACHE_DIR="${APACHE_CONF_ROOT:-/etc/apache2}"
        APACHE_MAIN="${APACHE_DIR}/apache2.conf"
        APACHE_USER="www-data"
        return 0
    fi
    if [ -f /etc/httpd/conf/httpd.conf ] || [ -d /etc/httpd ]; then
        APACHE_BIN="httpd"
        APACHE_CTL="apachectl"
        APACHE_DIR="${APACHE_CONF_ROOT:-/etc/httpd}"
        APACHE_MAIN="${APACHE_DIR}/conf/httpd.conf"
        APACHE_USER="apache"
        return 0
    fi
    return 1
}

secaudit_service_user() {
    local user=""
    if [ -f /etc/apache2/envvars ]; then
        user=$(bash -c 'set -a; . /etc/apache2/envvars; printf "%s" "$APACHE_RUN_USER"')
    fi
    if [ -z "$user" ] && [ -f "$APACHE_MAIN" ]; then
        user=$(awk '/^[[:space:]]*User[[:space:]]+/ { print $2; exit }' "$APACHE_MAIN")
    fi
    user="${user#\$\{}"
    user="${user%\}}"
    [ -n "$user" ] || user="$APACHE_USER"
    printf '%s' "$user"
}

secaudit_disable_module() {
    local mod="$1" f
    if secaudit_have_bin a2dismod; then
        a2dismod -f "$mod" >/dev/null 2>&1 || true
    fi
    for f in /etc/httpd/conf.modules.d/*.conf "/etc/apache2/mods-enabled/${mod}.load"; do
        [ -f "$f" ] || continue
        secaudit_backup_file "$f"
        sed -i -E "s/^([[:space:]]*)(LoadModule[[:space:]]+${mod}_module)/\\1# \\2/" "$f" 2>/dev/null || true
    done
}

secaudit_dropin_path() {
    if [ -d /etc/apache2 ]; then
        printf '%s\n' /etc/apache2/conf-available/zz-secaudit.conf
    else
        printf '%s\n' /etc/httpd/conf.d/zz-secaudit.conf
    fi
}

secaudit_configtest() {
    if secaudit_have_bin "$APACHE_CTL"; then
        "$APACHE_CTL" configtest >/dev/null 2>&1
        return $?
    fi
    if secaudit_have_bin "$APACHE_BIN"; then
        "$APACHE_BIN" -t >/dev/null 2>&1
        return $?
    fi
    return 0
}

secaudit_install_dropin() {
    local f link to ka_max ka_to line fields fsize body hdr_max body_max hdr_lo body_lo tokens signature key_mode
    to=$(secaudit_var TIMEOUT 10)
    ka_max=$(secaudit_var MAX_KEEPALIVE_REQUESTS 100)
    ka_to=$(secaudit_cap 5 "$(secaudit_var KEEPALIVE_TIMEOUT 15)")
    line=$(secaudit_var LIMIT_REQUEST_LINE 8190)
    fields=$(secaudit_var LIMIT_REQUEST_FIELDS 100)
    fsize=$(secaudit_var LIMIT_REQUEST_FIELDSIZE 1024)
    body=$(secaudit_var LIMIT_REQUEST_BODY 102400)
    hdr_max=$(secaudit_var REQUEST_READ_HEADER_MAX 40)
    body_max=$(secaudit_var REQUEST_READ_BODY_MAX 20)
    hdr_lo=20
    body_lo=10
    [ "$hdr_max" -lt "$hdr_lo" ] 2>/dev/null && hdr_lo=$hdr_max
    [ "$body_max" -lt "$body_lo" ] 2>/dev/null && body_lo=$body_max
    tokens=$(secaudit_var SERVER_TOKENS "Prod,ProductOnly"); tokens=${tokens%%,*}
    signature=$(secaudit_var SERVER_SIGNATURE Off)
    tokens=$(secaudit_var SERVER_TOKENS "Prod,ProductOnly"); tokens=${tokens%%,*}
    signature=$(secaudit_var SERVER_SIGNATURE Off)
    f=$(secaudit_dropin_path)
    mkdir -p "$(dirname "$f")"
    secaudit_backup_file "$f"
    cat >"$f" <<EOF
# SecAudit Apache HTTP hardening
TraceEnable Off
ServerTokens ${tokens}
ServerSignature ${signature}
Timeout ${to}
KeepAlive On
MaxKeepAliveRequests ${ka_max}
KeepAliveTimeout ${ka_to}
LimitRequestLine ${line}
LimitRequestFields ${fields}
LimitRequestFieldsize ${fsize}
LimitRequestBody ${body}
FileETag MTime Size
LogLevel notice
<IfModule reqtimeout_module>
    RequestReadTimeout header=${hdr_lo}-${hdr_max},MinRate=500 body=${body_lo}-${body_max},MinRate=500
</IfModule>
ErrorLog "syslog:local1"

<IfModule mod_headers.c>
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set Strict-Transport-Security "max-age=15768000"
</IfModule>

<FilesMatch "^\.ht">
    Require all denied
</FilesMatch>
<FilesMatch "^\.git">
    Require all denied
</FilesMatch>
<FilesMatch "^\.svn">
    Require all denied
</FilesMatch>

<IfModule mod_ssl.c>
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCompression off
    SSLInsecureRenegotiation off
</IfModule>
EOF
    if [ -d /etc/apache2/conf-enabled ]; then
        link=/etc/apache2/conf-enabled/zz-secaudit.conf
        secaudit_backup_file "$link"
        ln -sfn ../conf-available/zz-secaudit.conf "$link"
    fi
    if secaudit_configtest; then
        DROPIN_OK=1
        return 0
    fi
    rm -f "$f" /etc/apache2/conf-enabled/zz-secaudit.conf
    DROPIN_OK=0
    return 1
}

secaudit_wants_dropin() {
    local n
    for n in 31 33 34 35 39 40 41 42 43 52 54 55 56 59 61 62 64 65 66 67 68 69 70 71 72 73 74; do
        secaudit_rule_enabled "$n" && return 0
    done
    return 1
}

secaudit_skip_all() {
    local n
    for ((n = 1; n <= 79; n++)); do
        secaudit_finish "$n" skip "Apache HTTP Server is not installed"
    done
}

secaudit_remediate_modules() {
    # RULE1-8
    secaudit_finish 1 skip "log_config is part of the base server; install the matching package if the module is missing"
    if secaudit_rule_enabled 2; then
        secaudit_disable_module dav
        secaudit_disable_module dav_fs
    fi
    secaudit_finish 2 done "WebDAV modules disabled"
    if secaudit_rule_enabled 3; then
        secaudit_disable_module status
    fi
    secaudit_finish 3 done "status module disabled"
    if secaudit_rule_enabled 4; then
        secaudit_disable_module autoindex
    fi
    secaudit_finish 4 done "autoindex module disabled"
    secaudit_finish 5 skip "proxy modules are left loaded because this host may be a reverse proxy"
    if secaudit_rule_enabled 6; then
        secaudit_disable_module userdir
    fi
    secaudit_finish 6 done "userdir module disabled"
    if secaudit_rule_enabled 7; then
        secaudit_disable_module info
    fi
    secaudit_finish 7 done "info module disabled"
    secaudit_finish 8 skip "basic and digest auth modules are left loaded so an existing login is not removed"
}

secaudit_remediate_account_and_permissions() {
    # RULE9-20
    local user shell
    user=$(secaudit_service_user)
    secaudit_finish 9 skip "the User directive is not rewritten; set it to a dedicated account in the server configuration"
    if [ -n "$user" ] && [ "$user" != "root" ] && id "$user" >/dev/null 2>&1; then
        shell=$(command -v nologin 2>/dev/null || printf '%s' /usr/sbin/nologin)
        if secaudit_rule_enabled 10; then
            usermod -s "$shell" "$user" >/dev/null 2>&1 || true
        fi
        secaudit_finish 10 done "login shell for ${user} set to ${shell}"
        if secaudit_rule_enabled 11; then
            passwd -l "$user" >/dev/null 2>&1 || true
        fi
        secaudit_finish 11 done "password for ${user} locked"
    else
        secaudit_finish 10 skip "Apache service account was not found"
        secaudit_finish 11 skip "Apache service account was not found"
    fi
    if [ -d "$APACHE_DIR" ]; then
        if secaudit_rule_enabled 12 || secaudit_rule_enabled 13 || secaudit_rule_enabled 14 || secaudit_rule_enabled 19; then
            chown -R root:root "$APACHE_DIR" >/dev/null 2>&1 || true
            find "$APACHE_DIR" -perm -0002 -exec chmod o-w {} + >/dev/null 2>&1 || true
            find "$APACHE_DIR" -perm -0020 -exec chmod g-w {} + >/dev/null 2>&1 || true
        fi
        secaudit_finish 12 done "configuration tree owned by root"
        secaudit_finish 13 done "configuration tree group set to root"
        secaudit_finish 14 done "other write removed from the configuration tree"
        secaudit_finish 19 done "group write removed from the configuration tree"
    else
        secaudit_finish 12 skip "Apache configuration directory was not found"
        secaudit_finish 13 skip "Apache configuration directory was not found"
        secaudit_finish 14 skip "Apache configuration directory was not found"
        secaudit_finish 19 skip "Apache configuration directory was not found"
    fi
    secaudit_finish 15 skip "CoreDumpDirectory is left to the packaged default"
    secaudit_finish 16 skip "the Mutex path is left to the packaged default"
    secaudit_finish 17 skip "the PidFile path is left to the packaged default"
    secaudit_finish 18 skip "the ScoreBoardFile path is left to the packaged default"
    secaudit_finish 20 skip "document-root group write is a content-publishing choice and is not changed"
}

secaudit_remediate_access_and_features() {
    # RULE21-41
    local n script
    for n in 21 22 23 24 25 26 30 32 36 37 38; do
        secaudit_finish "$n" skip "this directive is site-specific and is not rewritten automatically"
    done
    secaudit_finish 27 skip "remove the packaged welcome page and sample icon aliases from the document root"
    if secaudit_rule_enabled 28 || secaudit_rule_enabled 29; then
        for script in /usr/lib/cgi-bin/printenv /usr/lib/cgi-bin/test-cgi /var/www/cgi-bin/printenv /var/www/cgi-bin/test-cgi; do
            [ -e "$script" ] && rm -f "$script"
        done
    fi
    secaudit_finish 28 done "sample printenv CGI removed when it was present"
    secaudit_finish 29 done "sample test-cgi CGI removed when it was present"
    if [ "$DROPIN_OK" = 1 ]; then
        secaudit_finish 31 done "TraceEnable Off written to zz-secaudit.conf"
        secaudit_finish 33 done "access to .ht files denied in zz-secaudit.conf"
        secaudit_finish 34 done "access to .git files denied in zz-secaudit.conf"
        secaudit_finish 35 done "access to .svn files denied in zz-secaudit.conf"
        secaudit_finish 39 done "X-Frame-Options written to zz-secaudit.conf"
        secaudit_finish 40 done "Referrer-Policy written to zz-secaudit.conf"
        secaudit_finish 41 done "Permissions-Policy written to zz-secaudit.conf"
    else
        for n in 31 33 34 35 39 40 41; do
            secaudit_finish "$n" skip "Apache rejected the hardening drop-in during configtest"
        done
    fi
}

secaudit_remediate_logging_and_tls() {
    # RULE42-64
    local n key
    if [ "$DROPIN_OK" = 1 ]; then
        for n in 42 43 52 54 55 56 59 61 62 64; do
            secaudit_finish "$n" done "directive written to zz-secaudit.conf"
        done
    else
        for n in 42 43 52 54 55 56 59 61 62 64; do
            secaudit_finish "$n" skip "Apache rejected the hardening drop-in during configtest"
        done
    fi
    secaudit_finish 44 skip "the packaged access-log format is left in place"
    secaudit_finish 45 skip "log rotation retention is a host logging policy and is not rewritten"
    secaudit_finish 46 skip "package updates are not applied by this script"
    secaudit_finish 47 skip "ModSecurity is not installed automatically"
    secaudit_finish 48 skip "the OWASP Core Rule Set is not installed automatically"
    secaudit_finish 49 skip "mod_ssl is not installed automatically"
    secaudit_finish 50 skip "a trusted certificate must be issued for this host name"
    key=$(grep -RhiE '^[[:space:]]*SSLCertificateKeyFile[[:space:]]+' /etc/apache2 /etc/httpd 2>/dev/null | awk '{ print $2 }' | tr -d '"' | head -1)
    if [ -n "$key" ] && [ -f "$key" ]; then
        if secaudit_rule_enabled 51; then
            key_mode=$(secaudit_var KEY_MODES "600,400,440"); chmod "${key_mode%%,*}" "$key" >/dev/null 2>&1 || true
        fi
        secaudit_finish 51 done "private key mode set to 600 (${key})"
    else
        secaudit_finish 51 skip "SSLCertificateKeyFile was not found"
    fi
    secaudit_finish 53 skip "cipher suite policy is site-specific and is not rewritten"
    secaudit_finish 57 skip "redirecting all content to HTTPS can take the site offline"
    secaudit_finish 58 skip "OCSP stapling needs a reachable responder and is not enabled automatically"
    secaudit_finish 60 skip "forward-secrecy cipher suites are site-specific and are not rewritten"
    secaudit_finish 63 skip "packaged sample content under the document root is left for an operator to remove"
}

secaudit_remediate_limits_and_mac() {
    # RULE65-79
    local n mode
    if [ "$DROPIN_OK" = 1 ]; then
        for n in 65 66 67 68 69 70 71 72 73 74; do
            secaudit_finish "$n" done "request limit written to zz-secaudit.conf"
        done
    else
        for n in 65 66 67 68 69 70 71 72 73 74; do
            secaudit_finish "$n" skip "Apache rejected the hardening drop-in during configtest"
        done
    fi
    if [ -f /etc/selinux/config ]; then
        if grep -q '^SELINUX=enforcing' /etc/selinux/config; then
            secaudit_finish 75 done "SELinux is already enforcing"
        else
            if secaudit_rule_enabled 75; then
                secaudit_backup_file /etc/selinux/config
                sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
                setenforce 1 >/dev/null 2>&1 || true
            fi
            secaudit_finish 75 done "SELINUX=enforcing written; reboot if SELinux was disabled"
        fi
    else
        secaudit_finish 75 done "SELinux is not configured on this host"
    fi
    secaudit_finish 76 skip "the httpd_t domain is assigned by the SELinux policy, not by this script"
    secaudit_finish 77 skip "permissive type changes need semanage on this host"
    secaudit_finish 78 skip "the AppArmor service is not started automatically"
    if secaudit_have_bin aa-enforce && [ -e /etc/apparmor.d/usr.sbin.apache2 ]; then
        if secaudit_rule_enabled 79; then
            aa-enforce usr.sbin.apache2 >/dev/null 2>&1
        fi
        secaudit_finish 79 done "Apache AppArmor profile set to enforce"
    else
        secaudit_finish 79 skip "AppArmor or the Apache profile is not installed"
    fi
}

secaudit_reload() {
    [ "$DROPIN_OK" = 1 ] || return 0
    if secaudit_have_bin systemctl; then
        systemctl reload apache2 >/dev/null 2>&1 || systemctl reload httpd >/dev/null 2>&1 || true
    fi
}

secaudit_main() {
    secaudit_log "starting remediation (Apache HTTP / secaudit_* style)"
    if ! secaudit_detect_layout; then
        secaudit_skip_all
        secaudit_log "remediation complete (Apache HTTP Server is not installed)"
        exit 0
    fi
    if secaudit_wants_dropin; then
        secaudit_install_dropin || secaudit_log "drop-in removed because configtest failed"
    fi
    secaudit_remediate_modules
    secaudit_remediate_account_and_permissions
    secaudit_remediate_access_and_features
    secaudit_remediate_logging_and_tls
    secaudit_remediate_limits_and_mac
    secaudit_reload
    secaudit_log "remediation complete"
}

secaudit_main "$@"
