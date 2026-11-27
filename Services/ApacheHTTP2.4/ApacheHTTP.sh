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

# Return 0 when $1 equals one comma-separated token of $2.
secaudit_in_csv() {
    local want="$1" list="$2" token
    local IFS=','
    for token in $list; do
        token="${token#"${token%%[![:space:]]*}"}"
        token="${token%"${token##*[![:space:]]}"}"
        [ "$want" = "$token" ] && return 0
    done
    return 1
}

if [ -z "${BASH_VERSION:-}" ]; then
    if command -v bash >/dev/null 2>&1; then
        exec bash "$0" "$@"
    fi
    printf '%s\n' "ERROR: bash is required." >&2
    exit 1
fi

set -o pipefail

export LC_ALL=C

APACHE_PREFIX="${APACHE_PREFIX:-}"
APACHE_CONF_ROOT="${APACHE_CONF_ROOT:-}"

secaudit_have_bin() { command -v "$1" >/dev/null 2>&1; }

secaudit_emit() {
	local n="$1" msg status detail
	shift
	msg="$*"
	secaudit_rule_enabled "$n" || return 0
	case "$msg" in
		PASS:*) status=PASS; detail="${msg#PASS: }" ;;
		FAIL:*) status=FAIL; detail="${msg#FAIL: }" ;;
		SKIP:*|N/A:*|NA:*) status=SKIP; detail="${msg#*: }" ;;
		ERROR:*) status=ERROR; detail="${msg#ERROR: }" ;;
		*) status=FAIL; detail="$msg" ;;
	esac
	printf 'RULE%s= %s: %s\n' "$n" "$status" "$detail"
}

secaudit_skip_all() {
	local last="$1" reason="$2" n
	for ((n = 1; n <= last; n++)); do
		secaudit_rule_enabled "$n" || continue
		printf 'RULE%s= SKIP: %s\n' "$n" "$reason"
	done
}

secaudit_detect_layout() {
    if [ -f /etc/apache2/apache2.conf ]; then
        APACHE_BIN="apache2"
        APACHE_CTL="apache2ctl"
        APACHE_SVC="apache2"
        APACHE_DIR="${APACHE_CONF_ROOT:-/etc/apache2}"
        APACHE_MAIN="${APACHE_DIR}/apache2.conf"
        APACHE_MODULES_DIR="${APACHE_DIR}/mods-enabled"
        APACHE_SITES_DIR="${APACHE_DIR}/sites-enabled"
        APACHE_LOGROTATE="/etc/logrotate.d/apache2"
        APACHE_RUN_DIR="/var/run/apache2"
        APACHE_USER="www-data"
        APACHE_GROUP="www-data"
        APACHE_WELCOME="/etc/apache2/conf-enabled/other-vhosts-access-log.conf /etc/apache2/conf-available/other-vhosts-access-log.conf"
        APACHE_CGI="/usr/lib/cgi-bin"
        APACHE_PKG_NAMES="apache2 apache2-bin libapache2-mod-security2"
        return 0
    fi
    APACHE_BIN="httpd"
    APACHE_CTL="apachectl"
    APACHE_SVC="httpd"
    APACHE_DIR="${APACHE_CONF_ROOT:-/etc/httpd}"
    APACHE_MAIN="${APACHE_DIR}/conf/httpd.conf"
    APACHE_MODULES_DIR="${APACHE_DIR}/conf.modules.d"
    APACHE_SITES_DIR="${APACHE_DIR}/conf.d"
    APACHE_LOGROTATE="/etc/logrotate.d/httpd"
    APACHE_RUN_DIR="/var/run/httpd"
    APACHE_USER="apache"
    APACHE_GROUP="apache"
    APACHE_WELCOME="/etc/httpd/conf.d/welcome.conf"
    APACHE_CGI="/var/www/cgi-bin"
    APACHE_PKG_NAMES="httpd mod_ssl mod_security"
}

secaudit_run() {
    # Prefer httpd/apache2 -M (RHEL); fall back to apachectl/apache2ctl (Debian env).
    if [ "$1" = "-M" ] && secaudit_have_bin "$APACHE_BIN"; then
        "$APACHE_BIN" "$@" 2>/dev/null && return 0
    fi
    if secaudit_have_bin "$APACHE_CTL"; then
        "$APACHE_CTL" "$@" 2>/dev/null
        return $?
    fi
    if secaudit_have_bin "$APACHE_BIN"; then
        "$APACHE_BIN" "$@" 2>/dev/null
        return $?
    fi
    return 1
}

secaudit_conf_files_collect() {
    local f line path seen="" queue=""
    [ -f "$APACHE_MAIN" ] && queue="$APACHE_MAIN"
    while [ -n "$queue" ]; do
        f=${queue%% *}
        queue=${queue#$f}
        queue=${queue# }
        [ -z "$f" ] && break
        case " $seen " in
            *" $f "*) continue ;;
        esac
        seen="$seen $f"
        echo "$f"
        [ -f "$f" ] || continue
        while IFS= read -r line; do
            line=${line%%#*}
            case "$line" in
                *IncludeOptional*|*Include*)
                    path=${line#*IncludeOptional}
                    path=${path#*Include}
                    path=${path//\"/}
                    path=${path//\'/}
                    for path in $path; do
                        case "$path" in
                            /*)
                                if [ -d "$path" ]; then
                                    for queue in "$path"/*.conf $queue; do :; done
                                elif [ -f "$path" ]; then
                                    queue="$path $queue"
                                fi
                                ;;
                            *)
                                if [ -f "$(dirname "$f")/$path" ]; then
                                    queue="$(dirname "$f")/$path $queue"
                                elif [ -f "${APACHE_DIR}/${path}" ]; then
                                    queue="${APACHE_DIR}/${path} $queue"
                                elif [ -f "${APACHE_DIR}/conf.d/${path}" ]; then
                                    queue="${APACHE_DIR}/conf.d/${path} $queue"
                                fi
                                ;;
                        esac
                    done
                    ;;
            esac
        done < "$f"
    done
    for f in "$APACHE_DIR"/conf.d/*.conf "$APACHE_DIR"/sites-enabled/* \
             "$APACHE_DIR"/sites-available/* "$APACHE_DIR"/conf-enabled/* \
             "$APACHE_MODULES_DIR"/*.conf "$APACHE_MODULES_DIR"/*; do
        [ -f "$f" ] && echo "$f"
    done
}

secaudit_conf_files() {
    secaudit_conf_files_collect | sort -u
}

secaudit_active_grep() {
    local pattern="$1"
    local f
    while IFS= read -r f; do
        [ -f "$f" ] || continue
        grep -iE "$pattern" "$f" 2>/dev/null | grep -vE '^[[:space:]]*#'
    done < <(secaudit_conf_files)
}

secaudit_directive_values() {
    local directive="$1"
    secaudit_active_grep "^[[:space:]]*${directive}[[:space:]]+" | \
        sed -E "s/^[[:space:]]*${directive}[[:space:]]+//;s/[[:space:]]+$//;s/[[:space:]]*#.*$//" | \
        sort -u | tr '\n' ' '
}

secaudit_directive_numeric() {
    local directive="$1" default="${2:-}"
    local val
    val=$(secaudit_directive_values "$directive")
    val=${val%% *}
    val=$(printf '%s' "$val" | grep -oE '[0-9]+' | head -1)
    if [ -n "$val" ]; then
        echo "$val"
    else
        echo "$default"
    fi
}

secaudit_request_read_timeout_max() {
    local part="$1" default="${2:-}"
    local line max="" n
    while IFS= read -r line; do
        case "$line" in
            *"${part}"=*)
                line=${line#*"${part}"=}
                line=${line%%,*}
                n=$(printf '%s' "$line" | tr '-' ' ' | awk '{print $NF}')
                [ -n "$n" ] && max="$n"
                ;;
        esac
    done < <(secaudit_active_grep 'RequestReadTimeout')
    if [ -n "$max" ]; then
        echo "$max"
    else
        echo "$default"
    fi
}

secaudit_modules() {
    secaudit_run -M
}

secaudit_module_list() {
    secaudit_modules | awk '/module/ {print $1}' | sort -u | tr '\n' ' '
}

secaudit_worker_user() {
    local u g
    u=$(secaudit_active_grep '^[[:space:]]*User[[:space:]]+' | awk '{print $2}' | tail -1)
    g=$(secaudit_active_grep '^[[:space:]]*Group[[:space:]]+' | awk '{print $2}' | tail -1)
    [ -n "$u" ] || u="$APACHE_USER"
    [ -n "$g" ] || g="$APACHE_GROUP"
    printf 'User %s,Group %s' "$u" "$g"
}

secaudit_worker_group() {
    local g
    g=$(secaudit_active_grep '^[[:space:]]*Group[[:space:]]+' | awk '{print $2}' | tail -1)
    [ -n "$g" ] || g="$APACHE_GROUP"
    echo "$g"
}

secaudit_document_root() {
    local dr
    dr=$(secaudit_active_grep '^[[:space:]]*DocumentRoot[[:space:]]+' | head -1 | awk '{print $2}' | tr -d '"')
    if [ -n "$dr" ]; then
        echo "$dr"
        return 0
    fi
    [ -d /var/www/html ] && echo "/var/www/html" && return 0
    echo "/var/www/html"
}

secaudit_block_grep() {
    local open_tag="$1" close_tag="$2" pattern="$3"
    local f
    while IFS= read -r f; do
        [ -f "$f" ] || continue
        awk -v open="$open_tag" -v close="$close_tag" '
            BEGIN { inside=0 }
            $0 ~ ("^[[:space:]]*" open "[[:space:]]") { inside=1; block=$0; next }
            inside { block=block "\n" $0 }
            inside && $0 ~ ("^[[:space:]]*" close ">") {
                print block
                inside=0; block=""
            }
        ' "$f" 2>/dev/null | grep -iE "$pattern"
    done < <(secaudit_conf_files)
}

secaudit_directory_block_grep() {
    secaudit_block_grep '<Directory' '</Directory>' "$1"
}

secaudit_filesmatch_block_grep() {
    secaudit_block_grep '<FilesMatch' '</FilesMatch>' "$1"
}

secaudit_directorymatch_block_grep() {
    secaudit_block_grep '<DirectoryMatch' '</DirectoryMatch>' "$1"
}

secaudit_pid_file() {
    local pid
    pid=$(secaudit_directive_values 'PidFile')
    pid=${pid%% *}
    pid=${pid//\"/}
    [ -n "$pid" ] || pid="${APACHE_RUN_DIR}/${APACHE_SVC}.pid"
    echo "$pid"
}

secaudit_scoreboard_file() {
    local sb
    sb=$(secaudit_directive_values 'ScoreBoardFile')
    sb=${sb%% *}
    sb=${sb//\"/}
    if [ -n "$sb" ]; then
        echo "$sb"
        return 0
    fi
    for sb in "${APACHE_RUN_DIR}/apache2.scoreboard" "${APACHE_RUN_DIR}/httpd.scoreboard" \
              "/var/run/apache2/apache2.scoreboard" "/var/run/httpd/scoreboard"; do
        [ -e "$sb" ] && echo "$sb" && return 0
    done
    echo "${APACHE_RUN_DIR}/scoreboard"
}

secaudit_core_dump_dir() {
    local d
    d=$(secaudit_directive_values 'CoreDumpDirectory')
    d=${d%% *}
    d=${d//\"/}
    [ -n "$d" ] && echo "$d" || echo "/var/log/${APACHE_SVC}"
}

secaudit_listen_directives() {
    secaudit_active_grep '^[[:space:]]*Listen[[:space:]]+' | \
        sed -E 's/^[[:space:]]*Listen[[:space:]]+//;s/[[:space:]]+$//' | sort -u | tr '\n' ' '
}

secaudit_ssl_cert_file() {
    secaudit_active_grep 'SSLCertificateFile' | head -1 | awk '{print $2}' | tr -d '"'
}

secaudit_ssl_key_file() {
    secaudit_active_grep 'SSLCertificateKeyFile' | head -1 | awk '{print $2}' | tr -d '"'
}

secaudit_header_values() {
    local name="$1"
    secaudit_active_grep "Header[[:space:]]+(always[[:space:]]+)?(set|append)[[:space:]]+${name}" | \
        sed -E 's/.*Header[[:space:]]+(always[[:space:]]+)?(set|append)[[:space:]]+[^[:space:]]+[[:space:]]+//;s/[[:space:]]+$//' | \
        tr -d '"' | sort -u | tr '\n' ' '
}

secaudit_find_perm_violations() {
    local dir="$1" user_check="$2" group_check="$3" perm_mask="$4" max="${5:-25}"
    local args=()
    [ -d "$dir" ] || { echo "MISSING"; return; }
    if [ "$user_check" = "not_root" ]; then
        find -L "$dir" ! -type l ! -user root 2>/dev/null | head -"$max" | tr '\n' ' '
        return
    fi
    if [ "$group_check" = "not_root" ]; then
        find "$dir" -path "${dir}/htdocs" -prune -o ! -group root -print 2>/dev/null | head -"$max" | tr '\n' ' '
        return
    fi
    if [ -n "$perm_mask" ]; then
        find -L "$dir" ! -type l -perm "$perm_mask" -ls 2>/dev/null | head -"$max" | awk '{print $3,$11}' | tr '\n' ' '
    fi
}

secaudit_git_restriction_assessment() {
    if secaudit_directorymatch_block_grep '\.git' | grep -qiE 'Require[[:space:]]+all[[:space:]]+denied'; then
        echo "PASS: Access to .git files is properly restricted"
    elif secaudit_filesmatch_block_grep '\.git' | grep -qiE 'Require[[:space:]]+all[[:space:]]+denied'; then
        echo "PASS: Access to .git files is properly restricted"
    elif secaudit_active_grep '\.git' | grep -qiE 'Require[[:space:]]+all[[:space:]]+denied'; then
        echo "PASS: Access to .git files is properly restricted"
    else
        echo "FAIL: Access to .git files is not restricted"
    fi
}

secaudit_svn_restriction_assessment() {
    if secaudit_directorymatch_block_grep '\.svn' | grep -qiE 'Require[[:space:]]+all[[:space:]]+denied'; then
        echo "PASS: Access to .svn files is properly restricted"
    elif secaudit_filesmatch_block_grep '\.svn' | grep -qiE 'Require[[:space:]]+all[[:space:]]+denied'; then
        echo "PASS: Access to .svn files is properly restricted"
    elif secaudit_active_grep '\.svn' | grep -qiE 'Require[[:space:]]+all[[:space:]]+denied'; then
        echo "PASS: Access to .svn files is properly restricted"
    else
        echo "FAIL: Access to .svn files is not restricted"
    fi
}

secaudit_referrer_policy_assessment() {
    local val
    val=$(secaudit_header_values 'Referrer-Policy')
    if [ -n "$val" ]; then
        echo "PASS: HTTP Header Referrer-Policy is set to '${val}'"
    else
        echo "FAIL: HTTP Header Referrer-Policy is not set"
    fi
}

secaudit_permissions_policy_assessment() {
    local val
    val=$(secaudit_header_values 'Permissions-Policy')
    if [ -n "$val" ]; then
        echo "PASS: HTTP Header Permissions-Policy is set to '${val}'"
    else
        echo "FAIL: HTTP Header Permissions-Policy is not set"
    fi
}

secaudit_http_methods_assessment() {
    if secaudit_active_grep '<LimitExcept' | grep -qiE 'GET|HEAD|POST|OPTIONS'; then
        echo "PASS: HTTP request methods are restricted via LimitExcept (GET/HEAD/POST/OPTIONS)"
    elif secaudit_active_grep '<Limit[[:space:]]+(GET|HEAD|POST|OPTIONS)' | grep -q .; then
        echo "PASS: HTTP request methods are restricted via Limit/LimitExcept"
    else
        echo "FAIL: HTTP request methods are not restricted (LimitExcept for GET/HEAD/POST/OPTIONS not found)"
    fi
}

secaudit_ip_host_rewrite_assessment() {
    if secaudit_active_grep 'RewriteCond.*HTTP_HOST|RewriteCond.*REQUEST_URI|RewriteRule.*\[F' | grep -q .; then
        echo "PASS: IP-based or invalid host requests are restricted"
    else
        echo "FAIL: IP-based requests may be allowed"
    fi
}

secaudit_listen_assessment() {
    local listen bad=""
    while IFS= read -r listen; do
        [ -z "$listen" ] && continue
        case "$listen" in
            0.0.0.0:*|::*|[[]::[]]:*|*:*)
                bad="${bad} wildcard:${listen}"
                ;;
            *:*)
                case "$listen" in
                    [0-9]*.[0-9]*.[0-9]*.[0-9]*:*|[[]*[]]:*) ;;
                    *) bad="${bad} no-ip:${listen}" ;;
                esac
                ;;
            *)
                bad="${bad} port-only:${listen}"
                ;;
        esac
    done < <(secaudit_active_grep '^[[:space:]]*Listen[[:space:]]+' | sed -E 's/^[[:space:]]*Listen[[:space:]]+//')
    if [ -z "$bad" ]; then
        echo "PASS: Listen directives specify explicit addresses"
    else
        echo "FAIL: Unrestricted or port-only Listen directives:${bad}"
    fi
}

secaudit_framing_assessment() {
    local hdr
    hdr=$(secaudit_active_grep 'Header[[:space:]]+(always[[:space:]]+)?(set|append)[[:space:]]+(X-Frame-Options|Content-Security-Policy)' | tr '\n' ' ')
    if [ -n "$hdr" ]; then
        echo "PASS: Browser framing restricted (${hdr})"
    else
        echo "FAIL: X-Frame-Options or Content-Security-Policy not configured"
    fi
}

secaudit_htaccess_assessment() {
    if secaudit_filesmatch_block_grep '\.ht' | grep -qiE 'Require[[:space:]]+all[[:space:]]+denied'; then
        echo "PASS: Access to .ht* files is denied"
    else
        echo "FAIL: Access to .ht* files is not restricted"
    fi
}

secaudit_uses_ssl() {
    secaudit_module_loaded 'ssl_module' || secaudit_module_loaded 'nss_module' || \
    secaudit_active_grep '^[[:space:]]*Listen[[:space:]]+.*443' | grep -q .
}

secaudit_dav_modules_assessment() {
    local loaded
    loaded=$(secaudit_modules | awk '/dav_module|dav_fs_module|dav_lock_module/ {print $1}' | tr '\n' ' ' | xargs)
    if [ -n "$loaded" ]; then
        echo "FAIL: WebDAV modules are loaded (${loaded})"
    else
        echo "PASS: WebDAV modules are not loaded"
    fi
}

secaudit_tls_protocol_assessment() {
    local cfg
    if ! secaudit_uses_ssl; then
        echo "PASS: Not applicable (SSL/TLS not configured)"
        return
    fi
    cfg=$(secaudit_active_grep 'SSLProtocol' | tr '\n' ' ')
    if [ -z "$cfg" ]; then
        echo "FAIL: SSLProtocol is not configured"
        return
    fi
    if echo "$cfg" | grep -qiE 'TLSv1(\.0)?|TLSv1\.1|SSLv2|SSLv3|\+TLSv1[^.]'; then
        echo "FAIL: Weak TLS protocols may be enabled (${cfg})"
    else
        echo "PASS: TLSv1.0/TLSv1.1 and SSL are not enabled (${cfg})"
    fi
}

secaudit_weak_cipher_assessment() {
    local cfg
    if ! secaudit_uses_ssl; then
        echo "PASS: Not applicable (SSL/TLS not configured)"
        return
    fi
    cfg=$(secaudit_active_grep 'SSLCipherSuite' | tr '\n' ' ')
    if [ -z "$cfg" ]; then
        echo "FAIL: SSLCipherSuite is not configured"
        return
    fi
    if echo "$cfg" | grep -qiE 'RC4|MD5|NULL|EXPORT|ADH|LOW|DES|3DES|IDEA'; then
        echo "FAIL: Weak ciphers may be enabled (${cfg})"
    else
        echo "PASS: No obvious weak cipher keywords in SSLCipherSuite"
    fi
}

secaudit_pfs_assessment() {
    local cfg
    if ! secaudit_uses_ssl; then
        echo "PASS: Not applicable (SSL/TLS not configured)"
        return
    fi
    cfg=$(secaudit_active_grep 'SSLCipherSuite' | tr '\n' ' ')
    if [ -z "$cfg" ]; then
        echo "FAIL: SSLCipherSuite is not configured"
        return
    fi
    if echo "$cfg" | grep -qiE 'RC4|MD5|NULL|EXPORT|ADH|LOW|SSLv2|SSLv3'; then
        echo "FAIL: Weak or non-PFS cipher configuration detected"
        return
    fi
    if echo "$cfg" | grep -qiE 'ECDHE|DHE|EECDH|EDH'; then
        echo "PASS: Forward-secrecy cipher suites (ECDHE/DHE) are configured"
    else
        echo "FAIL: No ECDHE/DHE cipher suites detected"
    fi
}

secaudit_hsts_assessment() {
    local val
    if ! secaudit_uses_ssl; then
        echo "PASS: Not applicable (SSL/TLS not configured)"
        return
    fi
    val=$(secaudit_header_values 'Strict-Transport-Security')
    if [ -n "$val" ]; then
        echo "PASS: Strict-Transport-Security is set (${val})"
    else
        echo "FAIL: Strict-Transport-Security is not set"
    fi
}

secaudit_ocsp_assessment() {
    local cfg
    if ! secaudit_uses_ssl; then
        echo "PASS: Not applicable (SSL/TLS not configured)"
        return
    fi
    cfg=$(secaudit_active_grep 'SSLUseStapling|SSLStaplingCache' | tr '\n' ' ')
    if echo "$cfg" | grep -qiE 'SSLUseStapling[[:space:]]+On'; then
        echo "PASS: OCSP stapling is enabled (${cfg})"
    else
        echo "FAIL: OCSP stapling is not enabled"
    fi
}

secaudit_extension_restriction_assessment() {
    local hits
    hits=$(secaudit_filesmatch_block_grep '\.(bak|backup|config|conf|dist|inc|ini|log|old|orig|save|sql|swp|tar|gz|zip|bz2)' | \
        grep -iE 'Require[[:space:]]+all[[:space:]]+denied' | tr '\n' ' ')
    if [ -n "$hits" ]; then
        echo "PASS: Inappropriate file extensions are restricted"
    else
        echo "FAIL: Inappropriate file extensions are not restricted"
    fi
}

secaudit_trace_assessment() {
    local cfg
    cfg=$(secaudit_active_grep 'TraceEnable' | tr '\n' ' ')
    if echo "$cfg" | grep -qiE 'TraceEnable[[:space:]]+off'; then
        echo "PASS: TraceEnable is off"
    elif [ -z "$cfg" ]; then
        echo "FAIL: TraceEnable is not explicitly set to off"
    else
        echo "FAIL: TraceEnable is not off (${cfg})"
    fi
}

secaudit_old_http_assessment() {
    if secaudit_active_grep 'RewriteEngine[[:space:]]+[Oo]n|RewriteCond.*HTTP_PROTOCOL|RewriteRule.*HTTP' | grep -q .; then
        echo "PASS: Rewrite rules restrict old HTTP protocol versions"
    else
        echo "FAIL: Old HTTP protocol versions are not restricted"
    fi
}

secaudit_log_config_assessment() {
    local lvl
    lvl=$(secaudit_active_grep '^[[:space:]]*LogLevel[[:space:]]+' | head -1 | awk '{print $2}')
    if echo "$lvl" | grep -qiE 'info|notice|warn|error|crit|alert|emerg'; then
        echo "PASS: LogLevel includes info or stricter (${lvl})"
    else
        echo "FAIL: LogLevel may not log missing resources (${lvl:-unset})"
    fi
}

secaudit_access_log_assessment() {
    if secaudit_active_grep 'LogFormat.*combined|CustomLog' | grep -q .; then
        echo "PASS: Combined access log format is configured"
    else
        echo "FAIL: Combined access log is not configured"
    fi
}

secaudit_modsecurity_assessment() {
    if secaudit_modules | awk '/security2_module/ {found=1} END{exit !found}'; then
        echo "PASS: ModSecurity (security2_module) is loaded"
    else
        echo "FAIL: ModSecurity is not loaded"
    fi
}

secaudit_module_loaded() {
    secaudit_modules | awk -v m="$1" '$1 ~ m {found=1} END{exit !found}'
}

secaudit_module_present_assessment() {
    local mod="$1"
    if secaudit_module_loaded "$mod"; then
        echo "PASS: ${mod} is loaded"
    else
        echo "FAIL: ${mod} is not loaded"
    fi
}

secaudit_module_absent_assessment() {
    local mod="$1"
    if secaudit_module_loaded "$mod"; then
        echo "FAIL: ${mod} is loaded"
    else
        echo "PASS: ${mod} is not loaded"
    fi
}

secaudit_proxy_modules_assessment() {
    local loaded
    loaded=$(secaudit_modules | awk '/proxy_/ {print $1}' | tr '\n' ' ' | xargs)
    if [ -n "$loaded" ]; then
        echo "FAIL: proxy modules are loaded (${loaded})"
    else
        echo "PASS: proxy modules are not loaded"
    fi
}

secaudit_auth_modules_assessment() {
    local loaded
    loaded=$(secaudit_modules | awk '/auth_basic_module|auth_digest_module/ {print $1}' | tr '\n' ' ' | xargs)
    if [ -n "$loaded" ]; then
        echo "FAIL: auth modules are loaded (${loaded})"
    else
        echo "PASS: auth_basic/auth_digest modules are not loaded"
    fi
}

secaudit_passwd_line() {
    local user="$1"
    getent passwd "$user" 2>/dev/null || \
    grep "^${user}:" /etc/passwd 2>/dev/null || \
    { [ -n "${NSS_WRAPPER_PASSWD:-}" ] && [ -f "$NSS_WRAPPER_PASSWD" ] && \
      grep "^${user}:" "$NSS_WRAPPER_PASSWD" 2>/dev/null; }
}

secaudit_worker_user_assessment() {
    local u g
    u=$(secaudit_active_grep '^[[:space:]]*User[[:space:]]+' | awk '{print $2}' | tail -1)
    g=$(secaudit_active_grep '^[[:space:]]*Group[[:space:]]+' | awk '{print $2}' | tail -1)
    [ -n "$u" ] || u="$APACHE_USER"
    [ -n "$g" ] || g="$APACHE_GROUP"
    if [ "$u" = "root" ]; then
        echo "FAIL: Apache runs as User root"
    elif [ "$u" = "nobody" ] || [ "$u" = "daemon" ]; then
        echo "FAIL: Apache runs as deprecated User ${u} (use a dedicated service account)"
    elif [ "$g" = "root" ]; then
        echo "FAIL: Apache runs as Group root (User=${u})"
    else
        echo "PASS: Apache runs as User ${u}, Group ${g} (non-root dedicated account)"
    fi
}

secaudit_invalid_shell_assessment() {
    local line shell user="${1:-$WORKER_USER}"
    line=$(secaudit_passwd_line "$user")
    shell=$(printf '%s' "$line" | cut -d: -f7)
    if echo "$shell" | grep -qiE 'nologin|false|/bin/false'; then
        echo "PASS: ${user} has non-login shell (${shell})"
    else
        echo "FAIL: ${user} has login shell (${shell:-unknown})"
    fi
}

secaudit_account_locked_assessment() {
    local st user="${1:-$WORKER_USER}" line shell
    st=$(passwd -S "$user" 2>/dev/null | awk '{print $2}')
    case "$st" in
        L|LK|NL) echo "PASS: ${user} account is locked (${st})"; return ;;
    esac
    line=$(secaudit_passwd_line "$user")
    shell=$(printf '%s' "$line" | cut -d: -f7)
    if echo "$shell" | grep -qiE 'nologin|false|/bin/false'; then
        echo "PASS: ${user} account is locked (non-login shell ${shell})"
    else
        echo "FAIL: ${user} account is not locked (${st:-unknown})"
    fi
}

secaudit_perm_violation_assessment() {
    local result="$1" ok_msg="$2" fail_msg="$3"
    if [ "$result" = "MISSING" ]; then
        echo "FAIL: ${fail_msg} (path missing)"
    elif [ -z "${result// /}" ]; then
        echo "PASS: ${ok_msg}"
    else
        echo "FAIL: ${fail_msg} (${result})"
    fi
}

secaudit_core_dump_assessment() {
    local owner mode
    if [ ! -d "$CORE_DUMP_DIR" ]; then
        echo "FAIL: CoreDumpDirectory ${CORE_DUMP_DIR} is missing"
        return
    fi
    owner=$(stat -c '%U:%G' "$CORE_DUMP_DIR" 2>/dev/null)
    mode=$(stat -c '%a' "$CORE_DUMP_DIR" 2>/dev/null)
    if echo "$owner" | grep -q '^root:' && [ "${mode:-777}" -le 750 ] 2>/dev/null; then
        echo "PASS: CoreDumpDirectory is secured (${owner}, mode=${mode})"
    else
        echo "FAIL: CoreDumpDirectory is not secured (${owner}, mode=${mode:-unknown})"
    fi
}

secaudit_mutex_assessment() {
    local m
    m=$(secaudit_active_grep '^[[:space:]]*Mutex[[:space:]]+' | tr '\n' ' ')
    if [ -n "$m" ]; then
        echo "PASS: Mutex is configured (${m})"
    else
        echo "PASS: Mutex uses system default (semaphores)"
    fi
}

secaudit_pid_assessment() {
    local info
    if [ ! -e "$PID_FILE" ]; then
        echo "FAIL: Pid file ${PID_FILE} is missing"
        return
    fi
    info=$(ls -ld "$PID_FILE" 2>/dev/null | awk '{print $3,$4,$1}')
    if echo "$info" | grep -q '^root '; then
        echo "PASS: Pid file secured (${info})"
    else
        echo "FAIL: Pid file not owned by root (${info})"
    fi
}

secaudit_root_directory_assessment() {
    local pattern="$1" pass_msg="$2"
    if secaudit_directory_block_grep '<Directory[[:space:]]+"/"' | grep -qiE "$pattern"; then
        echo "PASS: ${pass_msg}"
    else
        echo "FAIL: ${pass_msg} is not configured for OS root directory"
    fi
}

secaudit_allowoverride_assessment() {
    local bad
    bad=$(secaudit_active_grep 'AllowOverride[[:space:]]+' | grep -viE 'AllowOverride[[:space:]]+[Nn]one' | tr '\n' ' ')
    if [ -z "${bad// /}" ]; then
        echo "PASS: AllowOverride none is configured for all directories"
    else
        echo "FAIL: AllowOverride is not none in some contexts (${bad})"
    fi
}

secaudit_options_root_assessment() {
    if secaudit_directory_block_grep '<Directory[[:space:]]+"/"' | grep -qiE 'Options[[:space:]]+[Nn]one'; then
        echo "PASS: Options None on OS root directory"
    else
        echo "FAIL: Options None is not set on OS root directory"
    fi
}

secaudit_options_docroot_assessment() {
    local dr="${DOCROOT:-$(secaudit_document_root)}"
    if secaudit_directory_block_grep "${dr}|DocumentRoot" | grep -qiE 'Options[[:space:]]+[Nn]one'; then
        echo "PASS: Options None on web root directory (${dr})"
    else
        echo "FAIL: Options None is not set on web root directory (${dr})"
    fi
}

secaudit_dangerous_options_assessment() {
    local hits
    hits=$(secaudit_active_grep 'Options[[:space:]]+' | grep -viE 'Options[[:space:]]+[Nn]one' | \
        grep -iE 'Includes|Indexes|ExecCGI|FollowSymLinks' | tr '\n' ' ')
    if [ -z "$hits" ]; then
        echo "PASS: No dangerous Options directives found"
    else
        echo "FAIL: Dangerous Options may be enabled (${hits})"
    fi
}

secaudit_welcome_removed_assessment() {
    local wf found=""
    for wf in $APACHE_WELCOME /etc/httpd/conf.d/welcome.conf; do
        [ -f "$wf" ] && found="$wf" && break
    done
    if [ -z "$found" ]; then
        echo "PASS: Default welcome content is removed"
    else
        echo "FAIL: Default welcome content present (${found})"
    fi
}

secaudit_cgi_script_absent_assessment() {
    local name="$1"
    local hits
    hits=$(grep -ril "$name" "$APACHE_CGI" /var/www/cgi-bin /usr/lib/cgi-bin 2>/dev/null | tr '\n' ' ')
    if [ -z "$hits" ]; then
        echo "PASS: Default CGI script ${name} is removed"
    else
        echo "FAIL: Default CGI script ${name} found (${hits})"
    fi
}

secaudit_syslog_error_assessment() {
    if secaudit_active_grep 'ErrorLog[[:space:]]+"?syslog|ErrorLog[[:space:]]+syslog' | grep -q .; then
        echo "PASS: ErrorLog syslog is configured"
    else
        echo "FAIL: ErrorLog syslog is not configured"
    fi
}

secaudit_crs_assessment() {
    local count dir
    for dir in "$APACHE_DIR/modsecurity.d/owasp-modsecurity-crs-3.0.0" \
               "$APACHE_DIR/modsecurity.d/crs" \
               /usr/share/modsecurity-crs /etc/modsecurity/crs \
               /usr/share/modsecurity-crs/base_rules /etc/modsecurity.d/crs; do
        [ -d "$dir" ] || continue
        count=$(find "$dir" -name '*.conf' 2>/dev/null | xargs grep -h '^SecRule ' 2>/dev/null | wc -l | tr -d ' ')
        [ "${count:-0}" -gt 0 ] 2>/dev/null && break
    done
    count=${count:-0}
    if [ "$count" -gt 0 ] 2>/dev/null; then
        echo "PASS: OWASP CRS rules loaded (count=${count})"
    else
        echo "FAIL: OWASP CRS rules not found (count=0)"
    fi
}

secaudit_ssl_module_assessment() {
    local loaded
    loaded=$(secaudit_modules | awk '/ssl_module|nss_module/ {print $1}' | tr '\n' ' ' | xargs)
    if [ -n "$loaded" ]; then
        echo "PASS: SSL module is loaded (${loaded})"
    else
        echo "FAIL: mod_ssl/mod_nss is not loaded"
    fi
}

secaudit_ssl_directive_assessment() {
    local directive="$1" pattern="$2" pass_msg="$3"
    local cfg
    if ! secaudit_uses_ssl; then
        echo "PASS: Not applicable (SSL/TLS not configured)"
        return
    fi
    cfg=$(secaudit_active_grep "$directive" | tr '\n' ' ')
    if echo "$cfg" | grep -qiE "$pattern"; then
        echo "PASS: ${pass_msg} (${cfg})"
    elif [ -z "$cfg" ] && [ "$pattern" = 'off' ]; then
        echo "FAIL: ${directive} is not explicitly set to off"
    else
        echo "FAIL: ${pass_msg} (${cfg:-unset})"
    fi
}

secaudit_https_only_assessment() {
    local http
    http=$(secaudit_active_grep '^[[:space:]]*Listen[[:space:]]+' | grep -viE ':443|ssl|https' | \
        sed -E 's/^[[:space:]]*Listen[[:space:]]+//' | tr '\n' ' ')
    if [ -z "${http// /}" ]; then
        echo "PASS: No plain HTTP Listen directives found"
    else
        echo "FAIL: Plain HTTP Listen directives present (${http})"
    fi
}

secaudit_server_tokens_assessment() {
    local tokens
    tokens=$(secaudit_var SERVER_TOKENS "Prod,ProductOnly")
    tokens=${tokens//,/|}
    if secaudit_active_grep 'ServerTokens' | grep -qiE "ServerTokens[[:space:]]+(${tokens})"; then
        echo "PASS: ServerTokens is ${tokens}"
    else
        echo "FAIL: ServerTokens is not ${tokens}"
    fi
}

secaudit_server_signature_assessment() {
    local sig
    sig=$(secaudit_var SERVER_SIGNATURE Off)
    if secaudit_active_grep 'ServerSignature' | grep -qiE "ServerSignature[[:space:]]+${sig}"; then
        echo "PASS: ServerSignature is ${sig}"
    else
        echo "FAIL: ServerSignature is not ${sig}"
    fi
}

secaudit_numeric_assessment() {
    local directive="$1" op="$2" limit="$3" default="$4"
    local val
    val=$(secaudit_directive_numeric "$directive" "$default")
    case "$op" in
        le)
            if [ "$val" -le "$limit" ] 2>/dev/null && [ "$val" -gt 0 ] 2>/dev/null; then
                echo "PASS: ${directive}=${val} (limit<=${limit})"
            elif [ "$val" -eq 0 ] 2>/dev/null && [ "$limit" -ge 0 ] 2>/dev/null && [ "$directive" = "LimitRequestBody" ]; then
                echo "FAIL: ${directive}=${val} (required <=${limit} and >0)"
            elif [ "$val" -le "$limit" ] 2>/dev/null; then
                echo "PASS: ${directive}=${val} (limit<=${limit})"
            else
                echo "FAIL: ${directive}=${val} (required <=${limit})"
            fi
            ;;
        ge)
            if [ "$val" -ge "$limit" ] 2>/dev/null; then
                echo "PASS: ${directive}=${val} (>=${limit})"
            else
                echo "FAIL: ${directive}=${val} (required >=${limit})"
            fi
            ;;
        eq_on)
            if echo "$(secaudit_directive_values "$directive")" | grep -qi 'on'; then
                echo "PASS: ${directive} is On"
            else
                echo "FAIL: ${directive} is not On"
            fi
            ;;
    esac
}

secaudit_request_timeout_assessment() {
    local part="$1" limit="$2" default="$3"
    local val
    val=$(secaudit_request_read_timeout_max "$part" "$default")
    if [ "$val" -le "$limit" ] 2>/dev/null && [ "$val" -gt 0 ] 2>/dev/null; then
        echo "PASS: RequestReadTimeout ${part}=${val} (limit<=${limit})"
    else
        echo "FAIL: RequestReadTimeout ${part}=${val} (required <=${limit} and >0)"
    fi
}

secaudit_selinux_assessment() {
    local field="$1"
    if [ ! -f /etc/selinux/config ]; then
        echo "PASS: Not applicable (SELinux not configured)"
        return
    fi
    case "$field" in
        mode)
            if grep -q '^SELINUX=enforcing' /etc/selinux/config 2>/dev/null; then
                echo "PASS: SELinux is enforcing"
            else
                echo "FAIL: SELinux is not enforcing ($(grep '^SELINUX=' /etc/selinux/config 2>/dev/null))"
            fi
            ;;
        httpd_t)
            if secaudit_have_bin ps; then
                local bad
                bad=$(ps -eZ 2>/dev/null | grep -E 'httpd|apache2' | grep -vc 'httpd_t' || echo 0)
                if [ "${bad:-0}" -eq 0 ] 2>/dev/null; then
                    echo "PASS: Apache processes run in httpd_t context"
                else
                    echo "FAIL: ${bad} Apache process(es) not in httpd_t context"
                fi
            else
                echo "FAIL: Unable to verify SELinux process context"
            fi
            ;;
        permissive)
            if secaudit_have_bin semodule; then
                if semodule -l 2>/dev/null | grep -q permissive_httpd_t; then
                    echo "FAIL: httpd_t permissive mode is enabled"
                else
                    echo "PASS: httpd_t is not in permissive mode"
                fi
            else
                echo "PASS: Not applicable (semodule not available)"
            fi
            ;;
    esac
}

secaudit_apparmor_assessment() {
    local field="$1"
    if ! secaudit_have_bin aa-status; then
        echo "PASS: Not applicable (AppArmor not installed)"
        return
    fi
    case "$field" in
        enabled)
            if aa-status --enabled 2>/dev/null; then
                echo "PASS: AppArmor is enabled"
            else
                echo "FAIL: AppArmor is disabled"
            fi
            ;;
        enforce)
            local hits
            if secaudit_have_bin aa-unconfined; then
                hits=$(aa-unconfined --paranoid 2>/dev/null | grep -E 'apache2|httpd' | tr '\n' ' ')
            else
                hits=$(aa-status 2>/dev/null | grep -E 'apache2|httpd' | tr '\n' ' ')
            fi
            if [ -z "$hits" ]; then
                echo "PASS: Apache AppArmor profile is enforcing"
            else
                echo "FAIL: Apache may not be in enforce mode (${hits})"
            fi
            ;;
    esac
}

secaudit_scoreboard_assessment() {
    local sb info mode
    sb=$(secaudit_scoreboard_file)
    if [ ! -e "$sb" ]; then
        echo "PASS: ScoreBoardFile not used (in-memory scoreboard)"
        return
    fi
    info=$(stat -c '%U:%G' "$sb" 2>/dev/null)
    mode=$(stat -c '%a' "$sb" 2>/dev/null)
    if echo "$info" | grep -q '^root:' && [ "${mode:-777}" -le 640 ] 2>/dev/null; then
        echo "PASS: ScoreBoard file secured (${info}, mode=${mode})"
    else
        echo "FAIL: ScoreBoard file not secured (${info}, mode=${mode:-unknown})"
    fi
}

secaudit_logrotate_assessment() {
    if [ ! -f "$APACHE_LOGROTATE" ] || [ ! -s "$APACHE_LOGROTATE" ]; then
        echo "FAIL: Apache logrotate configuration is missing (${APACHE_LOGROTATE})"
        return
    fi
    if grep -E 'weekly|daily|monthly' "$APACHE_LOGROTATE" 2>/dev/null | grep -vE '^[[:space:]]*#' | grep -q . && \
       grep -E 'rotate[[:space:]]+[0-9]+' "$APACHE_LOGROTATE" 2>/dev/null | grep -vE '^[[:space:]]*#' | grep -q .; then
        echo "PASS: Log storage and rotation configured (${APACHE_LOGROTATE})"
    else
        echo "FAIL: Log rotation is not configured correctly (${APACHE_LOGROTATE})"
    fi
}

secaudit_patches_assessment() {
    local updates=0
    if secaudit_have_bin dnf; then
        updates=$(dnf check-update --security $APACHE_PKG_NAMES 2>/dev/null | awk '/^(httpd|apache2|mod_|libapache2)/ {c++} END{print c+0}')
    elif secaudit_have_bin yum; then
        updates=$(yum --security check-update $APACHE_PKG_NAMES 2>/dev/null | awk '/^(httpd|apache2|mod_|libapache2)/ {c++} END{print c+0}')
    elif secaudit_have_bin apt-get; then
        updates=$(apt-get -s upgrade 2>/dev/null | grep -ciE 'apache2|libapache2' || true)
    else
        echo "PASS: Not applicable (package manager unavailable)"
        return
    fi
    if [ "${updates:-0}" -eq 0 ] 2>/dev/null; then
        echo "PASS: No pending security updates for Apache packages"
    else
        echo "FAIL: ${updates} pending security update(s) for Apache packages"
    fi
}

secaudit_ssl_cert_assessment() {
    local cert count
    if ! secaudit_uses_ssl; then
        echo "PASS: Not applicable (SSL/TLS not configured)"
        return
    fi
    cert=$(secaudit_ssl_cert_file)
    if [ -z "$cert" ] || [ ! -r "$cert" ]; then
        echo "FAIL: SSLCertificateFile is missing or unreadable"
        return
    fi
    if secaudit_have_bin openssl && openssl x509 -in "$cert" -noout -subject -dates >/dev/null 2>&1; then
        count=$(grep -c 'BEGIN CERTIFICATE' "$cert" 2>/dev/null || echo 1)
        echo "PASS: SSLCertificateFile is valid (${cert}, chain_blocks=${count})"
    else
        echo "FAIL: SSLCertificateFile is invalid or unreadable (${cert})"
    fi
}

secaudit_ssl_key_assessment() {
    local key mode owner
    if ! secaudit_uses_ssl; then
        echo "PASS: Not applicable (SSL/TLS not configured)"
        return
    fi
    key=$(secaudit_ssl_key_file)
    if [ -z "$key" ] || [ ! -e "$key" ]; then
        echo "FAIL: SSLCertificateKeyFile is missing"
        return
    fi
    mode=$(stat -c '%a' "$key" 2>/dev/null)
    owner=$(stat -c '%U:%G' "$key" 2>/dev/null)
    if secaudit_in_csv "$mode" "$(secaudit_var KEY_MODES "600,400,440")"; then
        echo "PASS: Private key permissions are restricted (${mode} ${owner} ${key})"
    else
        echo "FAIL: Private key permissions are too open (${mode} ${owner} ${key}; accepted $(secaudit_var KEY_MODES "600,400,440"))"
    fi
}

secaudit_medium_cipher_assessment() {
    local cfg
    if ! secaudit_uses_ssl; then
        echo "PASS: Not applicable (SSL/TLS not configured)"
        return
    fi
    cfg=$(secaudit_active_grep 'SSLCipherSuite' | tr '\n' ' ')
    if [ -z "$cfg" ]; then
        echo "FAIL: SSLCipherSuite is not configured"
        return
    fi
    if echo "$cfg" | grep -qiE '3DES|DES-CBC3|IDEA'; then
        echo "FAIL: Medium-strength ciphers may be enabled (${cfg})"
    else
        echo "PASS: 3DES and IDEA ciphers are not enabled"
    fi
}

secaudit_default_content_assessment() {
    local hits="" wf p paths="/usr/share/httpd/icons /usr/share/apache2/icons /var/www/icons \
                              /usr/share/doc/httpd /usr/share/doc/apache2 /var/www/cgi-bin"
    for wf in $APACHE_WELCOME /etc/httpd/conf.d/welcome.conf; do
        [ -f "$wf" ] && hits="${hits} ${wf}"
    done
    for p in $paths; do
        [ -d "$p" ] && hits="${hits} ${p}"
    done
    if secaudit_active_grep 'Alias[[:space:]]+/icons|ScriptAlias[[:space:]]+/cgi-bin' | grep -q .; then
        hits="${hits} default-alias"
    fi
    hits=$(printf '%s' "$hits" | xargs)
    if [ -z "$hits" ]; then
        echo "PASS: Default Apache content is removed"
    else
        echo "FAIL: Default Apache content may still be present (${hits})"
    fi
}

secaudit_etag_assessment() {
    local cfg
    cfg=$(secaudit_active_grep 'FileETag' | tr '\n' ' ')
    if echo "$cfg" | grep -qiE 'FileETag[[:space:]]+[Nn]one'; then
        echo "PASS: FileETag is None"
    elif echo "$cfg" | grep -qiE 'FileETag[[:space:]]+(MTime[[:space:]]+Size|MTime,Size|MTime Size)'; then
        echo "PASS: FileETag excludes inode (${cfg})"
    elif [ -z "$cfg" ]; then
        echo "FAIL: FileETag is not configured (default may include inode)"
    else
        echo "FAIL: FileETag may include inode (${cfg})"
    fi
}

secaudit_package_versions() {
    if secaudit_have_bin rpm; then
        rpm -q $APACHE_PKG_NAMES 2>/dev/null | tr '\n' ' '
    elif secaudit_have_bin dpkg-query; then
        dpkg-query -W -f='${Package}=${Version} ' $APACHE_PKG_NAMES 2>/dev/null
    elif secaudit_have_bin "$APACHE_BIN"; then
        "$APACHE_BIN" -v 2>/dev/null | head -1
    else
        echo "UNKNOWN"
    fi
}

secaudit_bootstrap() {
	secaudit_detect_layout

	if ! secaudit_have_bin "$APACHE_BIN" && ! secaudit_have_bin "$APACHE_CTL"; then
	    secaudit_skip_all 79 "Apache HTTP Server is not installed"
	    return 1
	fi

	DOCROOT=$(secaudit_document_root)
	PID_FILE=$(secaudit_pid_file)
	CORE_DUMP_DIR=$(secaudit_core_dump_dir)
	WORKER_GROUP=$(secaudit_worker_group)
	WORKER_LINE=$(secaudit_worker_user)
	WORKER_USER=$(printf '%s' "$WORKER_LINE" | sed -n 's/.*User[[:space:]]*\([^,]*\).*/\1/p')
	[ -n "$WORKER_USER" ] || WORKER_USER="$APACHE_USER"

	return 0
}

secaudit_run_modules() {
	# RULE1-8
	secaudit_emit 1 "$(secaudit_module_present_assessment 'log_config_module')"
	secaudit_emit 2 "$(secaudit_dav_modules_assessment)"
	secaudit_emit 3 "$(secaudit_module_absent_assessment 'status_module')"
	secaudit_emit 4 "$(secaudit_module_absent_assessment 'autoindex_module')"
	secaudit_emit 5 "$(secaudit_proxy_modules_assessment)"
	secaudit_emit 6 "$(secaudit_module_absent_assessment 'userdir_module')"
	secaudit_emit 7 "$(secaudit_module_absent_assessment 'info_module')"
	secaudit_emit 8 "$(secaudit_auth_modules_assessment)"

}

secaudit_run_account_permissions() {
	# RULE9-20
	secaudit_emit 9 "$(secaudit_worker_user_assessment)"
	secaudit_emit 10 "$(secaudit_invalid_shell_assessment)"
	secaudit_emit 11 "$(secaudit_account_locked_assessment)"
	secaudit_emit 12 "$(secaudit_perm_violation_assessment "$(secaudit_find_perm_violations "$APACHE_DIR" not_root "" "" 30)" \
	    "Apache directories and files are owned by root" "Non-root ownership found")"
	secaudit_emit 13 "$(secaudit_perm_violation_assessment "$(secaudit_find_perm_violations "$APACHE_DIR" "" not_root "" 30)" \
	    "Apache directories and files have root group" "Non-root group ownership found")"
	secaudit_emit 14 "$(secaudit_perm_violation_assessment "$(secaudit_find_perm_violations "$APACHE_DIR" "" "" -0002 30)" \
	    "No world-writable Apache files or directories" "World-writable Apache paths found")"
	secaudit_emit 15 "$(secaudit_core_dump_assessment)"
	secaudit_emit 16 "$(secaudit_mutex_assessment)"
	secaudit_emit 17 "$(secaudit_pid_assessment)"
	secaudit_emit 18 "$(secaudit_scoreboard_assessment)"
	secaudit_emit 19 "$(secaudit_perm_violation_assessment "$(secaudit_find_perm_violations "$APACHE_DIR" "" "" -0020 30)" \
	    "No group-writable Apache files or directories" "Group-writable Apache paths found")"
	if [ -d "$DOCROOT" ]; then
	    secaudit_emit 20 "$(secaudit_perm_violation_assessment \
	        "$(find -L "$DOCROOT" -group "$WORKER_GROUP" -perm -0020 -ls 2>/dev/null | head -30 | awk '{print $3,$11}' | tr '\n' ' ')" \
	        "Document root has no group-writable files for Apache group" \
	        "Document root group-writable files found for Apache group")"
	else
	    secaudit_emit 20 "FAIL: Document root ${DOCROOT} is missing"
	fi

}

secaudit_run_access_control() {
	# RULE21-23
	secaudit_emit 21 "$(secaudit_root_directory_assessment 'Require[[:space:]]+all[[:space:]]+denied' 'Root directory access denied')"
	secaudit_emit 22 "$(secaudit_root_directory_assessment 'AllowOverride[[:space:]]+[Nn]one' 'AllowOverride none on OS root')"
	secaudit_emit 23 "$(secaudit_allowoverride_assessment)"

}

secaudit_run_features() {
	# RULE24-41
	secaudit_emit 24 "$(secaudit_options_root_assessment)"
	secaudit_emit 25 "$(secaudit_options_docroot_assessment)"
	secaudit_emit 26 "$(secaudit_dangerous_options_assessment)"
	secaudit_emit 27 "$(secaudit_welcome_removed_assessment)"
	secaudit_emit 28 "$(secaudit_cgi_script_absent_assessment 'printenv')"
	secaudit_emit 29 "$(secaudit_cgi_script_absent_assessment 'test-cgi')"
	secaudit_emit 30 "$(secaudit_http_methods_assessment)"
	secaudit_emit 31 "$(secaudit_trace_assessment)"
	secaudit_emit 32 "$(secaudit_old_http_assessment)"
	secaudit_emit 33 "$(secaudit_htaccess_assessment)"
	secaudit_emit 34 "$(secaudit_git_restriction_assessment)"
	secaudit_emit 35 "$(secaudit_svn_restriction_assessment)"
	secaudit_emit 36 "$(secaudit_extension_restriction_assessment)"
	secaudit_emit 37 "$(secaudit_ip_host_rewrite_assessment)"
	secaudit_emit 38 "$(secaudit_listen_assessment)"
	secaudit_emit 39 "$(secaudit_framing_assessment)"
	secaudit_emit 40 "$(secaudit_referrer_policy_assessment)"
	secaudit_emit 41 "$(secaudit_permissions_policy_assessment)"

}

secaudit_run_logging_modsecurity() {
	# RULE42-48
	secaudit_emit 42 "$(secaudit_log_config_assessment)"
	secaudit_emit 43 "$(secaudit_syslog_error_assessment)"
	secaudit_emit 44 "$(secaudit_access_log_assessment)"
	secaudit_emit 45 "$(secaudit_logrotate_assessment)"
	secaudit_emit 46 "$(secaudit_patches_assessment)"
	secaudit_emit 47 "$(secaudit_modsecurity_assessment)"
	secaudit_emit 48 "$(secaudit_crs_assessment)"

}

secaudit_run_ssl_tls() {
	# RULE49-60
	secaudit_emit 49 "$(secaudit_ssl_module_assessment)"
	secaudit_emit 50 "$(secaudit_ssl_cert_assessment)"
	secaudit_emit 51 "$(secaudit_ssl_key_assessment)"
	secaudit_emit 52 "$(secaudit_tls_protocol_assessment)"
	secaudit_emit 53 "$(secaudit_weak_cipher_assessment)"
	secaudit_emit 54 "$(secaudit_ssl_directive_assessment 'SSLInsecureRenegotiation' 'off' 'SSLInsecureRenegotiation is off')"
	secaudit_emit 55 "$(secaudit_ssl_directive_assessment 'SSLCompression' 'off' 'SSLCompression is off')"
	secaudit_emit 56 "$(secaudit_medium_cipher_assessment)"
	secaudit_emit 57 "$(secaudit_https_only_assessment)"
	secaudit_emit 58 "$(secaudit_ocsp_assessment)"
	secaudit_emit 59 "$(secaudit_hsts_assessment)"
	secaudit_emit 60 "$(secaudit_pfs_assessment)"

}

secaudit_run_information_leakage() {
	# RULE61-64
	secaudit_emit 61 "$(secaudit_server_tokens_assessment)"
	secaudit_emit 62 "$(secaudit_server_signature_assessment)"
	secaudit_emit 63 "$(secaudit_default_content_assessment)"
	secaudit_emit 64 "$(secaudit_etag_assessment)"

}

secaudit_run_dos() {
	# RULE65-70
	secaudit_emit 65 "$(secaudit_numeric_assessment 'TimeOut' le "$(secaudit_var TIMEOUT 10)" 60)"
	secaudit_emit 66 "$(secaudit_numeric_assessment 'KeepAlive' eq_on 0 0)"
	secaudit_emit 67 "$(secaudit_numeric_assessment 'MaxKeepAliveRequests' ge "$(secaudit_var MAX_KEEPALIVE_REQUESTS 100)" 100)"
	secaudit_emit 68 "$(secaudit_numeric_assessment 'KeepAliveTimeout' le "$(secaudit_var KEEPALIVE_TIMEOUT 15)" 5)"
	secaudit_emit 69 "$(secaudit_request_timeout_assessment 'header' "$(secaudit_var REQUEST_READ_HEADER_MAX 40)" 40)"
	secaudit_emit 70 "$(secaudit_request_timeout_assessment 'body' "$(secaudit_var REQUEST_READ_BODY_MAX 20)" 20)"

}

secaudit_run_request_limits() {
	# RULE71-74
	secaudit_emit 71 "$(secaudit_numeric_assessment 'LimitRequestLine' le "$(secaudit_var LIMIT_REQUEST_LINE 8190)" 8190)"
	secaudit_emit 72 "$(secaudit_numeric_assessment 'LimitRequestFields' le "$(secaudit_var LIMIT_REQUEST_FIELDS 100)" 100)"
	secaudit_emit 73 "$(secaudit_numeric_assessment 'LimitRequestFieldsize' le "$(secaudit_var LIMIT_REQUEST_FIELDSIZE 1024)" 8190)"
	secaudit_emit 74 "$(secaudit_numeric_assessment 'LimitRequestBody' le "$(secaudit_var LIMIT_REQUEST_BODY 102400)" 0)"

}

secaudit_run_selinux_rhel_family() {
	# RULE75-77
	secaudit_emit 75 "$(secaudit_selinux_assessment mode)"
	secaudit_emit 76 "$(secaudit_selinux_assessment httpd_t)"
	secaudit_emit 77 "$(secaudit_selinux_assessment permissive)"

}

secaudit_run_apparmor_debian_ubuntu() {
	# RULE78-79
	secaudit_emit 78 "$(secaudit_apparmor_assessment enabled)"
	secaudit_emit 79 "$(secaudit_apparmor_assessment enforce)"

}

secaudit_main() {
	secaudit_bootstrap || return 0
	secaudit_run_modules
	secaudit_run_account_permissions
	secaudit_run_access_control
	secaudit_run_features
	secaudit_run_logging_modsecurity
	secaudit_run_ssl_tls
	secaudit_run_information_leakage
	secaudit_run_dos
	secaudit_run_request_limits
	secaudit_run_selinux_rhel_family
	secaudit_run_apparmor_debian_ubuntu
}

secaudit_main "$@"
