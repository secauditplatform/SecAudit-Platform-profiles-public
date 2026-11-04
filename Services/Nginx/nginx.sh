#!/bin/bash

export LC_ALL=C

if [ -z "${BASH_VERSION:-}" ]; then
    if command -v bash >/dev/null 2>&1; then
        exec bash "$0" "$@"
    fi
    printf '%s\n' "ERROR: bash is required." >&2
    exit 1
fi

set -o pipefail

# --- config ---
_NGINX_CONF_ROOT="${NGINX_CONF_ROOT:-${SECAUDIT_NGINX_CONF_ROOT:-}}"
_NGINX_HTML_ROOT="${NGINX_HTML_ROOT:-${SECAUDIT_NGINX_HTML_ROOT:-/usr/share/nginx/html}}"
_NGINX_LOGROTATE="${NGINX_LOGROTATE:-${SECAUDIT_NGINX_LOGROTATE:-/etc/logrotate.d/nginx}}"
_NGINX_FIND_CAP="${NGINX_FIND_CAP:-${SECAUDIT_NGINX_FIND_CAP:-30}}"
_NGINX_CURL_CAP="${NGINX_CURL_CAP:-${SECAUDIT_NGINX_CURL_CAP:-8}}"
_NGINX_SUDO_CAP="${NGINX_SUDO_CAP:-${SECAUDIT_NGINX_SUDO_CAP:-5}}"
_NGINX_RULE_COUNT=66
_NGINX_AUTHORIZED_HTTP_PORTS="${NGINX_AUTHORIZED_HTTP_PORTS:-${SECAUDIT_NGINX_AUTHORIZED_HTTP_PORTS:-80 443}}"
_NGINX_HSTS_MIN_AGE="${NGINX_HSTS_MIN_AGE:-${SECAUDIT_NGINX_HSTS_MIN_AGE:-15768000}}"
_NGINX_TIMEOUT_SOFT_MAX="${NGINX_TIMEOUT_SOFT_MAX:-${SECAUDIT_NGINX_TIMEOUT_SOFT_MAX:-10}}"
_NGINX_BODY_SIZE_UNLIMITED="${NGINX_BODY_SIZE_UNLIMITED:-${SECAUDIT_NGINX_BODY_SIZE_UNLIMITED:-0}}"
_NGINX_HEADER_BUF_MAX_BYTES="${NGINX_HEADER_BUF_MAX_BYTES:-${SECAUDIT_NGINX_HEADER_BUF_MAX_BYTES:-32768}}"
_NGINX_DH_MIN_BITS="${NGINX_DH_MIN_BITS:-${SECAUDIT_NGINX_DH_MIN_BITS:-2048}}"
_NGINX_PRIVILEGED_GROUPS="${NGINX_PRIVILEGED_GROUPS:-${SECAUDIT_NGINX_PRIVILEGED_GROUPS:-root wheel sudo adm disk}}"

# --- runtime state ---
_NGINX_PRIMARY_CONF=""
_NGINX_BIN=""
_NGINX_SVC_ACCOUNT=""
_NGINX_PID_PATH=""
_NGINX_CONFIG_INDEX=""
_NGINX_COMPILE_FLAGS=""

# --- bootstrap / reporting ---
secaudit_report_pass() { printf 'RULE%s= PASS: %s\n' "$1" "$2"; }
secaudit_report_fail() { printf 'RULE%s= FAIL: %s\n' "$1" "${3:-$2}"; }
secaudit_report_skip() { printf 'RULE%s= SKIP: %s\n' "$1" "$2"; }
secaudit_report_error() { printf 'RULE%s= ERROR: %s\n' "$1" "$2"; }

# --- string / cmd utils ---
secaudit_have_bin() { command -v "$1" >/dev/null 2>&1; }

secaudit_exec_with_timeout() {
    local secs="$1"
    shift
    if secaudit_have_bin timeout; then
        timeout "$secs" "$@"
    else
        "$@"
    fi
}

secaudit_trim_ws() {
    local s="${1-}"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

secaudit_squash_ws() {
    printf '%s' "${1-}" | tr '\n' ' ' | sed -E 's/[[:space:]]+/ /g;s/^ //;s/ $//'
}

secaudit_path_mode_octal() {
    local target="$1"
    if [ -e "$target" ]; then
        stat -c '%a' "$target" 2>/dev/null || ls -ld "$target" 2>/dev/null | awk '{print $1}'
    else
        printf '%s' "MISSING"
    fi
}

secaudit_path_owner_user() {
    local target="$1"
    if [ -e "$target" ]; then
        stat -c '%U' "$target" 2>/dev/null
    fi
}

secaudit_path_owner_group() {
    local target="$1"
    if [ -e "$target" ]; then
        stat -c '%G' "$target" 2>/dev/null
    fi
}

secaudit_path_listing() {
    local target="$1"
    if [ -e "$target" ]; then
        ls -ld "$target" 2>/dev/null | awk '{print $1,$3,$4,$9}' | tr '\n' ' '
    else
        printf '%s' "MISSING"
    fi
}

secaudit_is_sample_config() {
    local path="$1" base
    base=$(basename "$path")
    case "$base" in
        example.conf|sample.conf|example*.conf|sample*.conf|*.default) return 0 ;;
    esac
    case "$path" in
        */examples/*|*/example/*|*/docs/examples/*) return 0 ;;
    esac
    return 1
}

secaudit_seconds_from_nginx_time() {
    local raw token num unit
    raw=$(secaudit_trim_ws "${1-}")
    [ -n "$raw" ] || { printf '%s' ""; return 1; }
    token=$(printf '%s' "$raw" | grep -oE '[0-9]+(\.[0-9]+)?(ms|s|m|h|d)?' | head -1)
    [ -n "$token" ] || { printf '%s' ""; return 1; }
    num=$(printf '%s' "$token" | grep -oE '^[0-9]+(\.[0-9]+)?')
    unit=$(printf '%s' "$token" | grep -oE '(ms|s|m|h|d)$')
    case "$unit" in
        ms) awk -v n="$num" 'BEGIN { printf "%d", int(n/1000) }' ;;
        m)  awk -v n="$num" 'BEGIN { printf "%d", int(n*60) }' ;;
        h)  awk -v n="$num" 'BEGIN { printf "%d", int(n*3600) }' ;;
        d)  awk -v n="$num" 'BEGIN { printf "%d", int(n*86400) }' ;;
        s|"") awk -v n="$num" 'BEGIN { printf "%d", int(n) }' ;;
        *) printf '%s' "" ; return 1 ;;
    esac
}

secaudit_bytes_from_nginx_size() {
    local raw token num unit
    raw=$(secaudit_trim_ws "${1-}")
    [ -n "$raw" ] || { printf '%s' ""; return 1; }
    token=$(printf '%s' "$raw" | grep -oiE '[0-9]+[kmg]?' | head -1)
    [ -n "$token" ] || { printf '%s' ""; return 1; }
    num=$(printf '%s' "$token" | grep -oE '^[0-9]+')
    unit=$(printf '%s' "$token" | grep -oiE '[kmg]$' | tr '[:upper:]' '[:lower:]')
    case "$unit" in
        k) awk -v n="$num" 'BEGIN { printf "%d", n*1024 }' ;;
        m) awk -v n="$num" 'BEGIN { printf "%d", n*1024*1024 }' ;;
        g) awk -v n="$num" 'BEGIN { printf "%d", n*1024*1024*1024 }' ;;
        *) printf '%s' "$num" ;;
    esac
}

secaudit_timeout_within_bound() {
    local seconds="$1" max="$2"
    [ -n "$seconds" ] || return 1
    [ "$seconds" -gt 0 ] 2>/dev/null || return 1
    [ "$seconds" -le "$max" ] 2>/dev/null
}

# --- discovery ---
secaudit_nginx_bin_path() {
    if secaudit_have_bin nginx; then
        command -v nginx
        return 0
    fi
    local candidate
    for candidate in /usr/sbin/nginx /usr/local/sbin/nginx /usr/local/nginx/sbin/nginx; do
        [ -x "$candidate" ] && { printf '%s\n' "$candidate"; return 0; }
    done
    return 1
}

secaudit_dump_compile_flags() {
    if [ -n "$_NGINX_COMPILE_FLAGS" ]; then
        printf '%s\n' "$_NGINX_COMPILE_FLAGS"
        return 0
    fi
    local bin
    bin=$(secaudit_nginx_bin_path) || return 1
    _NGINX_COMPILE_FLAGS=$("$bin" -V 2>&1)
    printf '%s\n' "$_NGINX_COMPILE_FLAGS"
}

secaudit_compile_flag_value() {
    local key="$1" line
    line=$(secaudit_dump_compile_flags 2>/dev/null | tr ' ' '\n' | grep -E "^--${key}=" | head -1)
    if [ -n "$line" ]; then
        printf '%s\n' "${line#--${key}=}" | tr -d '\r'
        return 0
    fi
    return 1
}

secaudit_nginx_process_running() {
    local pid
    if secaudit_have_bin pgrep; then
        pgrep -x nginx >/dev/null 2>&1 && return 0
        pgrep -f '[/]nginx( |$)' >/dev/null 2>&1 && return 0
    fi
    if [ -n "${_NGINX_PID_PATH:-}" ] && [ -f "$_NGINX_PID_PATH" ]; then
        pid=$(tr -d '[:space:]' < "$_NGINX_PID_PATH" 2>/dev/null)
        [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && return 0
    fi
    return 1
}

secaudit_tcp_port_is_open() {
    local port="$1"
    if secaudit_have_bin ss; then
        ss -tln 2>/dev/null | grep -qE ":${port}[[:space:]]"
        return $?
    fi
    if secaudit_have_bin netstat; then
        netstat -tln 2>/dev/null | grep -qE ":${port}[[:space:]]"
        return $?
    fi
    return 1
}

secaudit_resolve_pid_path() {
    local from_conf from_flags candidate
    from_conf=$(secaudit_collect_directive_args 'pid' | awk '{print $1}' | tr -d '"')
    if [ -n "$from_conf" ]; then
        printf '%s\n' "$from_conf"
        return 0
    fi
    from_flags=$(secaudit_compile_flag_value 'pid-path' 2>/dev/null || true)
    if [ -n "$from_flags" ]; then
        printf '%s\n' "$from_flags"
        return 0
    fi
    for candidate in /run/nginx.pid /var/run/nginx.pid /run/nginx/nginx.pid; do
        [ -e "$candidate" ] && { printf '%s\n' "$candidate"; return 0; }
    done
    printf '%s\n' "/var/run/nginx.pid"
}

secaudit_layout_probe() {
    local prefix
    prefix=$(secaudit_compile_flag_value 'prefix' 2>/dev/null || printf '%s' "/etc/nginx")
    _NGINX_CONF_ROOT="${_NGINX_CONF_ROOT:-$prefix/conf}"
    [ -d "$_NGINX_CONF_ROOT" ] || _NGINX_CONF_ROOT="/etc/nginx"

    if [ -f "${_NGINX_CONF_ROOT}/nginx.conf" ]; then
        _NGINX_PRIMARY_CONF="${_NGINX_CONF_ROOT}/nginx.conf"
    elif [ -f "${prefix}/conf/nginx.conf" ]; then
        _NGINX_PRIMARY_CONF="${prefix}/conf/nginx.conf"
        _NGINX_CONF_ROOT="${prefix}/conf"
    elif [ -f "/etc/nginx/nginx.conf" ]; then
        _NGINX_PRIMARY_CONF="/etc/nginx/nginx.conf"
        _NGINX_CONF_ROOT="/etc/nginx"
    else
        _NGINX_PRIMARY_CONF=$(secaudit_compile_flag_value 'conf-path' 2>/dev/null || printf '%s' "${_NGINX_CONF_ROOT}/nginx.conf")
        [ -n "${_NGINX_PRIMARY_CONF%/*}" ] && _NGINX_CONF_ROOT="${_NGINX_PRIMARY_CONF%/*}"
    fi

    [ -f /etc/logrotate.d/nginx ] && _NGINX_LOGROTATE="/etc/logrotate.d/nginx"

    local html
    for html in /usr/share/nginx/html /usr/share/nginx/www /var/www/html /usr/local/nginx/html; do
        if [ -d "$html" ]; then
            _NGINX_HTML_ROOT="$html"
            break
        fi
    done
}

secaudit_software_present() {
    secaudit_nginx_bin_path >/dev/null 2>&1 && return 0
    secaudit_nginx_process_running && return 0
    return 1
}

secaudit_conf_present() {
    [ -n "$_NGINX_PRIMARY_CONF" ] && [ -f "$_NGINX_PRIMARY_CONF" ] && return 0
    [ -d "${_NGINX_CONF_ROOT:-}" ] && return 0
    return 1
}

# --- query helpers / config walking ---
secaudit_expand_include_spec() {
    local origin="$1" spec="$2" candidate item
    spec=$(secaudit_trim_ws "$spec")
    spec=${spec%;}
    [ -n "$spec" ] || return 0

    case "$spec" in
        /*) candidate="$spec" ;;
        *)  candidate="$(dirname "$origin")/$spec" ;;
    esac

    if [ -f "$candidate" ]; then
        printf '%s\n' "$candidate"
        return 0
    fi
    if [ -f "${_NGINX_CONF_ROOT}/$spec" ]; then
        printf '%s\n' "${_NGINX_CONF_ROOT}/$spec"
        return 0
    fi
    if [ -d "$candidate" ]; then
        find "$candidate" -maxdepth 2 -type f \( -name '*.conf' -o -name '*.inc' \) 2>/dev/null
        return 0
    fi
    if [ -d "${_NGINX_CONF_ROOT}/$spec" ]; then
        find "${_NGINX_CONF_ROOT}/$spec" -maxdepth 2 -type f \( -name '*.conf' -o -name '*.inc' \) 2>/dev/null
        return 0
    fi
    case "$candidate" in
        *\*)
            for item in $candidate; do
                [ -f "$item" ] && printf '%s\n' "$item"
            done
            ;;
    esac
}

secaudit_supplemental_config_paths() {
    local dir extra
    for dir in \
        "${_NGINX_CONF_ROOT}/conf.d" \
        "${_NGINX_CONF_ROOT}/http.d" \
        "${_NGINX_CONF_ROOT}/stream.d" \
        "${_NGINX_CONF_ROOT}/snippets" \
        "${_NGINX_CONF_ROOT}/sites-enabled" \
        "${_NGINX_CONF_ROOT}/sites-available" \
        "${_NGINX_CONF_ROOT}/modules-enabled" \
        "${_NGINX_CONF_ROOT}/default.d"
    do
        [ -d "$dir" ] || continue
        secaudit_exec_with_timeout "$_NGINX_FIND_CAP" find "$dir" -type f \( -name '*.conf' -o -name '*.inc' \) 2>/dev/null || true
    done
    for extra in \
        "${_NGINX_CONF_ROOT}/mime.types" \
        "${_NGINX_CONF_ROOT}/fastcgi.conf" \
        "${_NGINX_CONF_ROOT}/fastcgi_params" \
        "${_NGINX_CONF_ROOT}/scgi_params" \
        "${_NGINX_CONF_ROOT}/uwsgi_params" \
        "${_NGINX_CONF_ROOT}/proxy_params"
    do
        [ -f "$extra" ] && printf '%s\n' "$extra"
    done
}

secaudit_walk_included_configs() {
    local file line spec seen="" queue="" depth=0 resolved
    queue="${_NGINX_PRIMARY_CONF}"
    while [ -n "$queue" ] && [ "$depth" -lt 80 ]; do
        depth=$((depth + 1))
        file=${queue%% *}
        queue=${queue#"$file"}
        queue=${queue# }
        [ -z "$file" ] && continue
        case " $seen " in
            *" $file "*) continue ;;
        esac
        seen="$seen $file"
        printf '%s\n' "$file"
        [ -f "$file" ] || continue
        while IFS= read -r line || [ -n "$line" ]; do
            line=${line%%#*}
            case "$line" in
                *include*)
                    spec=${line#*include}
                    spec=${spec//\"/}
                    spec=${spec//\'/}
                    spec=${spec%;*}
                    for spec in $spec; do
                        while IFS= read -r resolved; do
                            [ -n "$resolved" ] && [ -e "$resolved" ] && queue="$resolved $queue"
                        done < <(secaudit_expand_include_spec "$file" "$spec")
                    done
                    ;;
            esac
        done < "$file"
    done
    secaudit_supplemental_config_paths
}

secaudit_indexed_config_paths() {
    if [ -z "$_NGINX_CONFIG_INDEX" ]; then
        _NGINX_CONFIG_INDEX=$(secaudit_walk_included_configs | sort -u)
    fi
    printf '%s\n' "$_NGINX_CONFIG_INDEX"
}

secaudit_grep_live_config() {
    local pattern="$1" file
    while IFS= read -r file; do
        [ -f "$file" ] || continue
        secaudit_is_sample_config "$file" && continue
        grep -iE "$pattern" "$file" 2>/dev/null | grep -vE '^[[:space:]]*#' || true
    done < <(secaudit_indexed_config_paths)
    return 0
}

secaudit_collect_directive_block() {
    local name="$1" file
    while IFS= read -r file; do
        [ -f "$file" ] || continue
        secaudit_is_sample_config "$file" && continue
        awk -v name="$name" '
            BEGIN { cap=0; buf=""; lname=tolower(name) }
            {
                line=$0
                sub(/[[:space:]]*#.*/,"",line)
                if (!cap && tolower(line) ~ ("^[[:space:]]*" lname "[[:space:]]+")) cap=1
                if (cap) {
                    buf = buf " " line
                    if (line ~ /;[[:space:]]*$/) {
                        print buf
                        cap=0
                        buf=""
                    }
                }
            }
        ' "$file" 2>/dev/null
    done < <(secaudit_indexed_config_paths)
    return 0
}

secaudit_extract_location_blocks() {
    local file
    while IFS= read -r file; do
        [ -f "$file" ] || continue
        secaudit_is_sample_config "$file" && continue
        awk '
            BEGIN { depth=0; capturing=0; buf="" }
            {
                if (!capturing && $0 ~ /^[[:space:]]*location[[:space:]]/) {
                    capturing=1
                    buf=""
                    depth=0
                }
                if (capturing) {
                    buf = buf $0 "\n"
                    for (i = 1; i <= length($0); i++) {
                        c = substr($0, i, 1)
                        if (c == "{") depth++
                        else if (c == "}") depth--
                    }
                    # BusyBox awk treats bare '{' as a quantifier — escape it.
                    if (depth <= 0 && buf ~ /\{/) {
                        print buf
                        print "-----"
                        capturing=0
                        buf=""
                    }
                }
            }
        ' "$file" 2>/dev/null
    done < <(secaudit_indexed_config_paths)
}

secaudit_collect_directive_args() {
    local name="$1"
    secaudit_grep_live_config "^[[:space:]]*${name}[[:space:]]+" | \
        sed -E "s/^[[:space:]]*${name}[[:space:]]+//;s/[[:space:]]*;[[:space:]]*$//;s/[[:space:]]+$//" | \
        sort -u | tr '\n' ' '
}

secaudit_directive_is_present() {
    secaudit_collect_directive_args "$1" | grep -q '[^[:space:]]'
}

secaudit_first_directive_arg() {
    secaudit_collect_directive_args "$1" | awk '{print $1}'
}

secaudit_all_timeout_seconds_for() {
    local name="$1" raw token seconds
    raw=$(secaudit_collect_directive_args "$name")
    if [ -z "${raw// /}" ]; then
        return 0
    fi
    for token in $raw; do
        seconds=$(secaudit_seconds_from_nginx_time "$token" 2>/dev/null || true)
        [ -n "$seconds" ] && printf '%s\n' "$seconds"
    done
}

secaudit_worst_timeout_seconds() {
    local name="$1" fallback="${2:-}" value max=""
    while IFS= read -r value; do
        [ -n "$value" ] || continue
        if [ -z "$max" ] || [ "$value" -gt "$max" ] 2>/dev/null; then
            max="$value"
        fi
    done < <(secaudit_all_timeout_seconds_for "$name")
    if [ -n "$max" ]; then
        printf '%s' "$max"
    else
        printf '%s' "$fallback"
    fi
}

secaudit_smallest_timeout_seconds() {
    local name="$1" fallback="${2:-}" value min=""
    while IFS= read -r value; do
        [ -n "$value" ] || continue
        if [ -z "$min" ] || [ "$value" -lt "$min" ] 2>/dev/null; then
            min="$value"
        fi
    done < <(secaudit_all_timeout_seconds_for "$name")
    if [ -n "$min" ]; then
        printf '%s' "$min"
    else
        printf '%s' "$fallback"
    fi
}

secaudit_resolve_worker_account() {
    local account
    account=$(secaudit_grep_live_config '^[[:space:]]*user[[:space:]]+' | head -1 | awk '{print $2}' | tr -d ';')
    if [ -n "$account" ] && [ "$account" != "root" ]; then
        printf '%s\n' "$account"
        return 0
    fi
    account=$(ps -eo user=,comm= 2>/dev/null | awk '$2 ~ /^nginx$/ && $1 != "root" {print $1; exit}')
    if [ -z "$account" ]; then
        account=$(ps -eo user=,args= 2>/dev/null | awk '/\/(s)?bin\/nginx/ && $0 !~ /grep|nginx/ { if ($1 != "root") { print $1; exit } }')
    fi
    [ -n "$account" ] && { printf '%s\n' "$account"; return 0; }
    printf '%s\n' "nginx"
}

secaudit_passwd_record_for() {
    local account="$1"
    getent passwd "$account" 2>/dev/null || \
    grep "^${account}:" /etc/passwd 2>/dev/null || \
    { [ -n "${NSS_WRAPPER_PASSWD:-}" ] && [ -f "$NSS_WRAPPER_PASSWD" ] && \
      grep "^${account}:" "$NSS_WRAPPER_PASSWD" 2>/dev/null; }
}

secaudit_shadow_record_for() {
    local account="$1"
    if [ -r /etc/shadow ]; then
        grep "^${account}:" /etc/shadow 2>/dev/null
    fi
}

secaudit_tls_listener_configured() {
    if secaudit_grep_live_config '^[[:space:]]*listen[[:space:]]+.*ssl' | grep -q .; then
        return 0
    fi
    secaudit_ssl_certificate_paths | grep -q .
}

secaudit_reverse_proxy_configured() {
    secaudit_grep_live_config '^[[:space:]]*proxy_pass[[:space:]]+' | grep -q .
}

secaudit_https_upstream_configured() {
    secaudit_grep_live_config 'proxy_pass[[:space:]]+https://' | grep -q .
}

secaudit_ssl_certificate_paths() {
    secaudit_grep_live_config 'ssl_certificate[[:space:]]' | grep -vi 'ssl_certificate_key' | \
        sed -E 's/.*ssl_certificate[[:space:]]+([^;[:space:]]+).*/\1/' | \
        tr -d '"' | sort -u || true
}

secaudit_ssl_private_key_paths() {
    secaudit_grep_live_config 'ssl_certificate_key' | \
        sed -E 's/.*ssl_certificate_key[[:space:]]+([^;[:space:]]+).*/\1/' | \
        tr -d '"' | sort -u || true
}

secaudit_listen_endpoint_ports() {
    local line token port
    while IFS= read -r line; do
        line=$(secaudit_trim_ws "${line%%#*}")
        token=$(printf '%s' "$line" | awk '{print $2}' | tr -d ';')
        case "$token" in
            unix:*|*.sock) continue ;;
            \[[0-9a-fA-F:]*\]:*)
                port=${token##*:}
                ;;
            *:*)
                port=${token##*:}
                ;;
            [0-9]*)
                port=$token
                ;;
            *)
                port=80
                ;;
        esac
        port=$(printf '%s' "$port" | grep -oE '^[0-9]+')
        [ -n "$port" ] && printf '%s\n' "$port"
    done < <(secaudit_grep_live_config '^[[:space:]]*listen[[:space:]]+') | sort -un
}

secaudit_collect_add_header() {
    local header="$1"
    secaudit_grep_live_config "add_header[[:space:]]+${header}" | \
        sed -E "s/.*add_header[[:space:]]+${header}[[:space:]]+//" | \
        sed -E 's/;[[:space:]]*$//' | tr -d '"' | sort -u
}

secaudit_add_header_values_only() {
    local header="$1"
    secaudit_collect_add_header "$header" | sed -E 's/[[:space:]]+always[[:space:]]*$//' | \
        tr '\n' ' '
}

secaudit_add_header_has_always() {
    local header="$1"
    secaudit_collect_add_header "$header" | grep -qiE '[[:space:]]always[[:space:]]*$'
}

secaudit_probe_http_status() {
    local scheme="$1" port="$2" host="$3"
    secaudit_have_bin curl || return 1
    secaudit_exec_with_timeout "$_NGINX_CURL_CAP" curl -sk -o /dev/null -w '%{http_code}' \
        --connect-timeout 3 --max-time 5 \
        -H "Host: ${host}" "${scheme}://127.0.0.1:${port}/" 2>/dev/null
}

secaudit_probe_response_header() {
    local scheme="$1" port="$2" header="$3"
    secaudit_have_bin curl || return 1
    secaudit_exec_with_timeout "$_NGINX_CURL_CAP" curl -skI --connect-timeout 3 --max-time 5 \
        "${scheme}://127.0.0.1:${port}/" 2>/dev/null | \
        grep -i "^${header}:" | head -1 | cut -d: -f2- | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

secaudit_port_is_authorized() {
    local port="$1" allowed
    for allowed in $_NGINX_AUTHORIZED_HTTP_PORTS; do
        [ "$port" = "$allowed" ] && return 0
    done
    return 1
}

secaudit_shell_is_nologin() {
    local shell="$1"
    printf '%s' "$shell" | grep -qiE 'nologin|false|/dev/null'
}

secaudit_autoindex_hits_in_file() {
    local file="$1"
    [ -f "$file" ] || return 0
    grep -iE '^[[:space:]]*autoindex[[:space:]]+' "$file" 2>/dev/null | \
        grep -vE '^[[:space:]]*#' | grep -viE 'autoindex[[:space:]]+off'
}

secaudit_default_page_hits() {
    local file="$1"
    [ -f "$file" ] || return 0
    grep -iE 'nginx|welcome to nginx|openresty' "$file" 2>/dev/null
}

secaudit_ssl_protocols_text() {
    secaudit_grep_live_config '^[[:space:]]*ssl_protocols[[:space:]]+' | tr '\n' ' '
}

secaudit_weak_cipher_tokens() {
    printf '%s' "$1" | grep -qiE 'RC4|MD5|NULL|EXPORT|aNULL|eNULL|ADH|LOW|DES|3DES|PSK|SRP|CAMELLIA|SEED|IDEA|DSS'
}

# --- checks ---
secaudit_check_webdav_absent() {
    local num="$1"
    local build hits=""
    build=$(secaudit_dump_compile_flags 2>/dev/null || true)
    printf '%s' "$build" | grep -q 'http_dav_module' && hits="${hits} compile:http_dav_module"
    printf '%s' "$build" | grep -q 'http_dav_ext_module' && hits="${hits} compile:http_dav_ext_module"
    secaudit_grep_live_config 'load_module[[:space:]]+.*dav' | grep -q . && hits="${hits} load_module:dav"
    secaudit_grep_live_config '^[[:space:]]*dav_methods[[:space:]]+' | grep -q . && hits="${hits} dav_methods"
    secaudit_grep_live_config '^[[:space:]]*dav_access[[:space:]]+' | grep -q . && hits="${hits} dav_access"
    secaudit_grep_live_config '^[[:space:]]*create_full_put_path[[:space:]]+' | grep -q . && hits="${hits} create_full_put_path"
    if [ -n "$hits" ]; then
        secaudit_report_fail "$num" "WebDAV capability is present (${hits# })"
    else
        secaudit_report_pass "$num" "WebDAV module and dav_* directives are absent"
    fi
}

secaudit_check_gzip_disabled() {
    local num="$1"
    local build mods="" runtime=""
    build=$(secaudit_dump_compile_flags 2>/dev/null || true)
    mods=$(printf '%s' "$build" | grep -oE 'http_gzip_module|http_gzip_static_module' | sort -u | tr '\n' ' ')
    secaudit_grep_live_config '^[[:space:]]*gzip[[:space:]]+on' | grep -q . && runtime="${runtime} gzip:on"
    secaudit_grep_live_config '^[[:space:]]*gzip_static[[:space:]]+on' | grep -q . && runtime="${runtime} gzip_static:on"
    secaudit_grep_live_config 'load_module[[:space:]]+.*gzip' | grep -q . && runtime="${runtime} load_module:gzip"
    if [ -n "${mods// /}" ] || [ -n "$runtime" ]; then
        secaudit_report_fail "$num" "gzip compression is available (build=${mods:-none} runtime=${runtime:-none})"
    else
        secaudit_report_pass "$num" "gzip modules are not compiled in and gzip is not enabled"
    fi
}

secaudit_check_autoindex_scope() {
    local num="$1" scope="$2"
    local hits="" file
    if [ "$scope" = "main" ]; then
        hits=$(secaudit_autoindex_hits_in_file "$_NGINX_PRIMARY_CONF" | tr '\n' ' ')
    else
        while IFS= read -r file; do
            [ "$file" = "$_NGINX_PRIMARY_CONF" ] && continue
            secaudit_is_sample_config "$file" && continue
            hits="${hits} $(secaudit_autoindex_hits_in_file "$file" | tr '\n' ' ')"
        done < <(secaudit_indexed_config_paths)
    fi
    hits=$(secaudit_squash_ws "$hits")
    if [ -n "$hits" ]; then
        secaudit_report_fail "$num" "autoindex is enabled in ${scope} (${hits})"
    else
        secaudit_report_pass "$num" "autoindex is disabled in ${scope}"
    fi
}

secaudit_check_service_account_no_sudo() {
    local num="$1"
    local account="$_NGINX_SVC_ACCOUNT" listing="" sudoers=""
    if ! secaudit_have_bin sudo; then
        secaudit_report_pass "$num" "sudo is not installed; ${account} cannot escalate via sudo"
        return 0
    fi
    listing=$(secaudit_exec_with_timeout "$_NGINX_SUDO_CAP" sudo -n -l -U "$account" 2>/dev/null | \
        grep -Ev 'is not allowed to run sudo|may not run sudo' | tr '\n' ' ')
    if [ -r /etc/sudoers ]; then
        sudoers=$(grep -E "^[[:space:]]*${account}[[:space:]]|^[[:space:]]*%(nginx|www-data)[[:space:]]" /etc/sudoers /etc/sudoers.d/* 2>/dev/null | \
            grep -vE '^[[:space:]]*#' | tr '\n' ' ')
    fi
    if [ -z "${listing// /}" ] && [ -z "${sudoers// /}" ]; then
        secaudit_report_pass "$num" "${account} has no sudo privileges"
    else
        secaudit_report_fail "$num" "${account} has sudo rights (${listing} ${sudoers})"
    fi
}

secaudit_check_dedicated_worker_account() {
    local num="$1"
    local account="$_NGINX_SVC_ACCOUNT" record uid gid gname groups_out extra=""
    if [ -z "$account" ] || [ "$account" = "root" ]; then
        secaudit_report_fail "$num" "worker account is '${account:-unset}' (dedicated non-root account required)"
        return 0
    fi
    record=$(secaudit_passwd_record_for "$account")
    if [ -z "$record" ]; then
        secaudit_report_fail "$num" "worker account '${account}' is missing from passwd"
        return 0
    fi
    uid=$(printf '%s' "$record" | cut -d: -f3)
    gid=$(printf '%s' "$record" | cut -d: -f4)
    if [ "$uid" = "0" ]; then
        secaudit_report_fail "$num" "worker account '${account}' has uid=0"
        return 0
    fi
    groups_out=$(groups "$account" 2>/dev/null)
    gname=$(getent group "$gid" 2>/dev/null | cut -d: -f1)
    local g
    for g in $_NGINX_PRIVILEGED_GROUPS; do
        printf '%s' "$groups_out" | grep -qw "$g" && extra="${extra} ${g}"
    done
    if [ -n "$extra" ]; then
        secaudit_report_fail "$num" "worker '${account}' belongs to privileged groups (${extra# }) [${groups_out}]"
        return 0
    fi
    if [ -n "$groups_out" ] || [ -n "$gname" ]; then
        secaudit_report_pass "$num" "dedicated worker '${account}' uid=${uid} groups=${groups_out:-$gname}"
    else
        secaudit_report_fail "$num" "worker '${account}' exists but group membership is unknown (gid=${gid})"
    fi
}

secaudit_check_service_account_locked() {
    local num="$1"
    local account="$_NGINX_SVC_ACCOUNT" status hash shell record
    status=$(passwd -S "$account" 2>/dev/null | awk '{print $2}')
    case "$status" in
        L|LK|NL)
            secaudit_report_pass "$num" "${account} is locked (passwd -S ${status})"
            return 0
            ;;
    esac
    hash=$(secaudit_shadow_record_for "$account" | cut -d: -f2)
    case "$hash" in
        '!'*|'*'|!!*)
            secaudit_report_pass "$num" "${account} is locked in shadow (hash prefix)"
            return 0
            ;;
    esac
    record=$(secaudit_passwd_record_for "$account")
    shell=$(printf '%s' "$record" | cut -d: -f7)
    if secaudit_shell_is_nologin "$shell" && { [ -z "$hash" ] || [ "$hash" = "!" ] || [ "$hash" = "*" ]; }; then
        secaudit_report_pass "$num" "${account} cannot authenticate (nologin shell ${shell})"
    else
        secaudit_report_fail "$num" "${account} is not locked (passwd=${status:-unknown} shadow=${hash:-n/a} shell=${shell:-n/a})"
    fi
}

secaudit_check_service_account_nologin_shell() {
    local num="$1"
    local account="$_NGINX_SVC_ACCOUNT" record shell
    record=$(secaudit_passwd_record_for "$account")
    shell=$(printf '%s' "$record" | cut -d: -f7)
    if ! secaudit_shell_is_nologin "$shell"; then
        secaudit_report_fail "$num" "${account} has a login shell (${shell:-unknown})"
        return 0
    fi
    if [ -f /etc/shells ] && grep -qx "$shell" /etc/shells 2>/dev/null; then
        if printf '%s' "$shell" | grep -qi nologin; then
            secaudit_report_pass "$num" "${account} shell is ${shell} (nologin listed in /etc/shells)"
        else
            secaudit_report_fail "$num" "${account} shell ${shell} is present in /etc/shells"
        fi
        return 0
    fi
    secaudit_report_pass "$num" "${account} has non-login shell (${shell})"
}

secaudit_check_config_tree_ownership() {
    local num="$1"
    local bad="" path owner group
    if [ ! -d "$_NGINX_CONF_ROOT" ]; then
        secaudit_report_fail "$num" "configuration root '${_NGINX_CONF_ROOT}' is missing"
        return 0
    fi
    owner=$(secaudit_path_owner_user "$_NGINX_CONF_ROOT")
    group=$(secaudit_path_owner_group "$_NGINX_CONF_ROOT")
    if [ "$owner" != "root" ]; then
        secaudit_report_fail "$num" "${_NGINX_CONF_ROOT} owner is '${owner:-unknown}' (expected root)"
        return 0
    fi
    while IFS= read -r path; do
        [ -e "$path" ] || continue
        owner=$(secaudit_path_owner_user "$path")
        group=$(secaudit_path_owner_group "$path")
        if [ "$owner" != "root" ] || { [ -n "$group" ] && [ "$group" != "root" ]; }; then
            bad="${bad} ${path}:${owner}:${group}"
        fi
    done < <(secaudit_exec_with_timeout "$_NGINX_FIND_CAP" find "$_NGINX_CONF_ROOT" \( -type f -o -type d \) 2>/dev/null | head -200)
    if [ -n "$bad" ]; then
        secaudit_report_fail "$num" "non-root ownership in config tree (${bad# })"
    else
        secaudit_report_pass "$num" "${_NGINX_CONF_ROOT} and nested objects are owned by root:root"
    fi
}

secaudit_check_config_dir_permissions() {
    local num="$1"
    local violations="" path mode
    if [ ! -d "$_NGINX_CONF_ROOT" ]; then
        secaudit_report_fail "$num" "${_NGINX_CONF_ROOT} is missing"
        return 0
    fi
    while IFS= read -r path; do
        [ -d "$path" ] || continue
        mode=$(secaudit_path_mode_octal "$path")
        violations="${violations} ${mode}:${path}"
    done < <(secaudit_exec_with_timeout "$_NGINX_FIND_CAP" find "$_NGINX_CONF_ROOT" -type d -perm /007 2>/dev/null | head -50)
    if [ -n "$violations" ]; then
        secaudit_report_fail "$num" "directories allow other access (${violations# })"
    else
        secaudit_report_pass "$num" "config directories deny other rwx (o=0)"
    fi
}

secaudit_check_config_file_permissions() {
    local num="$1"
    local violations="" path mode
    if [ ! -d "$_NGINX_CONF_ROOT" ]; then
        secaudit_report_fail "$num" "${_NGINX_CONF_ROOT} is missing"
        return 0
    fi
    while IFS= read -r path; do
        [ -f "$path" ] || continue
        mode=$(secaudit_path_mode_octal "$path")
        violations="${violations} ${mode}:${path}"
    done < <(secaudit_exec_with_timeout "$_NGINX_FIND_CAP" find "$_NGINX_CONF_ROOT" -type f -perm /007 2>/dev/null | head -50)
    if [ -n "$violations" ]; then
        secaudit_report_fail "$num" "config files allow other access (${violations# })"
    else
        secaudit_report_pass "$num" "config files deny other rwx (o=0)"
    fi
}

secaudit_check_pid_file_mode() {
    local num="$1"
    local mode info parent pmode
    if [ ! -e "$_NGINX_PID_PATH" ]; then
        if secaudit_nginx_process_running; then
            secaudit_report_fail "$num" "PID file '${_NGINX_PID_PATH}' is missing while nginx is running"
        else
            secaudit_report_fail "$num" "PID file '${_NGINX_PID_PATH}' is missing"
        fi
        return 0
    fi
    mode=$(secaudit_path_mode_octal "$_NGINX_PID_PATH")
    info=$(secaudit_path_listing "$_NGINX_PID_PATH")
    parent=$(dirname "$_NGINX_PID_PATH")
    pmode=$(secaudit_path_mode_octal "$parent")
    case "$mode" in
        400|440|600|640|644)
            if [ -n "$pmode" ] && [ "$pmode" != "MISSING" ] && [ $((8#$pmode & 8#002)) -ne 0 ] 2>/dev/null; then
                secaudit_report_fail "$num" "PID file mode=${mode} but parent '${parent}' is world-writable (${pmode})"
            else
                secaudit_report_pass "$num" "PID file permissions are restricted (mode=${mode} parent=${pmode} ${info})"
            fi
            ;;
        *)
            secaudit_report_fail "$num" "PID file permissions are too open (mode=${mode:-unknown} ${info})"
            ;;
    esac
}

secaudit_check_pid_file_owner() {
    local num="$1"
    local owner group info
    if [ ! -e "$_NGINX_PID_PATH" ]; then
        if secaudit_nginx_process_running; then
            secaudit_report_fail "$num" "PID file '${_NGINX_PID_PATH}' is missing while nginx is running"
        else
            secaudit_report_fail "$num" "PID file '${_NGINX_PID_PATH}' is missing"
        fi
        return 0
    fi
    owner=$(secaudit_path_owner_user "$_NGINX_PID_PATH")
    group=$(secaudit_path_owner_group "$_NGINX_PID_PATH")
    info=$(secaudit_path_listing "$_NGINX_PID_PATH")
    if [ "$owner" = "root" ] && { [ "$group" = "root" ] || [ -z "$group" ]; }; then
        secaudit_report_pass "$num" "PID file is owned by root (${owner}:${group} ${info})"
    elif [ "$owner" = "root" ]; then
        secaudit_report_pass "$num" "PID file owner is root (${owner}:${group} ${info})"
    else
        secaudit_report_fail "$num" "PID file owner is '${owner:-unknown}' (expected root) (${info})"
    fi
}

secaudit_check_authorized_listen_ports() {
    local num="$1"
    local ports="" port bad="" live=""
    while IFS= read -r port; do
        [ -n "$port" ] || continue
        ports="${ports}${port} "
        secaudit_port_is_authorized "$port" || bad="${bad} ${port}"
    done < <(secaudit_listen_endpoint_ports)
    if [ -z "${ports// /}" ]; then
        secaudit_report_fail "$num" "No listen directives found"
        return 0
    fi
    if secaudit_nginx_process_running && { secaudit_have_bin ss || secaudit_have_bin netstat; }; then
        for port in 80 443 8080 8000 8443 8888; do
            if secaudit_tcp_port_is_open "$port"; then
                live="${live}${port} "
                secaudit_port_is_authorized "$port" || bad="${bad} live:${port}"
            fi
        done
    fi
    if [ -z "$bad" ]; then
        secaudit_report_pass "$num" "Listen uses authorized ports only (config=${ports} live=${live:-n/a})"
    else
        secaudit_report_fail "$num" "Unauthorized listen ports (${bad# }) config=(${ports}) live=(${live})"
    fi
}

secaudit_check_unknown_host_rejected() {
    local num="$1"
    local scheme port code codes="" bad="" reachable=0 host
    local hosts="invalid.audit.invalid not-a-real-vhost.example"
    if ! secaudit_have_bin curl; then
        secaudit_report_fail "$num" "Unable to verify unknown host rejection (curl is missing)"
        return 0
    fi
    for scheme in http https; do
        port=80
        [ "$scheme" = "https" ] && port=443
        if [ "$scheme" = "https" ] && ! secaudit_tls_listener_configured && ! secaudit_tcp_port_is_open 443; then
            continue
        fi
        for host in $hosts; do
            code=$(secaudit_probe_http_status "$scheme" "$port" "$host")
            case "$code" in
                000|"")
                    continue
                    ;;
                *)
                    reachable=1
                    codes="${codes}${scheme}:${host}:${code} "
                    case "$code" in
                        200|301|302|303|307|308) bad="${bad} ${scheme}:${host}:${code}" ;;
                    esac
                    ;;
            esac
        done
    done
    if [ "$reachable" -eq 0 ]; then
        secaudit_report_fail "$num" "Unable to verify unknown host rejection (service unreachable on 80/443)"
    elif [ -n "$bad" ]; then
        secaudit_report_fail "$num" "Unknown host accepted (${bad# }) samples=${codes}"
    else
        secaudit_report_pass "$num" "Unknown host rejected (samples=${codes})"
    fi
}

secaudit_check_catchall_vhost() {
    local num="$1"
    local default_listen reject_action named_catch
    default_listen=$(secaudit_grep_live_config 'listen[[:space:]]+.*default_server' | tr '\n' ' ')
    reject_action=$(secaudit_grep_live_config 'return[[:space:]]+(444|403|421|close)' | tr '\n' ' ')
    named_catch=$(secaudit_grep_live_config 'server_name[[:space:]]+_([;[:space:]]|$)' | tr '\n' ' ')
    if [ -n "${default_listen// /}" ] && { [ -n "${reject_action// /}" ] || [ -n "${named_catch// /}" ]; }; then
        secaudit_report_pass "$num" "Catch-all default_server with reject is configured"
    elif [ -n "${reject_action// /}" ] && [ -n "${named_catch// /}" ]; then
        secaudit_report_pass "$num" "Catch-all server_name _ with reject is configured"
    else
        secaudit_report_fail "$num" "Catch-all default_server + return 444/403 not detected (listen='${default_listen}' return='${reject_action}' name='${named_catch}')"
    fi
}

secaudit_check_timeout_cap() {
    local num="$1" directive="$2" op="$3" limit="$4"
    local values="" worst smallest raw
    raw=$(secaudit_collect_directive_args "$directive")
    worst=$(secaudit_worst_timeout_seconds "$directive" "")
    smallest=$(secaudit_smallest_timeout_seconds "$directive" "")
    values=$(secaudit_all_timeout_seconds_for "$directive" | tr '\n' ' ')
    if [ -z "${raw// /}" ]; then
        secaudit_report_fail "$num" "${directive} is not set (nginx default exceeds the ${limit}s cap)"
        return 0
    fi
    case "$op" in
        le)
            if [ -n "$worst" ] && [ "$worst" -gt 0 ] 2>/dev/null && [ "$worst" -le "$limit" ] 2>/dev/null && \
               [ -n "$smallest" ] && [ "$smallest" -gt 0 ] 2>/dev/null; then
                secaudit_report_pass "$num" "${directive} values=(${values}) all within 1..${limit}s"
            else
                secaudit_report_fail "$num" "${directive} values=(${values:-${raw}}) required in 1..${limit}s"
            fi
            ;;
        gt)
            if [ -n "$smallest" ] && [ "$smallest" -gt "$limit" ] 2>/dev/null; then
                secaudit_report_pass "$num" "${directive} values=(${values}) all >${limit}"
            else
                secaudit_report_fail "$num" "${directive} values=(${values:-${raw}}) must be >${limit}"
            fi
            ;;
    esac
}

secaudit_check_server_tokens_hidden() {
    local num="$1"
    local cfg http_hdr https_hdr leak=""
    cfg=$(secaudit_collect_directive_args 'server_tokens')
    if secaudit_tcp_port_is_open 80; then
        http_hdr=$(secaudit_probe_response_header http 80 Server 2>/dev/null)
        [ -z "$http_hdr" ] && http_hdr="(empty)"
    else
        http_hdr="unreachable"
    fi
    if secaudit_tls_listener_configured && secaudit_tcp_port_is_open 443; then
        https_hdr=$(secaudit_probe_response_header https 443 Server 2>/dev/null)
        [ -z "$https_hdr" ] && https_hdr="(empty)"
    elif secaudit_tls_listener_configured; then
        https_hdr="unreachable"
    else
        https_hdr="n/a"
    fi
    printf '%s' "$http_hdr $https_hdr" | grep -qE 'nginx/[0-9]|angie/[0-9]' && leak="version-in-header"
    if echo "$cfg" | grep -qi 'off' && [ -z "$leak" ]; then
        secaudit_report_pass "$num" "server_tokens off (${cfg}) Server-http='${http_hdr}' Server-https='${https_hdr}'"
    elif echo "$cfg" | grep -qi 'off'; then
        secaudit_report_fail "$num" "server_tokens off in config but Server header leaks version (${http_hdr} / ${https_hdr})"
    else
        secaudit_report_fail "$num" "server_tokens not off (${cfg:-unset}) Server-http='${http_hdr}' Server-https='${https_hdr}'"
    fi
}

secaudit_check_default_page_clean() {
    local num="$1" file="$2"
    local hits
    hits=$(secaudit_default_page_hits "$file" | tr '\n' ' ')
    if [ ! -f "$file" ]; then
        secaudit_report_pass "$num" "${file} is absent (no default branded content)"
    elif [ -z "$hits" ]; then
        secaudit_report_pass "$num" "${file} does not reference NGINX"
    else
        secaudit_report_fail "$num" "${file} references NGINX (${hits})"
    fi
}

secaudit_check_hidden_dotfiles_denied() {
    local num="$1"
    local block hits=""
    while IFS= read -r block; do
        [ -n "$block" ] || continue
        printf '%s' "$block" | grep -qiE 'location[[:space:]]+~[*]?[[:space:]].*(\\.|/\\.)' || continue
        if printf '%s' "$block" | grep -qiE 'deny[[:space:]]+all|return[[:space:]]+(403|404|444)'; then
            hits="${hits} $(printf '%s' "$block" | head -1)"
        fi
    done < <(secaudit_extract_location_blocks | awk 'BEGIN{RS="-----\n"} {gsub(/\n/," "); if ($0 ~ /location/) print}')
    hits=$(secaudit_squash_ws "$hits")
    if [ -n "$hits" ]; then
        secaudit_report_pass "$num" "Hidden-file location is denied (${hits})"
    else
        secaudit_report_fail "$num" "No location block denying hidden files (location ~ /\\. with deny all/return 403)"
    fi
}

secaudit_check_proxy_header_stripped() {
    local num="$1" header="$2"
    if ! secaudit_reverse_proxy_configured; then
        secaudit_report_pass "$num" "Not applicable (reverse proxy not configured)"
        return 0
    fi
    if secaudit_grep_live_config "proxy_hide_header[[:space:]]+${header}" | grep -q . || \
       secaudit_grep_live_config "more_clear_headers[[:space:]]+.*${header}" | grep -q .; then
        secaudit_report_pass "$num" "upstream ${header} is stripped (proxy_hide_header/more_clear_headers)"
    else
        secaudit_report_fail "$num" "proxy_hide_header ${header} is not configured"
    fi
}

secaudit_check_verbose_log_format() {
    local num="$1"
    local fmt missing=""
    fmt=$(secaudit_collect_directive_block 'log_format' | grep -i 'log_format[[:space:]]\+main' | tr '\n' ' ')
    if [ -z "${fmt// /}" ]; then
        secaudit_report_fail "$num" "log_format main is not configured"
        return 0
    fi
    printf '%s' "$fmt" | grep -q '\$remote_addr' || missing="${missing} \$remote_addr"
    printf '%s' "$fmt" | grep -qE '\$time_local|\$time_iso8601' || missing="${missing} \$time_local"
    printf '%s' "$fmt" | grep -q '\$request' || missing="${missing} \$request"
    printf '%s' "$fmt" | grep -q '\$status' || missing="${missing} \$status"
    printf '%s' "$fmt" | grep -qE '\$body_bytes_sent|\$bytes_sent' || missing="${missing} \$body_bytes_sent"
    printf '%s' "$fmt" | grep -q '\$http_user_agent' || missing="${missing} \$http_user_agent"
    if [ -n "$missing" ]; then
        secaudit_report_fail "$num" "log_format main lacks forensic fields (${missing# })"
    else
        secaudit_report_pass "$num" "log_format main includes remote_addr, time, request, status, bytes, user_agent"
    fi
}

secaudit_check_access_log_enabled() {
    local num="$1"
    local values dest_hits
    values=$(secaudit_collect_directive_args 'access_log')
    if [ -z "${values// /}" ]; then
        secaudit_report_fail "$num" "access_log is not configured"
        return 0
    fi
    dest_hits=$(printf '%s' "$values" | tr ' ' '\n' | grep -cE '/|syslog:' || true)
    if printf '%s' "$values" | grep -qw 'off' && [ "${dest_hits:-0}" -eq 0 ]; then
        secaudit_report_fail "$num" "access_log is disabled (off)"
    else
        secaudit_report_pass "$num" "access_log enabled (${values})"
    fi
}

secaudit_check_error_log_info() {
    local num="$1"
    local values
    values=$(secaudit_collect_directive_args 'error_log')
    if [ -z "${values// /}" ]; then
        secaudit_report_fail "$num" "error_log is not configured"
        return 0
    fi
    if echo "$values" | grep -qiE '(^|[[:space:]])(info|debug)([[:space:];]|$)'; then
        secaudit_report_pass "$num" "error_log is at info/debug (${values})"
    elif echo "$values" | grep -qiE '(^|[[:space:]])(notice|warn|error|crit|alert|emerg)([[:space:];]|$)'; then
        secaudit_report_fail "$num" "error_log level is below info (${values})"
    else
        secaudit_report_fail "$num" "error_log is configured but info level is not set (${values})"
    fi
}

secaudit_check_logrotate_period() {
    local num="$1"
    if [ ! -f "$_NGINX_LOGROTATE" ] || [ ! -s "$_NGINX_LOGROTATE" ]; then
        secaudit_report_fail "$num" "nginx logrotate configuration is missing (${_NGINX_LOGROTATE})"
        return 0
    fi
    if grep -E '^[[:space:]]*(daily|weekly)[[:space:]]*$' "$_NGINX_LOGROTATE" 2>/dev/null | grep -q .; then
        secaudit_report_pass "$num" "logrotate period is daily/weekly"
    else
        secaudit_report_fail "$num" "logrotate daily/weekly not found in ${_NGINX_LOGROTATE}"
    fi
}

secaudit_check_logrotate_count() {
    local num="$1"
    local rotate_n extras=""
    if [ ! -f "$_NGINX_LOGROTATE" ] || [ ! -s "$_NGINX_LOGROTATE" ]; then
        secaudit_report_fail "$num" "nginx logrotate configuration is missing (${_NGINX_LOGROTATE})"
        return 0
    fi
    rotate_n=$(grep -E '^[[:space:]]*rotate[[:space:]]+[0-9]+' "$_NGINX_LOGROTATE" 2>/dev/null | grep -vE '^[[:space:]]*#' | awk '{print $2}' | head -1)
    grep -qE '^[[:space:]]*compress' "$_NGINX_LOGROTATE" 2>/dev/null && extras="${extras} compress"
    grep -qE '^[[:space:]]*missingok' "$_NGINX_LOGROTATE" 2>/dev/null && extras="${extras} missingok"
    grep -qE 'nginx[[:space:]]+-s[[:space:]]+reload|kill[[:space:]].*USR1' "$_NGINX_LOGROTATE" 2>/dev/null && extras="${extras} postrotate"
    if [ -n "$rotate_n" ] && [ "$rotate_n" -ge 1 ] 2>/dev/null; then
        secaudit_report_pass "$num" "logrotate rotate=${rotate_n} extras=${extras:-none}"
    else
        secaudit_report_fail "$num" "logrotate rotate count is missing"
    fi
}

secaudit_check_remote_syslog() {
    local num="$1" directive="$2"
    local hits
    hits=$(secaudit_grep_live_config "^[[:space:]]*${directive}[[:space:]]+syslog:" | tr '\n' ' ')
    if [ -z "${hits// /}" ]; then
        hits=$(secaudit_grep_live_config "^[[:space:]]*${directive}[[:space:]]+syslog" | tr '\n' ' ')
    fi
    if echo "$hits" | grep -qi 'syslog'; then
        if echo "$hits" | grep -qiE 'server='; then
            secaudit_report_pass "$num" "${directive} is sent to syslog (${hits})"
        else
            secaudit_report_pass "$num" "${directive} syslog destination is configured (${hits})"
        fi
    else
        secaudit_report_fail "$num" "${directive} syslog is not configured"
    fi
}

secaudit_check_proxy_source_ip() {
    local num="$1" kind="$2"
    if ! secaudit_reverse_proxy_configured; then
        secaudit_report_pass "$num" "Not applicable (reverse proxy not configured)"
        return 0
    fi
    case "$kind" in
        proxy_pass)
            secaudit_report_pass "$num" "reverse proxy upstream routing is configured"
            ;;
        x-real-ip)
            if secaudit_grep_live_config 'proxy_set_header[[:space:]]+X-Real-IP[[:space:]]+\$remote_addr' | grep -q .; then
                secaudit_report_pass "$num" "X-Real-IP is set from \$remote_addr"
            elif secaudit_grep_live_config 'proxy_set_header[[:space:]]+X-Real-IP' | grep -q .; then
                secaudit_report_pass "$num" "X-Real-IP header is forwarded"
            else
                secaudit_report_fail "$num" "X-Real-IP header is not configured"
            fi
            ;;
        x-forwarded-for)
            if secaudit_grep_live_config 'proxy_set_header[[:space:]]+X-Forwarded-For[[:space:]]+(\$proxy_add_x_forwarded_for|\$remote_addr)' | grep -q .; then
                secaudit_report_pass "$num" "X-Forwarded-For is set from client address chain"
            elif secaudit_grep_live_config 'proxy_set_header[[:space:]]+X-Forwarded-For' | grep -q .; then
                secaudit_report_pass "$num" "X-Forwarded-For header is forwarded"
            else
                secaudit_report_fail "$num" "X-Forwarded-For header is not configured"
            fi
            ;;
    esac
}

secaudit_check_certificate_chain() {
    local num="$1"
    local cert leftover expired=0 invalid=0 missing=0 chain_ok=0 detail="" subj not_after
    if ! secaudit_tls_listener_configured; then
        secaudit_report_pass "$num" "Not applicable (HTTPS not configured)"
        return 0
    fi
    leftover=$(secaudit_ssl_certificate_paths)
    if [ -z "${leftover}" ]; then
        secaudit_report_fail "$num" "ssl_certificate is not configured"
        return 0
    fi
    while IFS= read -r cert; do
        [ -n "$cert" ] || continue
        if [ ! -r "$cert" ]; then
            missing=$((missing + 1))
            detail="${detail} unreadable:${cert}"
            continue
        fi
        if ! secaudit_have_bin openssl; then
            if grep -q 'BEGIN CERTIFICATE' "$cert" 2>/dev/null; then
                chain_ok=$((chain_ok + 1))
                detail="${detail} pem:${cert}"
            else
                invalid=$((invalid + 1))
                detail="${detail} not-pem:${cert}"
            fi
            continue
        fi
        if ! openssl x509 -in "$cert" -noout -subject >/dev/null 2>&1; then
            invalid=$((invalid + 1))
            detail="${detail} invalid:${cert}"
            continue
        fi
        if ! openssl x509 -in "$cert" -noout -checkend 0 >/dev/null 2>&1; then
            expired=$((expired + 1))
            not_after=$(openssl x509 -in "$cert" -noout -enddate 2>/dev/null | cut -d= -f2)
            detail="${detail} expired:${cert}(${not_after})"
            continue
        fi
        subj=$(openssl x509 -in "$cert" -noout -subject 2>/dev/null)
        chain_ok=$((chain_ok + 1))
        detail="${detail} ok:${cert}(${subj})"
    done <<EOF
${leftover}
EOF
    if [ "$expired" -gt 0 ] || [ "$invalid" -gt 0 ] || [ "$missing" -gt 0 ] || [ "$chain_ok" -eq 0 ]; then
        secaudit_report_fail "$num" "TLS certificate problem (ok=${chain_ok} expired=${expired} invalid=${invalid} missing=${missing}${detail})"
    else
        secaudit_report_pass "$num" "ssl_certificate files are valid and unexpired (${detail# })"
    fi
}

secaudit_check_private_key_hardening() {
    local num="$1"
    local key mode owner bad="" seen=0
    if ! secaudit_tls_listener_configured; then
        secaudit_report_pass "$num" "Not applicable (HTTPS not configured)"
        return 0
    fi
    while IFS= read -r key; do
        [ -n "$key" ] || continue
        seen=$((seen + 1))
        if [ ! -e "$key" ]; then
            bad="${bad} missing:${key}"
            continue
        fi
        mode=$(secaudit_path_mode_octal "$key")
        owner=$(secaudit_path_owner_user "$key")
        case "$mode" in
            400|440|600)
                if [ "$owner" != "root" ] && [ "$owner" != "$_NGINX_SVC_ACCOUNT" ]; then
                    bad="${bad} owner:${key}:${owner}"
                fi
                ;;
            *)
                bad="${bad} mode:${key}:${mode}"
                ;;
        esac
    done < <(secaudit_ssl_private_key_paths)
    if [ "$seen" -eq 0 ]; then
        secaudit_report_fail "$num" "ssl_certificate_key is not configured"
    elif [ -n "$bad" ]; then
        secaudit_report_fail "$num" "private key files are not sufficiently restricted (${bad# })"
    else
        secaudit_report_pass "$num" "all ssl_certificate_key files are mode 400/440/600"
    fi
}

secaudit_check_modern_tls_protocols() {
    local num="$1"
    local cfg
    if ! secaudit_tls_listener_configured; then
        secaudit_report_pass "$num" "Not applicable (HTTPS not configured)"
        return 0
    fi
    cfg=$(secaudit_ssl_protocols_text)
    if [ -z "${cfg// /}" ]; then
        secaudit_report_fail "$num" "ssl_protocols is not configured"
        return 0
    fi
    if echo "$cfg" | grep -qiE 'TLSv1\.2' && echo "$cfg" | grep -qiE 'TLSv1\.3'; then
        secaudit_report_pass "$num" "TLSv1.2 and TLSv1.3 are enabled (${cfg})"
    elif echo "$cfg" | grep -qiE 'TLSv1\.2|TLSv1\.3'; then
        secaudit_report_pass "$num" "Modern TLS is enabled (${cfg})"
    else
        secaudit_report_fail "$num" "TLSv1.2/TLSv1.3 not detected in ssl_protocols (${cfg})"
    fi
}

secaudit_check_legacy_tls_absent() {
    local num="$1"
    local cfg
    if ! secaudit_tls_listener_configured; then
        secaudit_report_pass "$num" "Not applicable (HTTPS not configured)"
        return 0
    fi
    cfg=$(secaudit_ssl_protocols_text)
    if [ -z "${cfg// /}" ]; then
        secaudit_report_fail "$num" "ssl_protocols is not configured"
        return 0
    fi
    if echo "$cfg" | grep -qiE 'SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|(^|[[:space:];])TLSv1([[:space:];]|$)'; then
        secaudit_report_fail "$num" "Outdated TLS protocols are enabled (${cfg})"
    else
        secaudit_report_pass "$num" "Outdated TLS protocols are not enabled (${cfg})"
    fi
}

secaudit_check_cipher_suite() {
    local num="$1" scope="$2"
    local cfg prefer
    if [ "$scope" = "proxy" ]; then
        if ! secaudit_https_upstream_configured; then
            if secaudit_reverse_proxy_configured; then
                secaudit_report_pass "$num" "Not applicable (upstream TLS not used)"
            else
                secaudit_report_pass "$num" "Not applicable (reverse proxy not configured)"
            fi
            return 0
        fi
        cfg=$(secaudit_grep_live_config '^[[:space:]]*proxy_ssl_ciphers[[:space:]]+' | tr '\n' ' ')
        if [ -z "${cfg// /}" ]; then
            secaudit_report_fail "$num" "proxy_ssl_ciphers is not configured for HTTPS upstreams"
            return 0
        fi
        if secaudit_weak_cipher_tokens "$cfg"; then
            secaudit_report_fail "$num" "Weak ciphers may be enabled in proxy_ssl_ciphers (${cfg})"
        else
            secaudit_report_pass "$num" "proxy_ssl_ciphers has no weak-cipher tokens"
        fi
        return 0
    fi
    if ! secaudit_tls_listener_configured; then
        secaudit_report_pass "$num" "Not applicable (HTTPS not configured)"
        return 0
    fi
    cfg=$(secaudit_grep_live_config '^[[:space:]]*ssl_ciphers[[:space:]]+' | grep -vi 'proxy_ssl_ciphers' | tr '\n' ' ')
    prefer=$(secaudit_collect_directive_args 'ssl_prefer_server_ciphers')
    if [ -z "${cfg// /}" ]; then
        secaudit_report_fail "$num" "ssl_ciphers is not configured"
        return 0
    fi
    if secaudit_weak_cipher_tokens "$cfg"; then
        secaudit_report_fail "$num" "Weak ciphers may be enabled in ssl_ciphers (${cfg})"
        return 0
    fi
    if ! echo "$prefer" | grep -qi 'on'; then
        secaudit_report_fail "$num" "ssl_ciphers looks strong but ssl_prefer_server_ciphers is not on (${prefer:-unset})"
        return 0
    fi
    secaudit_report_pass "$num" "ssl_ciphers has no weak tokens and server preference is on"
}

secaudit_check_custom_dhparam() {
    local num="$1"
    local file bits
    if ! secaudit_tls_listener_configured; then
        secaudit_report_pass "$num" "Not applicable (HTTPS not configured)"
        return 0
    fi
    file=$(secaudit_first_directive_arg 'ssl_dhparam' | tr -d '"')
    if [ -z "$file" ]; then
        secaudit_report_fail "$num" "ssl_dhparam is not configured"
        return 0
    fi
    if [ ! -r "$file" ]; then
        secaudit_report_fail "$num" "ssl_dhparam file '${file}' is missing or unreadable"
        return 0
    fi
    if secaudit_have_bin openssl; then
        bits=$(openssl dhparam -in "$file" -text -noout 2>/dev/null | awk '/DH Parameters:/{print $3}' | tr -d '()')
        if [ -n "$bits" ] && [ "$bits" -ge "$_NGINX_DH_MIN_BITS" ] 2>/dev/null; then
            secaudit_report_pass "$num" "ssl_dhparam ${file} has ${bits}-bit parameters"
        elif [ -n "$bits" ]; then
            secaudit_report_fail "$num" "ssl_dhparam ${file} is only ${bits} bits (required >= ${_NGINX_DH_MIN_BITS})"
        else
            secaudit_report_fail "$num" "unable to parse DH parameters from ${file}"
        fi
    else
        secaudit_report_pass "$num" "ssl_dhparam is configured (${file})"
    fi
}

secaudit_check_ocsp_flag() {
    local num="$1" directive="$2"
    local extra=""
    if ! secaudit_tls_listener_configured; then
        secaudit_report_pass "$num" "Not applicable (HTTPS not configured)"
        return 0
    fi
    if ! secaudit_grep_live_config "^[[:space:]]*${directive}[[:space:]]+on" | grep -q .; then
        secaudit_report_fail "$num" "${directive} on is not configured"
        return 0
    fi
    if [ "$directive" = "ssl_stapling" ]; then
        secaudit_directive_is_present 'resolver' && extra="${extra} resolver"
        secaudit_grep_live_config 'ssl_trusted_certificate|ssl_stapling_file' | grep -q . && extra="${extra} trust-anchor"
        secaudit_report_pass "$num" "ssl_stapling on extras=${extra:-none}"
    else
        secaudit_report_pass "$num" "${directive} on is configured"
    fi
}

secaudit_check_hsts_policy() {
    local num="$1"
    local val age always="" sub=""
    val=$(secaudit_add_header_values_only 'Strict-Transport-Security')
    age=$(printf '%s' "$val" | grep -oiE 'max-age=[0-9]+' | head -1 | cut -d= -f2)
    [ -n "$age" ] || age=0
    secaudit_add_header_has_always 'Strict-Transport-Security' && always="always"
    printf '%s' "$val" | grep -qi 'includesubdomains' && sub="includeSubDomains"
    if ! secaudit_tls_listener_configured; then
        secaudit_report_pass "$num" "Not applicable (HTTPS not configured)"
        return 0
    fi
    if [ "$age" -ge "$_NGINX_HSTS_MIN_AGE" ] 2>/dev/null; then
        secaudit_report_pass "$num" "HSTS max-age=${age} (>=${_NGINX_HSTS_MIN_AGE}) ${always} ${sub}"
    else
        secaudit_report_fail "$num" "HSTS max-age=${age} (required >=${_NGINX_HSTS_MIN_AGE}) value='${val}'"
    fi
}

secaudit_check_upstream_mtls() {
    local num="$1" check="$2"
    if ! secaudit_https_upstream_configured; then
        if secaudit_reverse_proxy_configured; then
            secaudit_report_pass "$num" "Not applicable (upstream TLS not used)"
        else
            secaudit_report_pass "$num" "Not applicable (reverse proxy not configured)"
        fi
        return 0
    fi
    case "$check" in
        client-cert)
            local cert_hits key_hits
            cert_hits=$(secaudit_grep_live_config '^[[:space:]]*proxy_ssl_certificate[[:space:]]+' | grep -vi 'proxy_ssl_certificate_key' || true)
            key_hits=$(secaudit_grep_live_config '^[[:space:]]*proxy_ssl_certificate_key[[:space:]]+' || true)
            if [ -n "${cert_hits}" ] && [ -n "${key_hits}" ]; then
                secaudit_report_pass "$num" "proxy_ssl_certificate and proxy_ssl_certificate_key are configured"
            else
                secaudit_report_fail "$num" "upstream client certificate/key is not fully configured"
            fi
            ;;
        trusted-cert)
            if secaudit_grep_live_config '^[[:space:]]*proxy_ssl_trusted_certificate[[:space:]]+' | grep -q .; then
                secaudit_report_pass "$num" "proxy_ssl_trusted_certificate is configured"
            else
                secaudit_report_fail "$num" "proxy_ssl_trusted_certificate is not configured"
            fi
            ;;
        verify)
            if secaudit_grep_live_config '^[[:space:]]*proxy_ssl_verify[[:space:]]+on' | grep -q .; then
                secaudit_report_pass "$num" "proxy_ssl_verify on is configured"
            else
                secaudit_report_fail "$num" "proxy_ssl_verify on is not configured"
            fi
            ;;
    esac
}

secaudit_check_session_tickets_disabled() {
    local num="$1"
    local val
    if ! secaudit_tls_listener_configured; then
        secaudit_report_pass "$num" "Not applicable (HTTPS not configured)"
        return 0
    fi
    val=$(secaudit_collect_directive_args 'ssl_session_tickets')
    if echo "$val" | grep -qi 'off'; then
        secaudit_report_pass "$num" "ssl_session_tickets is off"
    else
        secaudit_report_fail "$num" "ssl_session_tickets is not off (${val:-default/on})"
    fi
}

secaudit_check_http2_enabled() {
    local num="$1"
    if ! secaudit_tls_listener_configured; then
        secaudit_report_pass "$num" "Not applicable (HTTPS not configured)"
        return 0
    fi
    if secaudit_grep_live_config 'listen[[:space:]]+.*http2' | grep -q . || \
       secaudit_grep_live_config '^[[:space:]]*http2[[:space:]]+on' | grep -q .; then
        secaudit_report_pass "$num" "HTTP/2 is enabled on the TLS listener"
    else
        secaudit_report_fail "$num" "HTTP/2 is not enabled on the SSL listener"
    fi
}

secaudit_check_pfs_only_ciphers() {
    local num="$1"
    local ssl proxy combined
    ssl=$(secaudit_grep_live_config '^[[:space:]]*ssl_ciphers[[:space:]]+' | grep -vi 'proxy_ssl_ciphers' | tr '\n' ' ')
    proxy=$(secaudit_grep_live_config '^[[:space:]]*proxy_ssl_ciphers[[:space:]]+' | tr '\n' ' ')
    if ! secaudit_tls_listener_configured && ! secaudit_https_upstream_configured; then
        secaudit_report_pass "$num" "Not applicable (TLS/proxy TLS not configured)"
        return 0
    fi
    combined="${ssl} ${proxy}"
    if [ -z "${combined// /}" ]; then
        secaudit_report_fail "$num" "Neither ssl_ciphers nor proxy_ssl_ciphers are configured"
        return 0
    fi
    if echo "$combined" | grep -qiE 'kRSA|:RSA:|RSA\+|aRSA' && ! echo "$combined" | grep -qiE 'ECDHE|EECDH|DHE|EDH'; then
        secaudit_report_fail "$num" "Static RSA key exchange is allowed without PFS (${combined})"
        return 0
    fi
    if secaudit_weak_cipher_tokens "$combined"; then
        secaudit_report_fail "$num" "Non-PFS or weak ciphers are enabled"
        return 0
    fi
    if ! echo "$combined" | grep -qiE 'ECDHE|DHE|EECDH|EDH'; then
        secaudit_report_fail "$num" "PFS key exchange (ECDHE/DHE) is not present (${combined})"
        return 0
    fi
    secaudit_report_pass "$num" "PFS-compatible cipher configuration detected"
}

secaudit_check_ip_allow_rules() {
    local num="$1"
    if secaudit_grep_live_config '^[[:space:]]*allow[[:space:]]+' | grep -q .; then
        secaudit_report_pass "$num" "allow directives are configured"
    else
        secaudit_report_fail "$num" "allow directives are not configured"
    fi
}

secaudit_check_ip_deny_rules() {
    local num="$1"
    local deny_all
    if ! secaudit_grep_live_config '^[[:space:]]*deny[[:space:]]+' | grep -q .; then
        secaudit_report_fail "$num" "deny directives are not configured"
        return 0
    fi
    deny_all=$(secaudit_grep_live_config '^[[:space:]]*deny[[:space:]]+all' | head -1)
    if [ -n "$deny_all" ]; then
        secaudit_report_pass "$num" "deny rules include a default deny all"
    else
        secaudit_report_pass "$num" "deny directives are configured"
    fi
}

secaudit_check_http_method_filter() {
    local num="$1"
    local hits dangerous
    hits=$(secaudit_grep_live_config 'limit_except|if[[:space:]]*\(\$request_method|\$request_method[[:space:]]*!~' | tr '\n' ' ')
    dangerous=$(secaudit_grep_live_config 'limit_except' | grep -iE 'TRACE|TRACK|DEBUG' | tr '\n' ' ')
    if [ -z "${hits// /}" ]; then
        secaudit_report_fail "$num" "HTTP method restrictions are not configured (limit_except or \$request_method filter required)"
        return 0
    fi
    if [ -n "${dangerous// /}" ]; then
        secaudit_report_fail "$num" "limit_except appears to allow TRACE/TRACK/DEBUG (${dangerous})"
        return 0
    fi
    secaudit_report_pass "$num" "HTTP method restrictions configured (${hits})"
}

secaudit_check_client_io_timeouts() {
    local num="$1"
    local header_t body_t
    header_t=$(secaudit_worst_timeout_seconds 'client_header_timeout' "")
    body_t=$(secaudit_worst_timeout_seconds 'client_body_timeout' "")
    if [ -z "$header_t" ] || [ -z "$body_t" ]; then
        secaudit_report_fail "$num" "client_header_timeout=${header_t:-unset} client_body_timeout=${body_t:-unset} (both must be set to 1..${_NGINX_TIMEOUT_SOFT_MAX}s)"
        return 0
    fi
    if secaudit_timeout_within_bound "$header_t" "$_NGINX_TIMEOUT_SOFT_MAX" && secaudit_timeout_within_bound "$body_t" "$_NGINX_TIMEOUT_SOFT_MAX"; then
        secaudit_report_pass "$num" "client_header_timeout=${header_t}s client_body_timeout=${body_t}s"
    else
        secaudit_report_fail "$num" "client_header_timeout=${header_t}s client_body_timeout=${body_t}s (required 1..${_NGINX_TIMEOUT_SOFT_MAX}s)"
    fi
}

secaudit_check_request_body_limit() {
    local num="$1"
    local raw bytes
    raw=$(secaudit_first_directive_arg 'client_max_body_size')
    if [ -z "$raw" ]; then
        secaudit_report_fail "$num" "client_max_body_size is not configured"
        return 0
    fi
    bytes=$(secaudit_bytes_from_nginx_size "$raw")
    if [ -z "$bytes" ]; then
        secaudit_report_fail "$num" "client_max_body_size='${raw}' cannot be parsed"
        return 0
    fi
    if [ "$bytes" -eq "$_NGINX_BODY_SIZE_UNLIMITED" ] 2>/dev/null; then
        secaudit_report_fail "$num" "client_max_body_size=0 disables the limit"
        return 0
    fi
    secaudit_report_pass "$num" "client_max_body_size=${raw} (${bytes} bytes)"
}

secaudit_check_uri_header_buffers() {
    local num="$1"
    local raw count size bytes
    raw=$(secaudit_collect_directive_args 'large_client_header_buffers')
    if [ -z "${raw// /}" ]; then
        secaudit_report_fail "$num" "large_client_header_buffers is not configured"
        return 0
    fi
    count=$(printf '%s' "$raw" | awk '{print $1}')
    size=$(printf '%s' "$raw" | awk '{print $2}')
    bytes=$(secaudit_bytes_from_nginx_size "$size")
    if [ -n "$bytes" ] && [ "$bytes" -gt "$_NGINX_HEADER_BUF_MAX_BYTES" ] 2>/dev/null; then
        secaudit_report_fail "$num" "large_client_header_buffers size ${size} exceeds ${_NGINX_HEADER_BUF_MAX_BYTES} bytes (${raw})"
        return 0
    fi
    if [ -n "$count" ] && [ "$count" -gt 8 ] 2>/dev/null; then
        secaudit_report_fail "$num" "large_client_header_buffers count ${count} is excessive (${raw})"
        return 0
    fi
    secaudit_report_pass "$num" "large_client_header_buffers is configured (${raw})"
}

secaudit_check_conn_zone() {
    local num="$1"
    local cfg
    cfg=$(secaudit_grep_live_config '^[[:space:]]*limit_conn_zone[[:space:]]+' | tr '\n' ' ')
    if [ -z "${cfg// /}" ]; then
        secaudit_report_fail "$num" "limit_conn_zone is not configured"
        return 0
    fi
    if echo "$cfg" | grep -qE '\$binary_remote_addr|\$remote_addr'; then
        secaudit_report_pass "$num" "limit_conn_zone keys off client address (${cfg})"
    else
        secaudit_report_fail "$num" "limit_conn_zone does not key off \$binary_remote_addr/\$remote_addr (${cfg})"
    fi
}

secaudit_check_conn_limit() {
    local num="$1" hits
    # Capture first: under pipefail, `... | grep -vi | grep -q` fails with SIGPIPE (141)
    # when multiple matching lines exist and grep -q exits early.
    hits=$(secaudit_grep_live_config '^[[:space:]]*limit_conn[[:space:]]+' | grep -vi 'limit_conn_zone' || true)
    if [ -n "${hits}" ]; then
        secaudit_report_pass "$num" "limit_conn is configured"
    else
        secaudit_report_fail "$num" "limit_conn is not configured"
    fi
}

secaudit_check_req_zone() {
    local num="$1"
    local cfg
    cfg=$(secaudit_grep_live_config '^[[:space:]]*limit_req_zone[[:space:]]+' | tr '\n' ' ')
    if [ -z "${cfg// /}" ]; then
        secaudit_report_fail "$num" "limit_req_zone is not configured"
        return 0
    fi
    if echo "$cfg" | grep -qE 'rate=' && echo "$cfg" | grep -qE '\$binary_remote_addr|\$remote_addr'; then
        secaudit_report_pass "$num" "limit_req_zone has address key and rate (${cfg})"
    elif echo "$cfg" | grep -qE 'rate='; then
        secaudit_report_pass "$num" "limit_req_zone has a rate (${cfg})"
    else
        secaudit_report_fail "$num" "limit_req_zone is missing rate= (${cfg})"
    fi
}

secaudit_check_req_limit() {
    local num="$1" hits
    hits=$(secaudit_grep_live_config '^[[:space:]]*limit_req[[:space:]]+' | grep -vi 'limit_req_zone' || true)
    if [ -n "${hits}" ]; then
        secaudit_report_pass "$num" "limit_req is configured"
    else
        secaudit_report_fail "$num" "limit_req is not configured"
    fi
}

secaudit_check_security_header() {
    local num="$1" name="$2" expected="$3"
    local val always=""
    val=$(secaudit_add_header_values_only "$name")
    secaudit_add_header_has_always "$name" && always="always"
    if [ -z "${val// /}" ]; then
        secaudit_report_fail "$num" "${name} is not configured"
        return 0
    fi
    if [ -n "$expected" ] && ! echo "$val" | grep -qiE "$expected"; then
        secaudit_report_fail "$num" "${name}='${val}' (expected pattern: ${expected})"
        return 0
    fi
    if [ -z "$always" ]; then
        secaudit_report_fail "$num" "${name}='${val}' is set without the always flag (missing on error responses)"
        return 0
    fi
    secaudit_report_pass "$num" "${name}='${val}' always"
}

# --- runners (RULE1-66 sequential) ---
secaudit_skip_all_rules() {
    local n=1
    while [ "$n" -le "$_NGINX_RULE_COUNT" ]; do
        secaudit_report_skip "$n" "nginx not installed and nginx.conf not found"
        n=$((n + 1))
    done
}

secaudit_run_modules_and_account() {
    # RULE1-8
    secaudit_check_webdav_absent 1
    secaudit_check_gzip_disabled 2
    secaudit_check_autoindex_scope 3 main
    secaudit_check_autoindex_scope 4 includes
    secaudit_check_service_account_no_sudo 5
    secaudit_check_dedicated_worker_account 6
    secaudit_check_service_account_locked 7
    secaudit_check_service_account_nologin_shell 8
}

secaudit_run_file_perms() {
    # RULE9-13
    secaudit_check_config_tree_ownership 9
    secaudit_check_config_dir_permissions 10
    secaudit_check_config_file_permissions 11
    secaudit_check_pid_file_mode 12
    secaudit_check_pid_file_owner 13
}

secaudit_run_listen_and_vhost() {
    # RULE14-16
    secaudit_check_authorized_listen_ports 14
    secaudit_check_unknown_host_rejected 15
    secaudit_check_catchall_vhost 16
}

secaudit_run_timeouts_and_identity() {
    # RULE17-26
    secaudit_check_timeout_cap 17 keepalive_timeout le 10
    secaudit_check_timeout_cap 18 keepalive_timeout gt 0
    secaudit_check_timeout_cap 19 send_timeout le 10
    secaudit_check_timeout_cap 20 send_timeout gt 0
    secaudit_check_server_tokens_hidden 21
    secaudit_check_default_page_clean 22 "${_NGINX_HTML_ROOT}/index.html"
    secaudit_check_default_page_clean 23 "${_NGINX_HTML_ROOT}/50x.html"
    secaudit_check_hidden_dotfiles_denied 24
    secaudit_check_proxy_header_stripped 25 'X-Powered-By'
    secaudit_check_proxy_header_stripped 26 'Server'
}

secaudit_run_logging() {
    # RULE27-33
    secaudit_check_verbose_log_format 27
    secaudit_check_access_log_enabled 28
    secaudit_check_error_log_info 29
    secaudit_check_logrotate_period 30
    secaudit_check_logrotate_count 31
    secaudit_check_remote_syslog 32 error_log
    secaudit_check_remote_syslog 33 access_log
}

secaudit_run_proxy_headers() {
    # RULE34-36
    secaudit_check_proxy_source_ip 34 proxy_pass
    secaudit_check_proxy_source_ip 35 x-real-ip
    secaudit_check_proxy_source_ip 36 x-forwarded-for
}

secaudit_run_tls() {
    # RULE37-52
    secaudit_check_certificate_chain 37
    secaudit_check_private_key_hardening 38
    secaudit_check_modern_tls_protocols 39
    secaudit_check_legacy_tls_absent 40
    secaudit_check_cipher_suite 41 server
    secaudit_check_cipher_suite 42 proxy
    secaudit_check_custom_dhparam 43
    secaudit_check_ocsp_flag 44 ssl_stapling
    secaudit_check_ocsp_flag 45 ssl_stapling_verify
    secaudit_check_hsts_policy 46
    secaudit_check_upstream_mtls 47 client-cert
    secaudit_check_upstream_mtls 48 trusted-cert
    secaudit_check_upstream_mtls 49 verify
    secaudit_check_session_tickets_disabled 50
    secaudit_check_http2_enabled 51
    secaudit_check_pfs_only_ciphers 52
}

secaudit_run_access_limits() {
    # RULE53-62
    secaudit_check_ip_allow_rules 53
    secaudit_check_ip_deny_rules 54
    secaudit_check_http_method_filter 55
    secaudit_check_client_io_timeouts 56
    secaudit_check_request_body_limit 57
    secaudit_check_uri_header_buffers 58
    secaudit_check_conn_zone 59
    secaudit_check_conn_limit 60
    secaudit_check_req_zone 61
    secaudit_check_req_limit 62
}

secaudit_run_security_headers() {
    # RULE63-66
    secaudit_check_security_header 63 'X-Frame-Options' 'DENY|SAMEORIGIN'
    secaudit_check_security_header 64 'X-Content-Type-Options' 'nosniff'
    secaudit_check_security_header 65 'Content-Security-Policy' 'default-src'
    secaudit_check_security_header 66 'Referrer-Policy' '(^|[[:space:]])(no-referrer|strict-origin|strict-origin-when-cross-origin|same-origin)([[:space:]]|$)'
}

# --- bootstrap / main ---
secaudit_bootstrap_nginx() {
    secaudit_layout_probe

    if ! secaudit_software_present && ! secaudit_conf_present; then
        secaudit_skip_all_rules
        return 1
    fi

    _NGINX_BIN=$(secaudit_nginx_bin_path 2>/dev/null || true)
    _NGINX_PRIMARY_CONF="${_NGINX_PRIMARY_CONF:-${_NGINX_CONF_ROOT}/nginx.conf}"
    _NGINX_SVC_ACCOUNT=$(secaudit_resolve_worker_account)
    _NGINX_PID_PATH=$(secaudit_resolve_pid_path)
    return 0
}

secaudit_main() {
    if ! secaudit_bootstrap_nginx; then
        exit 0
    fi
    secaudit_run_modules_and_account
    secaudit_run_file_perms
    secaudit_run_listen_and_vhost
    secaudit_run_timeouts_and_identity
    secaudit_run_logging
    secaudit_run_proxy_headers
    secaudit_run_tls
    secaudit_run_access_limits
    secaudit_run_security_headers
    exit 0
}

secaudit_main "$@"
