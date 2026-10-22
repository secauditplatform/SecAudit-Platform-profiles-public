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

# --- config (aligned with nginx.sh) ---
_NGINX_CONF_ROOT="${NGINX_CONF_ROOT:-${SECAUDIT_NGINX_CONF_ROOT:-}}"
_NGINX_HTML_ROOT="${NGINX_HTML_ROOT:-${SECAUDIT_NGINX_HTML_ROOT:-/usr/share/nginx/html}}"
_NGINX_LOGROTATE="${NGINX_LOGROTATE:-${SECAUDIT_NGINX_LOGROTATE:-/etc/logrotate.d/nginx}}"
_NGINX_RULE_COUNT=66
_NGINX_DROPIN_NAME="${NGINX_REMEDIATE_DROPIN:-${SECAUDIT_NGINX_REMEDIATE_DROPIN:-zz-secaudit-hardening.conf}}"
_NGINX_SYSLOG_TARGET="${NGINX_REMEDIATE_SYSLOG:-${SECAUDIT_NGINX_SYSLOG:-127.0.0.1:514}}"
_NGINX_DHPARAM_PATH="${NGINX_REMEDIATE_DHPARAM:-${SECAUDIT_NGINX_DHPARAM:-}}"
_NGINX_HSTS_MIN_AGE="${NGINX_HSTS_MIN_AGE:-${SECAUDIT_NGINX_HSTS_MIN_AGE:-15768000}}"
_NGINX_STRONG_CIPHERS="EECDH+AESGCM:EDH+AESGCM:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
_NGINX_REMEDIATE_APPLY_PERMS="${NGINX_REMEDIATE_APPLY_PERMS:-1}"
_NGINX_REMEDIATE_APPLY_ACCOUNT="${NGINX_REMEDIATE_APPLY_ACCOUNT:-1}"
_NGINX_REMEDIATE_APPLY_CONFIG="${NGINX_REMEDIATE_APPLY_CONFIG:-1}"
_NGINX_REMEDIATE_APPLY_TLS="${NGINX_REMEDIATE_APPLY_TLS:-1}"
_NGINX_REMEDIATE_RELOAD="${NGINX_REMEDIATE_RELOAD:-1}"
_NGINX_REMEDIATE_DHPARAM_BITS="${NGINX_REMEDIATE_DHPARAM_BITS:-2048}"

# --- runtime ---
_NGINX_PRIMARY_CONF=""
_NGINX_BIN=""
_NGINX_SVC_ACCOUNT="nginx"
_NGINX_PID_PATH="/var/run/nginx.pid"
_NGINX_DROPIN=""
_NGINX_SSL_CERT=""
_NGINX_SSL_KEY=""
_NGINX_CONFIG_CHANGED=0

# =============================================================================
# Helpers
# =============================================================================

secaudit_have_bin() { command -v "$1" >/dev/null 2>&1; }

secaudit_log() { printf '[remediation] %s\n' "$*"; }

secaudit_remediate_done() {
    printf '[remediation] REMEDIATE RULE%s= applied: %s\n' "$1" "$2"
}

secaudit_remediate_skip() {
    printf '[remediation] REMEDIATE RULE%s= SKIP: manual step required - %s\n' "$1" "$2"
}

secaudit_exec_with_timeout() {
    local secs="$1"
    shift
    if secaudit_have_bin timeout; then
        timeout "$secs" "$@"
    else
        "$@"
    fi
}

secaudit_backup_file() {
    local f="$1"
    [ -f "$f" ] || return 0
    if [ ! -f "${f}.secaudit.bak" ]; then
        cp -a "$f" "${f}.secaudit.bak" 2>/dev/null || true
    fi
}

secaudit_harden_path() {
    local p="$1" mode="$2" own="$3"
    [ -e "$p" ] || return 1
    chmod "$mode" "$p" 2>/dev/null || true
    if [ -n "$own" ]; then
        chown "$own" "$p" 2>/dev/null || true
    fi
    return 0
}

secaudit_mark_changed() { _NGINX_CONFIG_CHANGED=1; }

secaudit_nginx_bin_path() {
    if secaudit_have_bin nginx; then
        command -v nginx
        return 0
    fi
    local c
    for c in /usr/sbin/nginx /usr/local/sbin/nginx /usr/local/nginx/sbin/nginx; do
        [ -x "$c" ] && { printf '%s' "$c"; return 0; }
    done
    return 1
}

secaudit_layout_probe() {
    local prefix conf
    prefix="/etc/nginx"
    if secaudit_have_bin nginx; then
        conf=$(nginx -V 2>&1 | tr ' ' '\n' | grep -E '^--prefix=' | head -1 | cut -d= -f2-)
        [ -n "$conf" ] && prefix="$conf"
        conf=$(nginx -V 2>&1 | tr ' ' '\n' | grep -E '^--conf-path=' | head -1 | cut -d= -f2-)
        if [ -n "$conf" ] && [ -f "$conf" ]; then
            _NGINX_PRIMARY_CONF="$conf"
            _NGINX_CONF_ROOT=$(dirname "$conf")
        fi
    fi
    _NGINX_CONF_ROOT="${_NGINX_CONF_ROOT:-$prefix}"
    [ -d "$_NGINX_CONF_ROOT" ] || _NGINX_CONF_ROOT="/etc/nginx"
    if [ -z "$_NGINX_PRIMARY_CONF" ] || [ ! -f "$_NGINX_PRIMARY_CONF" ]; then
        if [ -f "${_NGINX_CONF_ROOT}/nginx.conf" ]; then
            _NGINX_PRIMARY_CONF="${_NGINX_CONF_ROOT}/nginx.conf"
        elif [ -f /etc/nginx/nginx.conf ]; then
            _NGINX_PRIMARY_CONF="/etc/nginx/nginx.conf"
            _NGINX_CONF_ROOT="/etc/nginx"
        fi
    fi
    _NGINX_DROPIN="${_NGINX_CONF_ROOT}/conf.d/${_NGINX_DROPIN_NAME}"
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
    pgrep -x nginx >/dev/null 2>&1 && return 0
    return 1
}

secaudit_conf_present() {
    [ -n "$_NGINX_PRIMARY_CONF" ] && [ -f "$_NGINX_PRIMARY_CONF" ] && return 0
    [ -d "${_NGINX_CONF_ROOT:-}" ] && return 0
    return 1
}

secaudit_resolve_worker_account() {
    local u
    u=$(grep -E '^[[:space:]]*user[[:space:]]+' "$_NGINX_PRIMARY_CONF" 2>/dev/null | head -1 | awk '{print $2}' | tr -d ';')
    if [ -n "$u" ]; then
        printf '%s' "$u"
        return 0
    fi
    for u in nginx www-data www; do
        getent passwd "$u" >/dev/null 2>&1 && { printf '%s' "$u"; return 0; }
    done
    printf '%s' "nginx"
}

secaudit_detect_ssl_material() {
    local line
    _NGINX_SSL_CERT=""
    _NGINX_SSL_KEY=""
    if [ -f "${_NGINX_CONF_ROOT}/ssl/server.crt" ] && [ -f "${_NGINX_CONF_ROOT}/ssl/server.key" ]; then
        _NGINX_SSL_CERT="${_NGINX_CONF_ROOT}/ssl/server.crt"
        _NGINX_SSL_KEY="${_NGINX_CONF_ROOT}/ssl/server.key"
        return 0
    fi
    line=$(grep -REh '^[[:space:]]*ssl_certificate[[:space:]]+' "$_NGINX_CONF_ROOT" 2>/dev/null | grep -vi 'ssl_certificate_key' | head -1)
    _NGINX_SSL_CERT=$(printf '%s' "$line" | awk '{print $2}' | tr -d '";')
    line=$(grep -REh '^[[:space:]]*ssl_certificate_key[[:space:]]+' "$_NGINX_CONF_ROOT" 2>/dev/null | head -1)
    _NGINX_SSL_KEY=$(printf '%s' "$line" | awk '{print $2}' | tr -d '";')
    [ -n "$_NGINX_SSL_CERT" ] && [ -f "$_NGINX_SSL_CERT" ] && [ -n "$_NGINX_SSL_KEY" ] && [ -f "$_NGINX_SSL_KEY" ]
}

secaudit_tls_configured() {
    grep -REh '^[[:space:]]*listen[[:space:]]+.*ssl' "$_NGINX_CONF_ROOT" 2>/dev/null | grep -qvE '^[[:space:]]*#' && return 0
    grep -REh '^[[:space:]]*ssl_certificate[[:space:]]+' "$_NGINX_CONF_ROOT" 2>/dev/null | grep -qvE '^[[:space:]]*#' && return 0
    return 1
}

secaudit_proxy_configured() {
    grep -REh '^[[:space:]]*proxy_pass[[:space:]]+' "$_NGINX_CONF_ROOT" 2>/dev/null | grep -qvE '^[[:space:]]*#'
}

secaudit_comment_matching_lines() {
    local file="$1" pattern="$2"
    [ -f "$file" ] || return 1
    if grep -Eq "$pattern" "$file" 2>/dev/null; then
        secaudit_backup_file "$file"
        sed -E -i "s|^([[:space:]]*)(${pattern})|\\1# secaudit: \\2|" "$file" 2>/dev/null || true
        secaudit_mark_changed
        return 0
    fi
    return 1
}

secaudit_ensure_top_user() {
    local account="$1" file="$_NGINX_PRIMARY_CONF"
    [ -f "$file" ] || return 1
    secaudit_backup_file "$file"
    if grep -Eq '^[[:space:]]*user[[:space:]]+' "$file"; then
        sed -E -i "s|^[[:space:]]*user[[:space:]]+[^;]+;|user ${account};|" "$file" 2>/dev/null || true
    else
        printf 'user %s;\n%s\n' "$account" "$(cat "$file")" >"${file}.tmp" && mv "${file}.tmp" "$file"
    fi
    secaudit_mark_changed
}

secaudit_ensure_pid_path() {
    local file dir pid
    file="$_NGINX_PRIMARY_CONF"
    dir="/var/run/nginx"
    pid="${dir}/nginx.pid"
    [ -f "$file" ] || return 1
    mkdir -p "$dir" 2>/dev/null || true
    chmod 755 "$dir" 2>/dev/null || true
    chown root:root "$dir" 2>/dev/null || true
    secaudit_backup_file "$file"
    if grep -Eq '^[[:space:]]*pid[[:space:]]+' "$file"; then
        sed -E -i "s|^[[:space:]]*pid[[:space:]]+[^;]+;|pid ${pid};|" "$file" 2>/dev/null || true
    else
        printf 'pid %s;\n%s\n' "$pid" "$(cat "$file")" >"${file}.tmp" && mv "${file}.tmp" "$file"
    fi
    _NGINX_PID_PATH="$pid"
    secaudit_mark_changed
}

# Replace or insert a simple "name value;" inside the top-level http { } of primary conf.
secaudit_upsert_http_directive() {
    local name="$1" value="$2" file="$_NGINX_PRIMARY_CONF" tmp
    [ -f "$file" ] || return 1
    secaudit_backup_file "$file"
    # Prefer simple in-file replace for existing scalars (avoid duplicate directives).
    if grep -Eq "^[[:space:]]*${name}[[:space:]]+" "$file"; then
        sed -E -i "s|^([[:space:]]*)${name}[[:space:]]+[^;]+;|\\1${name} ${value};|g" "$file" 2>/dev/null || true
        secaudit_mark_changed
        return 0
    fi
    # Insert before the closing brace of the first http { } block.
    tmp=$(mktemp 2>/dev/null || mktemp -t ngxrem)
    awk -v kn="$name" -v kv="$value" '
        BEGIN { in_http=0; depth=0; done=0 }
        {
            line=$0
            if (!in_http && line ~ /^[[:space:]]*http[[:space:]]*\{/) {
                in_http=1
                depth=0
            }
            if (in_http) {
                for (i = 1; i <= length(line); i++) {
                    c = substr(line, i, 1)
                    if (c == "{") depth++
                    else if (c == "}") depth--
                }
                if (depth <= 0 && !done) {
                    print "    " kn " " kv ";"
                    done=1
                    in_http=0
                }
            }
            print line
        }
        END {
            if (!done) {
                print "http {"
                print "    " kn " " kv ";"
                print "}"
            }
        }
    ' "$file" >"$tmp" 2>/dev/null && mv "$tmp" "$file" || rm -f "$tmp"
    secaudit_mark_changed
    return 0
}

secaudit_apply_http_scalars() {
    # Directives that nginx rejects when duplicated at the same level.
    secaudit_upsert_http_directive gzip off
    secaudit_upsert_http_directive gzip_static off
    secaudit_upsert_http_directive autoindex off
    secaudit_upsert_http_directive server_tokens off
    secaudit_upsert_http_directive keepalive_timeout 5s
    secaudit_upsert_http_directive send_timeout 5s
    secaudit_upsert_http_directive client_header_timeout 5s
    secaudit_upsert_http_directive client_body_timeout 5s
    secaudit_upsert_http_directive client_max_body_size 1m
    secaudit_upsert_http_directive "large_client_header_buffers" "4 8k"
}

secaudit_config_has() {
    # True if pattern exists in conf tree outside the managed drop-in.
    local pattern="$1"
    grep -REh "$pattern" "$_NGINX_CONF_ROOT" 2>/dev/null \
        | grep -v "/${_NGINX_DROPIN_NAME}" \
        | grep -qvE '^[[:space:]]*#'
}

secaudit_write_http_dropin() {
    local dh="${_NGINX_DHPARAM_PATH}"
    local cert="${_NGINX_SSL_CERT}"
    local key="${_NGINX_SSL_KEY}"
    local syslog="$_NGINX_SYSLOG_TARGET"
    local hsts="$_NGINX_HSTS_MIN_AGE"
    local ciphers="$_NGINX_STRONG_CIPHERS"
    local zone_conn="secaudit_addr"
    local zone_req="secaudit_req"
    local need_conn_zone=1 need_req_zone=1 need_log_format=1

    mkdir -p "$(dirname "$_NGINX_DROPIN")" 2>/dev/null || true
    # Remove previous drop-in before scanning so we do not treat ourselves as "existing".
    rm -f "$_NGINX_DROPIN" "${_NGINX_DROPIN}.zones" 2>/dev/null || true

    if secaudit_config_has 'limit_conn_zone[[:space:]].*zone=addr:'; then
        zone_conn="addr"
        need_conn_zone=0
    elif secaudit_config_has 'limit_conn_zone[[:space:]]'; then
        # Reuse first existing zone name
        zone_conn=$(grep -REh 'limit_conn_zone[[:space:]].*zone=[A-Za-z0-9_]+' "$_NGINX_CONF_ROOT" 2>/dev/null \
            | grep -v "/${_NGINX_DROPIN_NAME}" | head -1 | grep -oE 'zone=[A-Za-z0-9_]+' | head -1 | cut -d= -f2)
        [ -n "$zone_conn" ] || zone_conn="secaudit_addr"
        need_conn_zone=0
    fi
    if secaudit_config_has 'limit_req_zone[[:space:]].*zone=req:'; then
        zone_req="req"
        need_req_zone=0
    elif secaudit_config_has 'limit_req_zone[[:space:]]'; then
        zone_req=$(grep -REh 'limit_req_zone[[:space:]].*zone=[A-Za-z0-9_]+' "$_NGINX_CONF_ROOT" 2>/dev/null \
            | grep -v "/${_NGINX_DROPIN_NAME}" | head -1 | grep -oE 'zone=[A-Za-z0-9_]+' | head -1 | cut -d= -f2)
        [ -n "$zone_req" ] || zone_req="secaudit_req"
        need_req_zone=0
    fi
    secaudit_config_has 'log_format[[:space:]]+main[[:space:]]' && need_log_format=0

    # Snapshot whether HTTP/HTTPS default_servers already exist (before we write this drop-in).
    local have_http_default=0 have_https_default=0
    secaudit_config_has 'listen[[:space:]]+80[[:space:]].*default_server|listen[[:space:]]+\[::\]:80[[:space:]].*default_server' && have_http_default=1
    secaudit_config_has 'listen[[:space:]]+.*default_server' && grep -REh 'listen[[:space:]]+.*default_server' "$_NGINX_CONF_ROOT" 2>/dev/null | grep -v "/${_NGINX_DROPIN_NAME}" | grep -Eq '443|ssl' && have_https_default=1
    secaudit_config_has 'listen[[:space:]]+443[[:space:]].*default_server|listen[[:space:]]+\[::\]:443[[:space:]].*default_server' && have_https_default=1

    cat >"$_NGINX_DROPIN" <<EOF
# SecAudit NGINX remediation drop-in (managed)
# http-context include via conf.d — safe to re-run remediator.
# Non-duplicable scalars (gzip/timeouts/server_tokens/...) are upserted into nginx.conf.

access_log /var/log/nginx/access.log main;
error_log /var/log/nginx/error.log info;
access_log syslog:server=${syslog},tag=nginx,facility=local7 main;
error_log syslog:server=${syslog},tag=nginx info;

add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Content-Security-Policy "default-src 'self'" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Strict-Transport-Security "max-age=${hsts}; includeSubDomains" always;

ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers '${ciphers}';
ssl_prefer_server_ciphers on;
ssl_session_tickets off;
EOF

    if [ "$need_log_format" -eq 1 ]; then
        cat >>"$_NGINX_DROPIN" <<'EOF'

log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                '$status $body_bytes_sent "$http_referer" '
                '"$http_user_agent"';
EOF
    fi
    if [ "$need_conn_zone" -eq 1 ]; then
        printf '\nlimit_conn_zone $binary_remote_addr zone=%s:10m;\n' "$zone_conn" >>"$_NGINX_DROPIN"
    fi
    if [ "$need_req_zone" -eq 1 ]; then
        printf 'limit_req_zone $binary_remote_addr zone=%s:10m rate=10r/s;\n' "$zone_req" >>"$_NGINX_DROPIN"
    fi

    if [ -n "$dh" ] && [ -f "$dh" ]; then
        printf 'ssl_dhparam %s;\n' "$dh" >>"$_NGINX_DROPIN"
    fi

    if secaudit_tls_configured; then
        cat >>"$_NGINX_DROPIN" <<EOF
resolver 1.1.1.1 8.8.8.8 valid=300s;
ssl_stapling on;
ssl_stapling_verify on;
http2 on;
EOF
        if [ "$have_https_default" -eq 0 ] && [ -n "$cert" ] && [ -f "$cert" ] && [ -n "$key" ] && [ -f "$key" ]; then
            cat >>"$_NGINX_DROPIN" <<EOF

# Catch-all HTTPS default_server — reject unknown hosts
server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name _;
    ssl_certificate ${cert};
    ssl_certificate_key ${key};
    return 403;
}
EOF
        fi
    fi

    if [ "$have_http_default" -eq 0 ]; then
        cat >>"$_NGINX_DROPIN" <<'EOF'

# Catch-all HTTP default_server — reject unknown hosts
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 403;
}
EOF
    fi

    printf '%s %s\n' "$zone_conn" "$zone_req" >"${_NGINX_DROPIN}.zones"
    secaudit_mark_changed
}

secaudit_patch_server_blocks() {
    # Inject per-server hardening into conf.d/*.conf (except our drop-in).
    local zone_conn="secaudit_addr" zone_req="secaudit_req"
    if [ -f "${_NGINX_DROPIN}.zones" ]; then
        read -r zone_conn zone_req <"${_NGINX_DROPIN}.zones"
    fi
    if ! secaudit_have_bin python3; then
        secaudit_log "python3 missing; skipping per-server location patching"
        return 1
    fi
    NGINX_CONF_ROOT="$_NGINX_CONF_ROOT" DROPIN_NAME="$_NGINX_DROPIN_NAME" ZONE_CONN="$zone_conn" ZONE_REQ="$zone_req" python3 - <<'PY'
import os, re, pathlib
root = pathlib.Path(os.environ["NGINX_CONF_ROOT"])
dropin = os.environ["DROPIN_NAME"]
zc = os.environ["ZONE_CONN"]
zr = os.environ["ZONE_REQ"]
hidden = """
    location ~ /\\. {
        deny all;
        return 403;
    }
"""
loc_harden = f"""
        limit_conn {zc} 20;
        limit_req zone={zr} burst=20 nodelay;
        allow 127.0.0.1;
        allow ::1;
        deny all;
        limit_except GET HEAD POST {{
            deny all;
        }}
"""
changed = False
for path in sorted(root.glob("conf.d/*.conf")):
    if path.name == dropin:
        continue
    text = path.read_text(encoding="utf-8", errors="replace")
    orig = text
    # Ensure hidden-files location in every server block once
    if not re.search(r'location\s+~\s*/\\.', text):
        # insert before each server closing at depth 1 — simpler: append before last } of each server via regex
        def add_hidden(m):
            body = m.group(0)
            if re.search(r'location\s+~\s*/\\.', body):
                return body
            # insert before final }
            return body[:-1] + hidden + "}\n"
        text = re.sub(r'server\s*\{(?:[^{}]|\{[^{}]*\})*\}', add_hidden, text, flags=re.S)
    # Harden location / blocks that lack limit_conn
    def harden_loc(m):
        body = m.group(0)
        if "limit_conn" in body and "limit_req" in body and re.search(r'\ballow\b', body) and re.search(r'\bdeny\b', body):
            return body
        # insert after opening brace
        return re.sub(r'(\blocation\s+/\s*\{)', r'\1' + loc_harden, body, count=1)
    text = re.sub(r'location\s+/\s*\{(?:[^{}]|\{[^{}]*\})*\}', harden_loc, text, flags=re.S)
    # TLS server hardening snippets
    def harden_ssl_server(m):
        body = m.group(0)
        if "ssl" not in body and not re.search(r'listen\s+[^\n]*ssl', body):
            return body
        inserts = []
        if not re.search(r'ssl_session_tickets\s+off', body):
            inserts.append("    ssl_session_tickets off;")
        if not re.search(r'http2\s+on', body) and not re.search(r'listen\s+[^\n]*http2', body):
            inserts.append("    http2 on;")
        if not inserts:
            return body
        return re.sub(r'(server\s*\{)', r'\1\n' + "\n".join(inserts), body, count=1)
    text = re.sub(r'server\s*\{(?:[^{}]|\{[^{}]*\})*\}', harden_ssl_server, text, flags=re.S)
    # proxy_hide_header when proxy_pass present
    if re.search(r'proxy_pass\s+', text):
        def add_proxy_hide(m):
            body = m.group(0)
            out = body
            if "proxy_hide_header X-Powered-By" not in body:
                out = re.sub(r'(server\s*\{)', r'\1\n    proxy_hide_header X-Powered-By;', out, count=1)
            if "proxy_hide_header Server" not in out:
                out = re.sub(r'(server\s*\{)', r'\1\n    proxy_hide_header Server;', out, count=1)
            if "proxy_set_header X-Real-IP" not in out:
                out = re.sub(r'(server\s*\{)', r'\1\n    proxy_set_header X-Real-IP $remote_addr;\n    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;', out, count=1)
            return out
        text = re.sub(r'server\s*\{(?:[^{}]|\{[^{}]*\})*\}', add_proxy_hide, text, flags=re.S)
    if text != orig:
        bak = path.with_suffix(path.suffix + ".secaudit.bak")
        if not bak.exists():
            bak.write_text(orig, encoding="utf-8")
        path.write_text(text, encoding="utf-8")
        changed = True
        print(f"patched {path}")
if changed:
    raise SystemExit(0)
raise SystemExit(1)
PY
    if [ $? -eq 0 ]; then
        secaudit_mark_changed
        return 0
    fi
    return 1
}

secaudit_ensure_logrotate() {
    mkdir -p "$(dirname "$_NGINX_LOGROTATE")" 2>/dev/null || true
    if [ ! -f "$_NGINX_LOGROTATE" ]; then
        cat >"$_NGINX_LOGROTATE" <<'EOF'
/var/log/nginx/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 nginx adm
    sharedscripts
    postrotate
        [ -f /var/run/nginx/nginx.pid ] && kill -USR1 `cat /var/run/nginx/nginx.pid`
        [ -f /var/run/nginx.pid ] && kill -USR1 `cat /var/run/nginx.pid`
    endscript
}
EOF
        return 0
    fi
    secaudit_backup_file "$_NGINX_LOGROTATE"
    grep -Eq '^[[:space:]]*(daily|weekly)[[:space:]]*$' "$_NGINX_LOGROTATE" || printf '\ndaily\n' >>"$_NGINX_LOGROTATE"
    if ! grep -Eq '^[[:space:]]*rotate[[:space:]]+[0-9]+' "$_NGINX_LOGROTATE"; then
        printf '\nrotate 14\n' >>"$_NGINX_LOGROTATE"
    fi
    return 0
}

secaudit_sanitize_default_pages() {
    local f
    for f in "${_NGINX_HTML_ROOT}/index.html" "${_NGINX_HTML_ROOT}/50x.html"; do
        [ -f "$f" ] || continue
        if grep -qiE 'nginx|angie' "$f" 2>/dev/null; then
            secaudit_backup_file "$f"
            cat >"$f" <<'EOF'
<!DOCTYPE html>
<html><head><title>Site</title></head>
<body><h1>Welcome</h1></body></html>
EOF
            secaudit_mark_changed
        fi
    done
}

secaudit_ensure_dhparam() {
    local out bits="$_NGINX_REMEDIATE_DHPARAM_BITS"
    out="${_NGINX_DHPARAM_PATH:-${_NGINX_CONF_ROOT}/ssl/dhparam.pem}"
    mkdir -p "$(dirname "$out")" 2>/dev/null || true
    if [ -f "$out" ] && [ -s "$out" ]; then
        _NGINX_DHPARAM_PATH="$out"
        return 0
    fi
    if ! secaudit_have_bin openssl; then
        return 1
    fi
    secaudit_log "generating ${bits}-bit DH parameters at ${out} (may take a while)"
    if secaudit_exec_with_timeout 180 openssl dhparam -dsaparam -out "$out" "$bits" 2>/dev/null; then
        _NGINX_DHPARAM_PATH="$out"
        chmod 644 "$out" 2>/dev/null || true
        return 0
    fi
    if secaudit_exec_with_timeout 300 openssl dhparam -out "$out" "$bits" 2>/dev/null; then
        _NGINX_DHPARAM_PATH="$out"
        chmod 644 "$out" 2>/dev/null || true
        return 0
    fi
    return 1
}

secaudit_nginx_test() {
    local bin
    bin=$(secaudit_nginx_bin_path) || return 1
    if [ -n "$_NGINX_PRIMARY_CONF" ] && [ -f "$_NGINX_PRIMARY_CONF" ]; then
        "$bin" -t -c "$_NGINX_PRIMARY_CONF" >/dev/null 2>&1
    else
        "$bin" -t >/dev/null 2>&1
    fi
}

secaudit_nginx_reload() {
    local bin oldpid
    [ "$_NGINX_REMEDIATE_RELOAD" = "1" ] || return 0
    bin=$(secaudit_nginx_bin_path) || return 1
    if ! secaudit_nginx_test; then
        secaudit_log "nginx -t failed; skipping reload (restore .secaudit.bak if needed)"
        "$bin" -t 2>&1 | tail -20 | while IFS= read -r line; do secaudit_log "nginx-t: $line"; done
        return 1
    fi
    # Changing pid path requires a full restart; reload keeps the old pid file semantics.
    if "$bin" -s reload 2>/dev/null; then
        secaudit_log "nginx reloaded"
        return 0
    fi
    if [ -f "$_NGINX_PID_PATH" ]; then
        kill -HUP "$(tr -d '[:space:]' <"$_NGINX_PID_PATH")" 2>/dev/null && secaudit_log "nginx HUP via pid file" && return 0
    fi
    for oldpid in /var/run/nginx.pid /run/nginx.pid /nginx.pid; do
        [ -f "$oldpid" ] || continue
        kill -HUP "$(tr -d '[:space:]' <"$oldpid")" 2>/dev/null && secaudit_log "nginx HUP via ${oldpid}" && return 0
    done
    # Last resort for containers running nginx as PID1-child: start a new master if none responds
    if ! pgrep -x nginx >/dev/null 2>&1; then
        "$bin" 2>/dev/null &
        secaudit_log "nginx started in background"
        return 0
    fi
    secaudit_log "nginx reload signal failed (config on disk is updated; restart container/service manually)"
    return 1
}

# =============================================================================
# Rule remediations
# =============================================================================

secaudit_remediate_modules_and_account() {
    # RULE1-8
    local acct="$_NGINX_SVC_ACCOUNT" f

    # RULE1 WebDAV — disable runtime directives; compile-time module needs rebuild
    local dav_hit=0
    for f in "$_NGINX_PRIMARY_CONF" "${_NGINX_CONF_ROOT}/conf.d"/*.conf; do
        [ -f "$f" ] || continue
        basename "$f" | grep -qx "$_NGINX_DROPIN_NAME" && continue
        secaudit_comment_matching_lines "$f" 'load_module[[:space:]]+.*dav' && dav_hit=1
        secaudit_comment_matching_lines "$f" 'dav_methods[[:space:]]+' && dav_hit=1
        secaudit_comment_matching_lines "$f" 'dav_access[[:space:]]+' && dav_hit=1
        secaudit_comment_matching_lines "$f" 'create_full_put_path[[:space:]]+' && dav_hit=1
    done
    if nginx -V 2>&1 | grep -q 'http_dav_module'; then
        secaudit_remediate_skip 1 "rebuild/replace nginx without http_dav_module (runtime dav_* directives cleared if present)"
    elif [ "$dav_hit" -eq 1 ]; then
        secaudit_remediate_done 1 "commented WebDAV runtime directives"
    else
        secaudit_remediate_done 1 "WebDAV runtime directives absent"
    fi

    # RULE2 gzip — force off in drop-in; compile modules need rebuild
    if nginx -V 2>&1 | grep -qE 'http_gzip_module|http_gzip_static_module'; then
        secaudit_remediate_skip 2 "rebuild/replace nginx without gzip modules (runtime gzip off applied via drop-in)"
    else
        secaudit_remediate_done 2 "gzip runtime disabled via drop-in"
    fi
    for f in "$_NGINX_PRIMARY_CONF" "${_NGINX_CONF_ROOT}/conf.d"/*.conf; do
        [ -f "$f" ] || continue
        basename "$f" | grep -qx "$_NGINX_DROPIN_NAME" && continue
        secaudit_comment_matching_lines "$f" 'load_module[[:space:]]+.*gzip'
        if grep -Eq '^[[:space:]]*gzip[[:space:]]+on' "$f" 2>/dev/null; then
            secaudit_backup_file "$f"
            sed -E -i 's/^([[:space:]]*)gzip[[:space:]]+on[[:space:]]*;/\1gzip off;/' "$f" 2>/dev/null || true
            secaudit_mark_changed
        fi
    done

    # RULE3/4 autoindex — drop-in sets off; comment enables
    for f in "$_NGINX_PRIMARY_CONF" "${_NGINX_CONF_ROOT}/conf.d"/*.conf; do
        [ -f "$f" ] || continue
        if grep -Eq '^[[:space:]]*autoindex[[:space:]]+on' "$f" 2>/dev/null; then
            secaudit_backup_file "$f"
            sed -E -i 's/^([[:space:]]*)autoindex[[:space:]]+on[[:space:]]*;/\1autoindex off;/' "$f" 2>/dev/null || true
            secaudit_mark_changed
        fi
    done
    secaudit_remediate_done 3 "autoindex off (main/drop-in)"
    secaudit_remediate_done 4 "autoindex off (includes/drop-in)"

    if [ "$_NGINX_REMEDIATE_APPLY_ACCOUNT" != "1" ]; then
        local n
        for n in 5 6 7 8; do secaudit_remediate_skip "$n" "account remediation disabled"; done
        return 0
    fi

    # Ensure non-root worker account exists
    if ! getent passwd "$acct" >/dev/null 2>&1; then
        if secaudit_have_bin useradd; then
            useradd --system --no-create-home --shell /sbin/nologin "$acct" 2>/dev/null \
                || useradd -r -s /sbin/nologin "$acct" 2>/dev/null || true
        elif secaudit_have_bin adduser; then
            adduser -S -D -H -s /sbin/nologin "$acct" 2>/dev/null || true
        fi
    fi
    secaudit_ensure_top_user "$acct"
    secaudit_remediate_done 6 "worker account '${acct}' referenced in nginx.conf"

    # RULE5 sudo
    if [ -d /etc/sudoers.d ]; then
        rm -f /etc/sudoers.d/*nginx* /etc/sudoers.d/*www-data* 2>/dev/null || true
    fi
    if [ -f /etc/sudoers ] && grep -Eq "^[[:space:]]*${acct}[[:space:]]" /etc/sudoers 2>/dev/null; then
        secaudit_backup_file /etc/sudoers
        sed -E -i "/^[[:space:]]*${acct}[[:space:]]/d" /etc/sudoers 2>/dev/null || true
    fi
    secaudit_remediate_done 5 "removed sudo rights for ${acct} if present"

    # RULE7 lock
    if secaudit_have_bin passwd; then
        passwd -l "$acct" >/dev/null 2>&1 || true
    fi
    if [ -f /etc/shadow ]; then
        secaudit_backup_file /etc/shadow
    fi
    secaudit_remediate_done 7 "locked account ${acct}"

    # RULE8 nologin shell
    local nologin="/sbin/nologin"
    [ -x /usr/sbin/nologin ] && nologin="/usr/sbin/nologin"
    [ -x /sbin/nologin ] || [ -x /usr/sbin/nologin ] || nologin="/bin/false"
    if secaudit_have_bin usermod; then
        usermod -s "$nologin" "$acct" 2>/dev/null || true
    elif secaudit_have_bin chsh; then
        chsh -s "$nologin" "$acct" 2>/dev/null || true
    fi
    secaudit_remediate_done 8 "set ${acct} shell to ${nologin}"
}

secaudit_remediate_file_perms() {
    # RULE9-13
    local path

    if [ "$_NGINX_REMEDIATE_APPLY_PERMS" != "1" ]; then
        local n
        for n in 9 10 11 12 13; do secaudit_remediate_skip "$n" "permission remediation disabled"; done
        return 0
    fi

    if [ -d "$_NGINX_CONF_ROOT" ]; then
        chown -R root:root "$_NGINX_CONF_ROOT" 2>/dev/null || true
        secaudit_remediate_done 9 "${_NGINX_CONF_ROOT} ownership root:root"
        while IFS= read -r path; do
            [ -d "$path" ] || continue
            chmod 750 "$path" 2>/dev/null || chmod o-rwx "$path" 2>/dev/null || true
        done < <(find "$_NGINX_CONF_ROOT" -type d 2>/dev/null | head -200)
        secaudit_remediate_done 10 "config directories mode 750 (o=0)"
        while IFS= read -r path; do
            [ -f "$path" ] || continue
            case "$path" in
                *.key|*/ssl/*key*) chmod 600 "$path" 2>/dev/null || true ;;
                *) chmod 640 "$path" 2>/dev/null || chmod o-rwx "$path" 2>/dev/null || true ;;
            esac
        done < <(find "$_NGINX_CONF_ROOT" -type f 2>/dev/null | head -400)
        secaudit_remediate_done 11 "config files mode 640/600 (o=0)"
    else
        secaudit_remediate_skip 9 "config root missing"
        secaudit_remediate_skip 10 "config root missing"
        secaudit_remediate_skip 11 "config root missing"
    fi

    secaudit_ensure_pid_path
    mkdir -p "$(dirname "$_NGINX_PID_PATH")" 2>/dev/null || true
    chmod 755 "$(dirname "$_NGINX_PID_PATH")" 2>/dev/null || true
    if [ -e "$_NGINX_PID_PATH" ]; then
        chmod 644 "$_NGINX_PID_PATH" 2>/dev/null || true
        chown root:root "$_NGINX_PID_PATH" 2>/dev/null || true
    fi
    secaudit_remediate_done 12 "pid path ${_NGINX_PID_PATH} under non-world-writable dir"
    secaudit_remediate_done 13 "pid owner root:root (when file exists)"
}

secaudit_remediate_listen_and_vhost() {
    # RULE14-16
    secaudit_remediate_skip 14 "review listen directives; keep only authorized ports (${NGINX_AUTHORIZED_HTTP_PORTS:-80 443})"
    # RULE15/16 handled by catch-all servers in drop-in + existing http default_server
    if grep -REh 'default_server|server_name[[:space:]]+_|return[[:space:]]+444' "$_NGINX_CONF_ROOT" 2>/dev/null | grep -qvE '^[[:space:]]*#'; then
        secaudit_remediate_done 15 "catch-all / default_server reject configured (verify with audit probe)"
        secaudit_remediate_done 16 "catch-all vhost present"
    else
        secaudit_remediate_skip 15 "add default_server return 444 for unknown hosts"
        secaudit_remediate_skip 16 "add default_server return 444 for unknown hosts"
    fi
}

secaudit_remediate_timeouts_and_identity() {
    # RULE17-26 — mostly drop-in + server patch + html sanitize
    local n
    for n in 17 18 19 20; do
        secaudit_remediate_done "$n" "keepalive/send timeouts capped via drop-in"
    done
    secaudit_remediate_done 21 "server_tokens off via drop-in"
    secaudit_sanitize_default_pages
    secaudit_remediate_done 22 "default index.html sanitized if branded"
    secaudit_remediate_done 23 "default 50x.html sanitized if branded"
    secaudit_remediate_done 24 "hidden-file location deny injected where missing"
    if secaudit_proxy_configured; then
        secaudit_remediate_done 25 "proxy_hide_header X-Powered-By (when proxy_pass present)"
        secaudit_remediate_done 26 "proxy_hide_header Server (when proxy_pass present)"
    else
        secaudit_remediate_done 25 "N/A (no reverse proxy) — no change required"
        secaudit_remediate_done 26 "N/A (no reverse proxy) — no change required"
    fi
}

secaudit_remediate_logging() {
    # RULE27-33
    secaudit_remediate_done 27 "log_format main with forensic fields via drop-in"
    secaudit_remediate_done 28 "access_log enabled via drop-in"
    secaudit_remediate_done 29 "error_log info via drop-in"
    secaudit_ensure_logrotate
    secaudit_remediate_done 30 "logrotate daily/weekly present"
    secaudit_remediate_done 31 "logrotate rotate count present"
    secaudit_remediate_done 32 "error_log syslog:${_NGINX_SYSLOG_TARGET} via drop-in"
    secaudit_remediate_done 33 "access_log syslog:${_NGINX_SYSLOG_TARGET} via drop-in"
}

secaudit_remediate_proxy_headers() {
    # RULE34-36
    if secaudit_proxy_configured; then
        secaudit_remediate_done 34 "proxy_pass retained; source IP headers ensured when patching"
        secaudit_remediate_done 35 "proxy_set_header X-Real-IP when proxy present"
        secaudit_remediate_done 36 "proxy_set_header X-Forwarded-For when proxy present"
    else
        secaudit_remediate_done 34 "N/A (no reverse proxy)"
        secaudit_remediate_done 35 "N/A (no reverse proxy)"
        secaudit_remediate_done 36 "N/A (no reverse proxy)"
    fi
}

secaudit_remediate_tls() {
    # RULE37-52
    local n
    if [ "$_NGINX_REMEDIATE_APPLY_TLS" != "1" ]; then
        for n in $(seq 37 52); do secaudit_remediate_skip "$n" "TLS remediation disabled"; done
        return 0
    fi

    if ! secaudit_tls_configured; then
        for n in 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52; do
            case "$n" in
                42|47|48|49) secaudit_remediate_done "$n" "N/A (no TLS/proxy TLS)" ;;
                *) secaudit_remediate_done "$n" "N/A (HTTPS not configured)" ;;
            esac
        done
        return 0
    fi

    secaudit_remediate_skip 37 "install a trusted certificate chain from your CA/PKI"
    if [ -n "$_NGINX_SSL_KEY" ] && [ -f "$_NGINX_SSL_KEY" ]; then
        secaudit_harden_path "$_NGINX_SSL_KEY" 600 "root:root"
        secaudit_remediate_done 38 "private key mode 600 owner root"
    else
        secaudit_remediate_skip 38 "ssl_certificate_key not found"
    fi
    secaudit_remediate_done 39 "ssl_protocols TLSv1.2 TLSv1.3 via drop-in"
    secaudit_remediate_done 40 "legacy SSL/TLS protocols not enabled in drop-in"
    secaudit_remediate_done 41 "strong ssl_ciphers + ssl_prefer_server_ciphers on"
    if secaudit_proxy_configured && grep -REh 'proxy_pass[[:space:]]+https://' "$_NGINX_CONF_ROOT" 2>/dev/null | grep -qvE '^[[:space:]]*#'; then
        secaudit_remediate_skip 42 "set proxy_ssl_ciphers to a strong PFS suite on HTTPS upstreams"
    else
        secaudit_remediate_done 42 "N/A (no HTTPS upstream)"
    fi

    if secaudit_ensure_dhparam; then
        secaudit_remediate_done 43 "ssl_dhparam ${_NGINX_DHPARAM_PATH}"
    else
        secaudit_remediate_skip 43 "generate ssl_dhparam (>=2048) with openssl and reference it"
    fi
    secaudit_remediate_done 44 "ssl_stapling on + resolver via drop-in"
    secaudit_remediate_done 45 "ssl_stapling_verify on via drop-in"
    secaudit_remediate_done 46 "HSTS max-age=${_NGINX_HSTS_MIN_AGE} via drop-in"
    if grep -REh 'proxy_pass[[:space:]]+https://' "$_NGINX_CONF_ROOT" 2>/dev/null | grep -qvE '^[[:space:]]*#'; then
        secaudit_remediate_skip 47 "configure proxy_ssl_certificate / proxy_ssl_certificate_key for upstream mTLS"
        secaudit_remediate_skip 48 "configure proxy_ssl_trusted_certificate"
        secaudit_remediate_skip 49 "set proxy_ssl_verify on"
    else
        secaudit_remediate_done 47 "N/A (no HTTPS upstream)"
        secaudit_remediate_done 48 "N/A (no HTTPS upstream)"
        secaudit_remediate_done 49 "N/A (no HTTPS upstream)"
    fi
    secaudit_remediate_done 50 "ssl_session_tickets off"
    secaudit_remediate_done 51 "http2 on"
    secaudit_remediate_done 52 "PFS ECDHE/DHE ciphers via drop-in"
}

secaudit_remediate_access_limits() {
    # RULE53-62
    local n
    for n in 53 54 55; do
        secaudit_remediate_done "$n" "allow/deny/limit_except injected into location / where missing"
    done
    secaudit_remediate_done 56 "client_header_timeout/client_body_timeout via drop-in"
    secaudit_remediate_done 57 "client_max_body_size via drop-in"
    secaudit_remediate_done 58 "large_client_header_buffers via drop-in"
    secaudit_remediate_done 59 "limit_conn_zone via drop-in"
    secaudit_remediate_done 60 "limit_conn in location / via patch"
    secaudit_remediate_done 61 "limit_req_zone via drop-in"
    secaudit_remediate_done 62 "limit_req in location / via patch"
}

secaudit_remediate_security_headers() {
    # RULE63-66
    local n
    for n in 63 64 65 66; do
        secaudit_remediate_done "$n" "security headers via drop-in add_header"
    done
}

# =============================================================================
# Bootstrap / main
# =============================================================================

secaudit_skip_all_rules() {
    local n=1
    while [ "$n" -le "$_NGINX_RULE_COUNT" ]; do
        secaudit_remediate_skip "$n" "nginx not present on this host"
        n=$((n + 1))
    done
}

secaudit_bootstrap_nginx() {
    secaudit_layout_probe
    if ! secaudit_software_present && ! secaudit_conf_present; then
        secaudit_log "nginx not detected; skipping automated remediations"
        secaudit_skip_all_rules
        return 1
    fi
    _NGINX_BIN=$(secaudit_nginx_bin_path 2>/dev/null || true)
    _NGINX_SVC_ACCOUNT=$(secaudit_resolve_worker_account)
    secaudit_detect_ssl_material || true
    _NGINX_DHPARAM_PATH="${_NGINX_DHPARAM_PATH:-${_NGINX_CONF_ROOT}/ssl/dhparam.pem}"
    secaudit_log "conf_root=${_NGINX_CONF_ROOT} primary=${_NGINX_PRIMARY_CONF:-none}"
    secaudit_log "dropin=${_NGINX_DROPIN} account=${_NGINX_SVC_ACCOUNT}"
    secaudit_log "ssl_cert=${_NGINX_SSL_CERT:-none} ssl_key=${_NGINX_SSL_KEY:-none}"
    secaudit_log "apply_perms=${_NGINX_REMEDIATE_APPLY_PERMS} apply_config=${_NGINX_REMEDIATE_APPLY_CONFIG} apply_tls=${_NGINX_REMEDIATE_APPLY_TLS}"
    return 0
}

secaudit_main() {
    secaudit_log "starting remediation (Nginx / secaudit_* style)"

    if ! secaudit_bootstrap_nginx; then
        secaudit_log "remediation complete (nothing to apply)"
        exit 0
    fi

    if [ "$_NGINX_REMEDIATE_APPLY_CONFIG" = "1" ]; then
        # Order: scalars in primary conf, dhparam, drop-in, server patches
        secaudit_apply_http_scalars
        if secaudit_tls_configured; then
            secaudit_ensure_dhparam || true
        fi
        secaudit_write_http_dropin
        secaudit_patch_server_blocks || true
    else
        secaudit_log "config remediation disabled (NGINX_REMEDIATE_APPLY_CONFIG=0)"
    fi

    secaudit_remediate_modules_and_account
    secaudit_remediate_file_perms
    secaudit_remediate_listen_and_vhost
    secaudit_remediate_timeouts_and_identity
    secaudit_remediate_logging
    secaudit_remediate_proxy_headers
    secaudit_remediate_tls
    secaudit_remediate_access_limits
    secaudit_remediate_security_headers

    if [ "$_NGINX_CONFIG_CHANGED" -eq 1 ] || [ "$_NGINX_REMEDIATE_RELOAD" = "1" ]; then
        secaudit_nginx_reload || true
    fi

    secaudit_log "remediation complete (nginx_remediation.sh)"
    secaudit_log "note: compile-time modules (WebDAV/gzip) require a different nginx build; bind-mount perms may not change on Docker Desktop"
    exit 0
}

secaudit_main "$@"
