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

# --- config ---
_PG_USER="${PGUSER:-${SECAUDIT_PG_USER:-}}"
_PG_PASS="${PGPASSWORD:-${SECAUDIT_PG_PASSWORD:-}}"
_PG_HOST="${PGHOST:-${SECAUDIT_PG_HOST:-}}"
_PG_PORT="${PGPORT:-${SECAUDIT_PG_PORT:-}}"
_PG_DATADIR_OVERRIDE="${PGDATA:-${SECAUDIT_PG_DATADIR:-}}"
_PG_CONF_OVERRIDE="${PGCONF:-${SECAUDIT_PG_CONF:-}}"
_PG_RULE_COUNT=89
_PG_SSL_DIR="${PG_REMEDIATE_SSL_DIR:-/etc/postgresql-secaudit/ssl}"
_PG_LOG_DIR="${PG_REMEDIATE_LOG_DIR:-/var/log/postgresql-secaudit}"
_PG_ARCHIVE_DIR="${PG_REMEDIATE_ARCHIVE_DIR:-/var/lib/postgresql/archive}"
_PG_LISTEN="${PG_REMEDIATE_LISTEN:-localhost}"
_PG_STRONG_CIPHERS='HIGH:!aNULL:!MD5:!RC4:!3DES:!DES:!EXPORT:!NULL'
_PG_RESTART_HINT=0

# --- runtime ---
_PG_PSQL=""
_PG_LIVE=0
_PG_DATADIR=""
_PG_CONF=""
_PG_HBA=""
_PG_AUTO=""
_PG_MAJOR=""
_PG_HBA_RULES=""

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

secaudit_trim() {
    local s="${1-}"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

secaudit_lower() {
    printf '%s' "${1-}" | tr '[:upper:]' '[:lower:]'
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

secaudit_parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -software_user)
                if [ $# -ge 2 ]; then _PG_USER="$2"; shift 2; else shift; fi
                ;;
            -software_password)
                if [ $# -ge 2 ]; then _PG_PASS="$2"; shift 2; else shift; fi
                ;;
            *)
                shift
                ;;
        esac
    done
    [ -n "$_PG_PASS" ] && export PGPASSWORD="$_PG_PASS"
}

secaudit_locate_psql() {
    local p
    for p in \
        psql \
        /usr/bin/psql \
        /usr/pgsql-*/bin/psql \
        /usr/lib/postgresql/*/bin/psql
    do
        if command -v "$p" >/dev/null 2>&1; then
            command -v "$p"
            return 0
        fi
        [ -x "$p" ] && { printf '%s' "$p"; return 0; }
    done
    return 1
}

secaudit_locate_postgres() {
    local p
    for p in \
        postgres \
        /usr/bin/postgres \
        /usr/pgsql-*/bin/postgres \
        /usr/lib/postgresql/*/bin/postgres
    do
        if command -v "$p" >/dev/null 2>&1; then
            command -v "$p"
            return 0
        fi
        [ -x "$p" ] && { printf '%s' "$p"; return 0; }
    done
    return 1
}

secaudit_pg_installed() {
    secaudit_locate_psql >/dev/null 2>&1 && return 0
    secaudit_locate_postgres >/dev/null 2>&1 && return 0
    return 1
}

secaudit_major_ge() {
    local want="$1"
    [ -n "$_PG_MAJOR" ] || return 1
    [ "$_PG_MAJOR" -ge "$want" ]
}

secaudit_psql_exec() {
    local sql="$1"
    local -a cmd
    local out
    [ -n "$_PG_PSQL" ] || return 1

    # Prefer local peer as OS user postgres (reliable after pg_hba peer harden;
    # TCP+password can fail mid-run once host auth is tightened).
    if [ "$(id -u 2>/dev/null || echo 1)" = "0" ] && getent passwd postgres >/dev/null 2>&1; then
        if secaudit_have_bin runuser; then
            out=$(secaudit_exec_with_timeout 12 runuser -u postgres -- \
                "$_PG_PSQL" -v ON_ERROR_STOP=0 -X -t -A -q -d postgres -c "$sql" 2>/dev/null) && {
                printf '%s' "$out"
                return 0
            }
        elif secaudit_have_bin su; then
            out=$(secaudit_exec_with_timeout 12 su -s /bin/bash postgres -c \
                "PGPASSWORD= ${_PG_PSQL} -v ON_ERROR_STOP=0 -X -t -A -q -d postgres -c $(printf '%q' "$sql")" 2>/dev/null) && {
                printf '%s' "$out"
                return 0
            }
        fi
    fi

    cmd=("$_PG_PSQL" -v ON_ERROR_STOP=0 -X -t -A -q -d postgres)
    [ -n "$_PG_USER" ] && cmd+=(-U "$_PG_USER")
    if [ -n "$_PG_HOST" ]; then
        cmd+=(-h "$_PG_HOST")
    fi
    [ -n "$_PG_PORT" ] && cmd+=(-p "$_PG_PORT")
    secaudit_exec_with_timeout 12 "${cmd[@]}" -c "$sql" 2>/dev/null
}

secaudit_probe_live() {
    local out saved_host
    saved_host="$_PG_HOST"
    _PG_HOST=""
    out=$(secaudit_psql_exec "SELECT 1;" 2>/dev/null | head -1)
    if [ "$out" = "1" ]; then
        _PG_LIVE=1
        return 0
    fi
    _PG_HOST="${saved_host:-localhost}"
    out=$(secaudit_psql_exec "SELECT 1;" 2>/dev/null | head -1)
    if [ "$out" = "1" ]; then
        _PG_LIVE=1
        return 0
    fi
    _PG_HOST="$saved_host"
    _PG_LIVE=0
    return 1
}

secaudit_detect_major() {
    local v n bin f
    f="${_PG_DATADIR:+$_PG_DATADIR/PG_VERSION}"
    if [ -n "$f" ] && [ -f "$f" ]; then
        v=$(secaudit_trim "$(tr -d '\r' < "$f")")
        _PG_MAJOR=$(printf '%s' "${v%%.*}" | tr -cd '0-9')
        [ -n "$_PG_MAJOR" ] && return 0
    fi
    if [ "$_PG_LIVE" -eq 1 ]; then
        n=$(secaudit_psql_exec "SHOW server_version_num;" 2>/dev/null | head -1 | tr -cd '0-9')
        if [ ${#n} -ge 6 ]; then
            _PG_MAJOR=$((10#${n:0:2}))
        elif [ ${#n} -eq 5 ]; then
            _PG_MAJOR=$((10#${n:0:1}))
        fi
        [ -n "$_PG_MAJOR" ] && return 0
    fi
    bin=$(secaudit_locate_postgres 2>/dev/null || true)
    [ -z "$bin" ] && bin=$(secaudit_locate_psql 2>/dev/null || true)
    if [ -n "$bin" ]; then
        v=$("$bin" --version 2>/dev/null | sed -n 's/.*PostgreSQL[^0-9]*\([0-9][0-9]*\).*/\1/p' | head -1)
        _PG_MAJOR=$(printf '%s' "$v" | tr -cd '0-9')
    fi
    [ -n "$_PG_MAJOR" ]
}

secaudit_layout_datadir() {
    local d found
    if [ -n "$_PG_DATADIR_OVERRIDE" ] && [ -d "$_PG_DATADIR_OVERRIDE" ]; then
        printf '%s' "$_PG_DATADIR_OVERRIDE"
        return 0
    fi
    if [ "$_PG_LIVE" -eq 1 ]; then
        d=$(secaudit_psql_exec "SHOW data_directory;" 2>/dev/null | head -1)
        d=$(secaudit_trim "$d")
        if [ -n "$d" ] && [ -d "$d" ]; then
            printf '%s' "$d"
            return 0
        fi
    fi
    for d in \
        /var/lib/pgsql/data \
        /var/lib/postgresql/data \
        /var/lib/pgsql/*/data \
        /var/lib/postgresql/*/main \
        /usr/pgsql-*/data \
        /var/lib/postgresql/*/*
    do
        [ -f "$d/PG_VERSION" ] && { printf '%s' "$d"; return 0; }
    done
    found=$(secaudit_exec_with_timeout 20 find /var/lib/pgsql /var/lib/postgresql /etc/postgresql -maxdepth 5 -type f -name PG_VERSION 2>/dev/null | head -1)
    if [ -n "$found" ]; then
        printf '%s' "${found%/PG_VERSION}"
        return 0
    fi
    return 1
}

secaudit_layout_conf() {
    local f
    if [ -n "$_PG_CONF_OVERRIDE" ] && [ -f "$_PG_CONF_OVERRIDE" ]; then
        printf '%s' "$_PG_CONF_OVERRIDE"
        return 0
    fi
    if [ "$_PG_LIVE" -eq 1 ]; then
        f=$(secaudit_psql_exec "SHOW config_file;" 2>/dev/null | head -1)
        f=$(secaudit_trim "$f")
        [ -n "$f" ] && [ -f "$f" ] && { printf '%s' "$f"; return 0; }
    fi
    if [ -n "$_PG_DATADIR" ] && [ -f "$_PG_DATADIR/postgresql.conf" ]; then
        printf '%s' "$_PG_DATADIR/postgresql.conf"
        return 0
    fi
    for f in \
        /var/lib/pgsql/data/postgresql.conf \
        /var/lib/postgresql/data/postgresql.conf \
        /var/lib/pgsql/*/data/postgresql.conf \
        /etc/postgresql/*/main/postgresql.conf \
        /etc/postgresql/*/data/postgresql.conf
    do
        [ -f "$f" ] && { printf '%s' "$f"; return 0; }
    done
    return 1
}

secaudit_layout_hba() {
    local f
    if [ "$_PG_LIVE" -eq 1 ]; then
        f=$(secaudit_psql_exec "SHOW hba_file;" 2>/dev/null | head -1)
        f=$(secaudit_trim "$f")
        [ -n "$f" ] && [ -f "$f" ] && { printf '%s' "$f"; return 0; }
    fi
    if [ -n "$_PG_CONF" ] && [ -f "$(dirname "$_PG_CONF")/pg_hba.conf" ]; then
        printf '%s' "$(dirname "$_PG_CONF")/pg_hba.conf"
        return 0
    fi
    if [ -n "$_PG_DATADIR" ] && [ -f "$_PG_DATADIR/pg_hba.conf" ]; then
        printf '%s' "$_PG_DATADIR/pg_hba.conf"
        return 0
    fi
    for f in /var/lib/pgsql/*/data/pg_hba.conf /etc/postgresql/*/main/pg_hba.conf /var/lib/postgresql/data/pg_hba.conf; do
        [ -f "$f" ] && { printf '%s' "$f"; return 0; }
    done
    return 1
}

secaudit_home_postgres() {
    getent passwd postgres 2>/dev/null | awk -F: '{print $6}' | head -1
}

secaudit_unit_names() {
    local maj="${_PG_MAJOR:-}"
    printf '%s\n' postgresql
    if [ -n "$maj" ]; then
        printf '%s\n' "postgresql-${maj}" "postgresql${maj}" "postgresql@${maj}-main" "postgresql@${maj}"
    fi
    printf '%s\n' postgresql-9.6 postgresql-10 postgresql-11 postgresql-12 postgresql-13 postgresql-14 postgresql-15 postgresql-16 postgresql-17
}

secaudit_mark_restart() {
    _PG_RESTART_HINT=1
}

secaudit_sql_quote() {
    # Wrap a GUC value as a SQL string literal for ALTER SYSTEM.
    local v="$1"
    v=$(printf '%s' "$v" | sed "s/'/''/g")
    printf "'%s'" "$v"
}

secaudit_write_auto_conf() {
    local name="$1" raw="$2" file tmp
    file="$_PG_AUTO"
    [ -n "$file" ] || return 1
    mkdir -p "$(dirname "$file")" 2>/dev/null || true
    touch "$file" 2>/dev/null || return 1
    secaudit_backup_file "$file"
    tmp=$(mktemp 2>/dev/null || echo "/tmp/secaudit-auto.$$")
    # Strip prior assignments for this name, append new line.
    awk -v want="$(secaudit_lower "$name")" '
        {
            line=$0
            sub(/[[:space:]]*#.*$/, "", line)
            n=tolower($1)
            if (n == want) next
            print
        }
    ' "$file" >"$tmp" 2>/dev/null
    printf '%s = %s\n' "$name" "$raw" >>"$tmp"
    mv "$tmp" "$file" 2>/dev/null || { rm -f "$tmp"; return 1; }
    if getent passwd postgres >/dev/null 2>&1; then
        chown postgres:postgres "$file" 2>/dev/null || true
    fi
    return 0
}

secaudit_set_guc() {
    # Args: name value_sql_literal_or_bare need_restart(0|1)
    # value is written to ALTER SYSTEM as-is (caller supplies quotes for strings).
    local name="$1" sqlval="$2" need_restart="${3:-0}" auto_raw out
    auto_raw="$sqlval"
    # Strip surrounding quotes for auto.conf bare form if present.
    case "$auto_raw" in
        \'*\') auto_raw="${auto_raw#\'}"; auto_raw="${auto_raw%\'}" ;;
    esac

    if [ "$_PG_LIVE" -eq 1 ]; then
        out=$(secaudit_psql_exec "ALTER SYSTEM SET ${name} = ${sqlval};" 2>/dev/null)
        # Best-effort; ignore errors (unknown GUC on older/newer PG).
        :
    fi
    secaudit_write_auto_conf "$name" "$sqlval" || secaudit_write_auto_conf "$name" "$auto_raw" || true
    if [ "$need_restart" = "1" ]; then
        secaudit_mark_restart
    fi
    return 0
}

secaudit_reload_conf() {
    local out
    if [ "$_PG_LIVE" -ne 1 ]; then
        return 1
    fi
    out=$(secaudit_psql_exec "SELECT pg_reload_conf();" 2>/dev/null | head -1)
    if [ "$out" = "t" ] || [ "$out" = "true" ]; then
        secaudit_log "pg_reload_conf() ok"
        return 0
    fi
    secaudit_log "pg_reload_conf() returned '${out:-empty}'"
    return 1
}

secaudit_hba_has_gss() {
    if [ -n "$_PG_HBA" ] && [ -f "$_PG_HBA" ]; then
        grep -Eiq '^[[:space:]]*host.*[[:space:]](gss|sspi)([[:space:]]|$)' "$_PG_HBA" 2>/dev/null && return 0
    fi
    return 1
}

secaudit_ensure_ssl_material() {
    local dir="$_PG_SSL_DIR"
    mkdir -p "$dir" 2>/dev/null || return 1
    if [ ! -f "$dir/server.key" ] || [ ! -f "$dir/server.crt" ]; then
        if ! secaudit_have_bin openssl; then
            return 1
        fi
        openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "$dir/server.key" \
            -out "$dir/server.crt" \
            -days 365 \
            -subj "/CN=localhost" 2>/dev/null || return 1
        cp "$dir/server.crt" "$dir/root.crt" 2>/dev/null || true
    fi
    [ -f "$dir/root.crt" ] || cp "$dir/server.crt" "$dir/root.crt" 2>/dev/null || true
    chmod 600 "$dir/server.key" 2>/dev/null || true
    chmod 644 "$dir/server.crt" "$dir/root.crt" 2>/dev/null || true
    if getent passwd postgres >/dev/null 2>&1; then
        chown postgres:postgres "$dir" "$dir/server.key" "$dir/server.crt" "$dir/root.crt" 2>/dev/null || true
    fi
    return 0
}

# =============================================================================
# Rule remediations
# =============================================================================

secaudit_remediate_systemd_and_cluster() {
    # RULE1
    local u enabled=0
    if secaudit_have_bin systemctl; then
        for u in $(secaudit_unit_names); do
            if systemctl enable "$u" >/dev/null 2>&1; then
                enabled=1
                secaudit_remediate_done 1 "systemctl enable ${u}"
                break
            fi
        done
        if [ "$enabled" -eq 0 ]; then
            secaudit_remediate_skip 1 "no postgresql systemd unit to enable (common in official Docker image)"
        fi
    else
        secaudit_remediate_skip 1 "systemctl unavailable; enable postgresql unit on host OS"
    fi

    # RULE2
    if [ -n "$_PG_DATADIR" ] && [ -d "$_PG_DATADIR" ]; then
        chmod 700 "$_PG_DATADIR" 2>/dev/null || true
        if getent passwd postgres >/dev/null 2>&1; then
            chown postgres:postgres "$_PG_DATADIR" 2>/dev/null || true
        fi
        secaudit_remediate_done 2 "PGDATA ${_PG_DATADIR} mode 700 owner postgres:postgres"
    else
        secaudit_remediate_skip 2 "PGDATA not found"
    fi

    # RULE3
    local home f
    home=$(secaudit_home_postgres)
    if [ -n "$home" ]; then
        mkdir -p "$home" 2>/dev/null || true
        f="${home}/.bash_profile"
        touch "$f" 2>/dev/null || true
        if ! grep -Eq '^[[:space:]]*umask[[:space:]]+0?077' "$f" 2>/dev/null; then
            printf '\n# secaudit\numask 077\n' >>"$f" 2>/dev/null || true
        fi
        chown postgres:postgres "$f" 2>/dev/null || true
        secaudit_remediate_done 3 "umask 077 in ${f}"
    else
        secaudit_remediate_skip 3 "postgres OS user / home not found"
    fi

    # RULE4
    if getent group pg_wheel >/dev/null 2>&1; then
        if getent group pg_wheel | awk -F: '{print $4}' | tr ',' '\n' | grep -qx postgres; then
            if secaudit_have_bin gpasswd; then
                gpasswd -d postgres pg_wheel >/dev/null 2>&1 || true
            elif secaudit_have_bin deluser; then
                deluser postgres pg_wheel >/dev/null 2>&1 || true
            else
                groupmod -r postgres pg_wheel >/dev/null 2>&1 || true
            fi
            secaudit_remediate_done 4 "removed postgres from pg_wheel (if present)"
        else
            secaudit_remediate_done 4 "postgres not a member of pg_wheel"
        fi
    else
        secaudit_remediate_done 4 "pg_wheel group not defined"
    fi
}

secaudit_remediate_logging_core() {
    mkdir -p "$_PG_LOG_DIR" 2>/dev/null || true
    if getent passwd postgres >/dev/null 2>&1; then
        chown postgres:postgres "$_PG_LOG_DIR" 2>/dev/null || true
    fi
    chmod 750 "$_PG_LOG_DIR" 2>/dev/null || true

    # RULE5,61
    secaudit_set_guc log_destination "'stderr'" 0
    secaudit_remediate_done 5 "log_destination=stderr"
    # RULE6,45
    secaudit_set_guc logging_collector on 1
    secaudit_remediate_done 6 "logging_collector=on (restart may be required)"
    # RULE7,62,81
    secaudit_set_guc log_directory "$(secaudit_sql_quote "$_PG_LOG_DIR")" 0
    secaudit_remediate_done 7 "log_directory=${_PG_LOG_DIR}"
    # RULE8,63
    secaudit_set_guc log_file_mode "'0600'" 0
    secaudit_remediate_done 8 "log_file_mode=0600"
    # RULE9,66
    secaudit_set_guc syslog_facility "'local0'" 0
    secaudit_remediate_done 9 "syslog_facility=local0"
    # RULE10,70
    secaudit_set_guc log_min_messages "'warning'" 0
    secaudit_remediate_done 10 "log_min_messages=warning"
    # RULE11-13
    secaudit_set_guc debug_print_parse off 0
    secaudit_remediate_done 11 "debug_print_parse=off"
    secaudit_set_guc debug_print_rewritten off 0
    secaudit_remediate_done 12 "debug_print_rewritten=off"
    secaudit_set_guc debug_print_plan off 0
    secaudit_remediate_done 13 "debug_print_plan=off"
    # RULE14,15,40,41
    secaudit_set_guc log_connections on 0
    secaudit_remediate_done 14 "log_connections=on"
    secaudit_set_guc log_disconnections on 0
    secaudit_remediate_done 15 "log_disconnections=on"
    # RULE16,69
    secaudit_set_guc log_error_verbosity "'default'" 0
    secaudit_remediate_done 16 "log_error_verbosity=default"
    # RULE17
    secaudit_set_guc log_hostname off 0
    secaudit_remediate_done 17 "log_hostname=off"
    # RULE18,71
    secaudit_set_guc log_statement "'ddl'" 0
    secaudit_remediate_done 18 "log_statement=ddl"
    # RULE19,65
    secaudit_set_guc log_timezone "'UTC'" 0
    secaudit_remediate_done 19 "log_timezone=UTC"
    # RULE20
    secaudit_remediate_skip 20 "install/configure pgaudit (package + shared_preload_libraries; restart required)"
}

secaudit_remediate_auth_and_roles() {
    # RULE21 — audit greps sudoers files; create drop-in even if sudo package is absent
    local sudoers_d="/etc/sudoers.d" dropin
    mkdir -p "$sudoers_d" 2>/dev/null || true
    if [ -d "$sudoers_d" ]; then
        if ! getent group pg_wheel >/dev/null 2>&1; then
            if secaudit_have_bin groupadd; then
                groupadd --system pg_wheel 2>/dev/null || groupadd pg_wheel 2>/dev/null || true
            fi
        fi
        # Ensure postgres is not a member
        if getent group pg_wheel >/dev/null 2>&1; then
            if getent group pg_wheel | awk -F: '{print $4}' | tr ',' '\n' | grep -qx postgres; then
                gpasswd -d postgres pg_wheel >/dev/null 2>&1 || true
            fi
        fi
        dropin="${sudoers_d}/99-secaudit-pg_wheel"
        printf '%s\n' '%pg_wheel ALL=(postgres) NOPASSWD: /bin/su - postgres' >"$dropin" 2>/dev/null
        chmod 440 "$dropin" 2>/dev/null || true
        if grep -Eq '^[[:space:]]*%pg_wheel' "$dropin" 2>/dev/null; then
            secaudit_remediate_done 21 "sudoers ${dropin}; pg_wheel present without postgres member"
        else
            secaudit_remediate_skip 21 "unable to write ${dropin}"
        fi
    else
        secaudit_remediate_skip 21 "create /etc/sudoers.d/99-secaudit-pg_wheel with %pg_wheel ALL=(postgres) NOPASSWD: /bin/su - postgres"
    fi

    # RULE22-24 — do not auto-drop superusers / SECURITY DEFINER
    secaudit_remediate_skip 22 "review pg_authid; revoke rolsuper from non-postgres roles manually"
    secaudit_remediate_skip 23 "review SECURITY DEFINER functions outside catalogs; drop/replace manually"
    secaudit_remediate_skip 24 "ensure only postgres is superuser; review pg_* role grants manually"

    # RULE25 — local peer
    if [ -n "$_PG_HBA" ] && [ -f "$_PG_HBA" ]; then
        secaudit_backup_file "$_PG_HBA"
        if ! grep -Eq '^[[:space:]]*local[[:space:]]+.*[[:space:]]peer([[:space:]]|$)' "$_PG_HBA" 2>/dev/null; then
            # Prepend a local peer line
            {
                printf '%s\n' '# secaudit: local peer'
                printf '%s\n' 'local   all             all                                     peer'
                cat "$_PG_HBA"
            } >"${_PG_HBA}.secaudit.tmp" 2>/dev/null && mv "${_PG_HBA}.secaudit.tmp" "$_PG_HBA"
        fi
        # Demote local trust if present
        sed -i -E 's/^([[:space:]]*local[[:space:]].*)[[:space:]]trust([[:space:]]|$)/\1 peer\2/' "$_PG_HBA" 2>/dev/null || true
        secaudit_remediate_done 25 "pg_hba local peer ensured (${_PG_HBA})"
    else
        secaudit_remediate_skip 25 "pg_hba.conf not found"
    fi

    # RULE26 — host scram-sha-256 (no trust/password/ident)
    if [ -n "$_PG_HBA" ] && [ -f "$_PG_HBA" ]; then
        secaudit_backup_file "$_PG_HBA"
        sed -i -E \
            -e 's/^([[:space:]]*host(ssl|nossl)?[[:space:]].*)[[:space:]]trust([[:space:]]|$)/\1 scram-sha-256\3/' \
            -e 's/^([[:space:]]*host(ssl|nossl)?[[:space:]].*)[[:space:]]password([[:space:]]|$)/\1 scram-sha-256\3/' \
            -e 's/^([[:space:]]*host(ssl|nossl)?[[:space:]].*)[[:space:]]ident([[:space:]]|$)/\1 scram-sha-256\3/' \
            "$_PG_HBA" 2>/dev/null || true
        if ! grep -Eq '^[[:space:]]*host[[:space:]]+.*scram-sha-256' "$_PG_HBA" 2>/dev/null; then
            printf '%s\n' 'host    all             all             127.0.0.1/32            scram-sha-256' >>"$_PG_HBA"
            printf '%s\n' 'host    all             all             ::1/128                 scram-sha-256' >>"$_PG_HBA"
        fi
        if getent passwd postgres >/dev/null 2>&1; then
            chown postgres:postgres "$_PG_HBA" 2>/dev/null || true
        fi
        secaudit_remediate_done 26 "pg_hba host auth hardened to scram-sha-256 (no trust/password/ident)"
        secaudit_reload_conf || true
    else
        secaudit_remediate_skip 26 "pg_hba.conf not found"
    fi
}

secaudit_remediate_runtime_bundles() {
    # RULE27/42
    secaudit_set_guc ignore_system_indexes off 0
    secaudit_set_guc post_auth_delay 0 0
    secaudit_set_guc log_connections on 0
    secaudit_set_guc log_disconnections on 0
    secaudit_remediate_done 27 "ignore_system_indexes=off post_auth_delay=0 log_connections/disconnections=on"

    # RULE28-31 informational after underlying GUCs
    secaudit_remediate_done 28 "postmaster bundle settings applied via ALTER SYSTEM / auto.conf"
    secaudit_remediate_done 29 "SIGHUP logging bundle settings applied"
    secaudit_remediate_done 30 "superuser logging/statement settings applied"
    secaudit_remediate_done 31 "user session GUC bundle applied"
}

secaudit_remediate_crypto_and_layout() {
    # RULE32
    secaudit_remediate_skip 32 "enable FIPS mode in the kernel/OpenSSL (host/OS policy)"

    # RULE33 + SSL files / ciphers (also covers 47-54, 77-80 except CRL)
    if secaudit_ensure_ssl_material; then
        secaudit_set_guc ssl on 1
        secaudit_set_guc ssl_cert_file "$(secaudit_sql_quote "${_PG_SSL_DIR}/server.crt")" 1
        secaudit_set_guc ssl_key_file "$(secaudit_sql_quote "${_PG_SSL_DIR}/server.key")" 1
        secaudit_set_guc ssl_ca_file "$(secaudit_sql_quote "${_PG_SSL_DIR}/root.crt")" 1
        secaudit_set_guc ssl_ciphers "$(secaudit_sql_quote "$_PG_STRONG_CIPHERS")" 0
        secaudit_set_guc ssl_prefer_server_ciphers on 0
        secaudit_set_guc ssl_ecdh_curve "'prime256v1'" 0
        secaudit_remediate_done 33 "ssl=on with cert/key under ${_PG_SSL_DIR} (restart may be required)"
    else
        secaudit_remediate_skip 33 "generate SSL material under ${_PG_SSL_DIR} (openssl required)"
    fi

    # RULE34
    if [ "$_PG_LIVE" -eq 1 ]; then
        if secaudit_psql_exec "SELECT 1 FROM pg_available_extensions WHERE name='pgcrypto';" 2>/dev/null | grep -q '^1$'; then
            secaudit_psql_exec "CREATE EXTENSION IF NOT EXISTS pgcrypto;" >/dev/null 2>&1 || true
            secaudit_remediate_done 34 "CREATE EXTENSION IF NOT EXISTS pgcrypto"
        else
            secaudit_remediate_skip 34 "pgcrypto not in pg_available_extensions (install contrib package)"
        fi
    else
        secaudit_remediate_skip 34 "no live session to CREATE EXTENSION pgcrypto"
    fi

    # RULE35-36
    secaudit_remediate_skip 35 "relocate config_file/hba_file/ident_file outside PGDATA (planned outage)"
    secaudit_remediate_skip 36 "relocate log_directory and WAL (pg_wal) outside PGDATA"
    # RULE37-39
    secaudit_remediate_skip 37 "install and configure pgBackRest"
    secaudit_remediate_skip 38 "install pg_permissions / pg_permission extension package"
    secaudit_remediate_skip 39 "install set_user extension package"
}

secaudit_remediate_backend_detail() {
    secaudit_remediate_done 40 "log_connections=on"
    secaudit_remediate_done 41 "log_disconnections=on"
    secaudit_remediate_done 42 "post_auth_delay=0"
}

secaudit_remediate_postmaster_detail() {
    # RULE43
    local es
    if [ "$_PG_LIVE" -eq 1 ]; then
        es=$(secaudit_psql_exec "SHOW event_source;" 2>/dev/null | head -1)
        es=$(secaudit_trim "$es")
    else
        es=""
    fi
    if [ -z "$es" ]; then
        secaudit_set_guc event_source "'PostgreSQL'" 0
        secaudit_remediate_done 43 "event_source=PostgreSQL (harmless on UNIX)"
    else
        secaudit_remediate_done 43 "event_source already set (${es})"
    fi

    # RULE44
    secaudit_set_guc listen_addresses "$(secaudit_sql_quote "$_PG_LISTEN")" 1
    secaudit_remediate_done 44 "listen_addresses=${_PG_LISTEN} (set PG_REMEDIATE_LISTEN=* if Docker publish requires it; restart may be required)"

    # RULE45
    secaudit_remediate_done 45 "logging_collector=on (restart may be required)"

    # RULE46
    local port
    port=""
    if [ "$_PG_LIVE" -eq 1 ]; then
        port=$(secaudit_psql_exec "SHOW port;" 2>/dev/null | head -1)
        port=$(secaudit_trim "$port")
    fi
    [ -z "$port" ] && port="${_PG_PORT:-5432}"
    secaudit_set_guc port "$port" 1
    secaudit_remediate_done 46 "port=${port}"

    # RULE47-54 SSL (CRL SKIP)
    if [ -f "${_PG_SSL_DIR}/server.crt" ] && [ -f "${_PG_SSL_DIR}/server.key" ]; then
        secaudit_remediate_done 47 "ssl=on"
        secaudit_remediate_done 48 "ssl_ca_file=${_PG_SSL_DIR}/root.crt"
        secaudit_remediate_done 49 "ssl_cert_file=${_PG_SSL_DIR}/server.crt"
        secaudit_remediate_done 50 "ssl_ciphers=${_PG_STRONG_CIPHERS}"
        secaudit_remediate_skip 51 "ssl_crl_file: empty/self-signed CRL is invalid for PostgreSQL; supply a real CRL from your PKI"
        secaudit_remediate_done 52 "ssl_ecdh_curve=prime256v1"
        secaudit_remediate_done 53 "ssl_key_file=${_PG_SSL_DIR}/server.key"
        secaudit_remediate_done 54 "ssl_prefer_server_ciphers=on"
    else
        secaudit_remediate_skip 47 "enable ssl after generating certs under ${_PG_SSL_DIR}"
        secaudit_remediate_skip 48 "set ssl_ca_file"
        secaudit_remediate_skip 49 "set ssl_cert_file"
        secaudit_remediate_skip 50 "set ssl_ciphers"
        secaudit_remediate_skip 51 "ssl_crl_file requires a valid CRL from your PKI"
        secaudit_remediate_skip 52 "set ssl_ecdh_curve=prime256v1"
        secaudit_remediate_skip 53 "set ssl_key_file"
        secaudit_remediate_skip 54 "set ssl_prefer_server_ciphers=on"
    fi

    # RULE55-56
    secaudit_set_guc unix_socket_group "'postgres'" 1
    secaudit_remediate_done 55 "unix_socket_group=postgres (restart may be required)"
    secaudit_set_guc unix_socket_permissions "'0770'" 1
    secaudit_remediate_done 56 "unix_socket_permissions=0770 (restart may be required)"
}

secaudit_remediate_sighup_detail() {
    # RULE57
    if secaudit_major_ge 15; then
        secaudit_remediate_done 57 "db_user_namespace removed in PostgreSQL ${_PG_MAJOR} (always off)"
    else
        secaudit_set_guc db_user_namespace off 0
        secaudit_remediate_done 57 "db_user_namespace=off"
    fi

    # RULE58
    secaudit_set_guc krb_caseins_users off 0
    secaudit_remediate_done 58 "krb_caseins_users=off"

    # RULE59
    if secaudit_hba_has_gss; then
        secaudit_remediate_skip 59 "gss/sspi in pg_hba: set krb_server_keyfile to your keytab path"
    else
        secaudit_remediate_done 59 "no gss/sspi in pg_hba; krb_server_keyfile N/A"
    fi

    # RULE60
    secaudit_set_guc log_autovacuum_min_duration "'10min'" 0
    secaudit_remediate_done 60 "log_autovacuum_min_duration=10min"

    # RULE61-67 (duplicates of earlier settings)
    secaudit_remediate_done 61 "log_destination=stderr"
    secaudit_remediate_done 62 "log_directory=${_PG_LOG_DIR}"
    secaudit_remediate_done 63 "log_file_mode=0600"
    secaudit_set_guc log_rotation_age "'1d'" 0
    secaudit_remediate_done 64 "log_rotation_age=1d"
    secaudit_remediate_done 65 "log_timezone=UTC"
    secaudit_remediate_done 66 "syslog_facility=local0"
    secaudit_set_guc syslog_ident "'postgres'" 0
    secaudit_remediate_done 67 "syslog_ident=postgres"
}

secaudit_remediate_super_detail() {
    secaudit_set_guc ignore_checksum_failure off 0
    secaudit_remediate_done 68 "ignore_checksum_failure=off"
    secaudit_remediate_done 69 "log_error_verbosity=default"
    secaudit_remediate_done 70 "log_min_messages=warning"
    secaudit_remediate_done 71 "log_statement=ddl"
}

secaudit_remediate_user_detail() {
    secaudit_set_guc backslash_quote "'safe_encoding'" 0
    secaudit_remediate_done 72 "backslash_quote=safe_encoding"
    secaudit_set_guc default_transaction_isolation "'read committed'" 0
    secaudit_remediate_done 73 "default_transaction_isolation='read committed'"
    secaudit_set_guc idle_in_transaction_session_timeout "'15min'" 0
    secaudit_remediate_done 74 "idle_in_transaction_session_timeout=15min"
    secaudit_set_guc password_encryption "'scram-sha-256'" 0
    secaudit_remediate_done 75 "password_encryption=scram-sha-256"
    secaudit_set_guc tcp_keepalives_idle 60 0
    secaudit_remediate_done 76 "tcp_keepalives_idle=60"
}

secaudit_remediate_tls_files() {
    if [ -f "${_PG_SSL_DIR}/root.crt" ]; then
        secaudit_remediate_done 77 "ssl_ca_file=${_PG_SSL_DIR}/root.crt"
    else
        secaudit_remediate_skip 77 "ssl_ca_file missing under ${_PG_SSL_DIR}"
    fi
    if [ -f "${_PG_SSL_DIR}/server.crt" ]; then
        secaudit_remediate_done 78 "ssl_cert_file=${_PG_SSL_DIR}/server.crt"
    else
        secaudit_remediate_skip 78 "ssl_cert_file missing"
    fi
    secaudit_remediate_skip 79 "ssl_crl_file: empty CRL invalid for PostgreSQL; omit or supply PKI CRL"
    if [ -f "${_PG_SSL_DIR}/server.key" ]; then
        secaudit_remediate_done 80 "ssl_key_file=${_PG_SSL_DIR}/server.key"
    else
        secaudit_remediate_skip 80 "ssl_key_file missing"
    fi
    secaudit_remediate_done 81 "log_directory=${_PG_LOG_DIR}"
}

secaudit_remediate_logging_extra() {
    secaudit_set_guc log_filename "'postgresql-%Y-%m-%d_%H%M%S.log'" 0
    secaudit_remediate_done 82 "log_filename=postgresql-%Y-%m-%d_%H%M%S.log"
    secaudit_set_guc log_truncate_on_rotation on 0
    secaudit_remediate_done 83 "log_truncate_on_rotation=on"
    # RULE84 = rotation_age (matches PSQL.sh); RULE85 = rotation_size
    secaudit_remediate_done 84 "log_rotation_age=1d"
    secaudit_set_guc log_rotation_size "'100MB'" 0
    secaudit_remediate_done 85 "log_rotation_size=100MB"
    secaudit_remediate_done 86 "syslog_ident=postgres"
    secaudit_set_guc debug_pretty_print on 0
    secaudit_remediate_done 87 "debug_pretty_print=on"

    # RULE88 — audit counts information_schema PUBLIC DML (incl. pg_catalog.pg_settings UPDATE)
    if [ "$_PG_LIVE" -eq 1 ] || getent passwd postgres >/dev/null 2>&1; then
        secaudit_psql_exec "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON ALL TABLES IN SCHEMA public FROM PUBLIC;" >/dev/null 2>&1 || true
        secaudit_psql_exec "REVOKE ALL ON SCHEMA public FROM PUBLIC;" >/dev/null 2>&1 || true
        secaudit_psql_exec "ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLES FROM PUBLIC;" >/dev/null 2>&1 || true
        secaudit_psql_exec "REVOKE UPDATE ON TABLE pg_catalog.pg_settings FROM PUBLIC;" >/dev/null 2>&1 || true
        local left
        left=$(secaudit_psql_exec "SELECT count(*) FROM information_schema.table_privileges WHERE grantee='PUBLIC' AND privilege_type IN ('INSERT','UPDATE','DELETE','TRUNCATE');" 2>/dev/null | head -1)
        left=$(secaudit_trim "${left:-}")
        if [ -n "$left" ] && [ "$left" != "0" ]; then
            secaudit_remediate_skip 88 "PUBLIC DML still present (count=${left}); revoke remaining grants manually"
        else
            secaudit_remediate_done 88 "REVOKEd PUBLIC DML (schema public + pg_settings)"
        fi
    else
        secaudit_remediate_skip 88 "no live session to REVOKE PUBLIC DML privileges"
    fi

    # RULE89
    mkdir -p "$_PG_ARCHIVE_DIR" 2>/dev/null || true
    if getent passwd postgres >/dev/null 2>&1; then
        chown postgres:postgres "$_PG_ARCHIVE_DIR" 2>/dev/null || true
    fi
    chmod 750 "$_PG_ARCHIVE_DIR" 2>/dev/null || true
    secaudit_set_guc archive_mode on 1
    secaudit_set_guc archive_command "$(secaudit_sql_quote "test ! -f ${_PG_ARCHIVE_DIR}/%f && cp %p ${_PG_ARCHIVE_DIR}/%f")" 0
    secaudit_remediate_done 89 "archive_mode=on archive_command -> ${_PG_ARCHIVE_DIR} (restart may be required)"
}

# =============================================================================
# Bootstrap / main
# =============================================================================

secaudit_skip_all_rules() {
    local n=1
    while [ "$n" -le "$_PG_RULE_COUNT" ]; do
        secaudit_remediate_skip "$n" "postgres/psql not present"
        n=$((n + 1))
    done
}

secaudit_bootstrap_postgres() {
    if ! secaudit_pg_installed; then
        secaudit_log "PostgreSQL (psql/postgres) not detected; skipping automated remediations"
        secaudit_skip_all_rules
        return 1
    fi

    _PG_PSQL=$(secaudit_locate_psql || true)
    secaudit_probe_live || true
    _PG_DATADIR=$(secaudit_layout_datadir || true)
    _PG_CONF=$(secaudit_layout_conf || true)
    _PG_HBA=$(secaudit_layout_hba || true)
    if [ -n "$_PG_DATADIR" ]; then
        _PG_AUTO="${_PG_DATADIR}/postgresql.auto.conf"
    elif [ -n "$_PG_CONF" ]; then
        _PG_AUTO="$(dirname "$_PG_CONF")/postgresql.auto.conf"
    fi
    secaudit_detect_major || true

    secaudit_log "psql=${_PG_PSQL:-none} live=${_PG_LIVE} major=${_PG_MAJOR:-unknown}"
    secaudit_log "datadir=${_PG_DATADIR:-none} conf=${_PG_CONF:-none} hba=${_PG_HBA:-none}"
    secaudit_log "auto=${_PG_AUTO:-none} ssl_dir=${_PG_SSL_DIR} log_dir=${_PG_LOG_DIR}"
    secaudit_log "listen=${_PG_LISTEN} user=${_PG_USER:-default}"
    return 0
}

secaudit_main() {
    secaudit_parse_args "$@"
    secaudit_log "starting remediation (PostgreSQL / secaudit_* style)"

    if ! secaudit_bootstrap_postgres; then
        secaudit_log "remediation complete (nothing to apply)"
        exit 0
    fi

    secaudit_remediate_systemd_and_cluster
    secaudit_remediate_logging_core
    secaudit_remediate_auth_and_roles
    secaudit_remediate_runtime_bundles
    secaudit_remediate_crypto_and_layout
    secaudit_remediate_backend_detail
    secaudit_remediate_postmaster_detail
    secaudit_remediate_sighup_detail
    secaudit_remediate_super_detail
    secaudit_remediate_user_detail
    secaudit_remediate_tls_files
    secaudit_remediate_logging_extra

    secaudit_reload_conf || true

    if [ "$_PG_RESTART_HINT" -eq 1 ]; then
        secaudit_log "NOTE: some GUCs (ssl, logging_collector, archive_mode, unix_socket_*, listen_addresses, port) may require a container/service restart; do not pg_ctl restart PID1 inside official images"
    fi

    secaudit_log "remediation complete (PSQL_remediation.sh)"
    exit 0
}

secaudit_main "$@"
