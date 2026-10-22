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
_PG_USER="${PGUSER:-${SECAUDIT_PG_USER:-}}"
_PG_PASS="${PGPASSWORD:-${SECAUDIT_PG_PASSWORD:-}}"
_PG_HOST="${PGHOST:-${SECAUDIT_PG_HOST:-}}"
_PG_PORT="${PGPORT:-${SECAUDIT_PG_PORT:-}}"
_PG_DATADIR_OVERRIDE="${PGDATA:-${SECAUDIT_PG_DATADIR:-}}"
_PG_CONF_OVERRIDE="${PGCONF:-${SECAUDIT_PG_CONF:-}}"

_PG_SKIP_IDS="1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64 65 66 67 68 69 70 71 72 73 74 75 76 77 78 79 80 81 82 83 84 85 86 87 88 89"

# --- runtime state ---
_PG_PSQL=""
_PG_LIVE=0
_PG_DATADIR=""
_PG_CONF=""
_PG_HBA=""
_PG_MAJOR=""
_PG_HBA_RULES=""
_PG_EXT_CACHE=""
declare -A _PG_GUC_SETTING=()
declare -A _PG_GUC_CONTEXT=()
declare -A _PG_GUC_SOURCE=()
declare -A _PG_GUC_UNIT=()
declare -A _PG_GUC_PENDING=()

# --- reporting ---
secaudit_report_pass() { printf 'RULE%s= PASS: %s\n' "$1" "$2"; }
secaudit_report_fail() { printf 'RULE%s= FAIL: %s\n' "$1" "${3:-$2}"; }
secaudit_report_skip() { printf 'RULE%s= SKIP: %s\n' "$1" "$2"; }
secaudit_report_error() { printf 'RULE%s= ERROR: %s\n' "$1" "$2"; }

# --- utils ---
secaudit_have_bin() { command -v "$1" >/dev/null 2>&1; }

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

secaudit_path_mode_octal() {
    if [ -e "$1" ]; then
        stat -c '%a' "$1" 2>/dev/null
    else
        printf '%s' "MISSING"
    fi
}

secaudit_path_owner_user() { [ -e "$1" ] && stat -c '%U' "$1" 2>/dev/null; }
secaudit_path_owner_group() { [ -e "$1" ] && stat -c '%G' "$1" 2>/dev/null; }

secaudit_mode_norm() {
    local v
    v=$(secaudit_trim "$1")
    v="${v#0}"; v="${v#0}"
    printf '%s' "$v"
}

secaudit_bool_on() {
    case "$(secaudit_lower "$1")" in
        on|true|yes|1) return 0 ;;
    esac
    return 1
}

secaudit_bool_off() {
    case "$(secaudit_lower "$1")" in
        off|false|no|0|"") return 0 ;;
    esac
    return 1
}

secaudit_skip_all_rules() {
    local reason="$1" id
    for id in $_PG_SKIP_IDS; do
        secaudit_report_skip "$id" "$reason"
    done
}

# --- CLI ---
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

# --- discovery ---
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

secaudit_wal_dirname() {
    if secaudit_major_ge 10; then
        printf '%s' pg_wal
    else
        printf '%s' pg_xlog
    fi
}

secaudit_psql_exec() {
    local sql="$1"
    local -a cmd
    [ -n "$_PG_PSQL" ] || return 1
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

secaudit_include_expand_spec() {
    local origin="$1" spec="$2" candidate item
    spec=$(secaudit_trim "$spec")
    spec=${spec%;}
    spec=${spec#\'}; spec=${spec%\'}
    spec=${spec#\"}; spec=${spec%\"}
    [ -n "$spec" ] || return 0
    case "$spec" in
        /*) candidate="$spec" ;;
        *)  candidate="$(dirname "$origin")/$spec" ;;
    esac
    if [ -f "$candidate" ]; then
        printf '%s\n' "$candidate"
        return 0
    fi
    if [ -d "$candidate" ]; then
        secaudit_exec_with_timeout 20 find "$candidate" -maxdepth 2 -type f \( -name '*.conf' -o -name '*.auto.conf' \) 2>/dev/null
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

secaudit_include_walk() {
    local file line key spec seen="" queue="" depth=0 resolved
    queue="${_PG_CONF}"
    while [ -n "$queue" ] && [ "$depth" -lt 60 ]; do
        depth=$((depth + 1))
        file=${queue%%$'\n'*}
        if [ "$file" = "$queue" ]; then queue=""; else queue=${queue#*$'\n'}; fi
        [ -z "$file" ] && continue
        case " $seen " in
            *" $file "*) continue ;;
        esac
        seen="$seen $file"
        [ -f "$file" ] || continue
        printf '#SRC %s\n' "$file"
        while IFS= read -r line || [ -n "$line" ]; do
            line=${line%%#*}
            line=$(secaudit_trim "$line")
            [ -n "$line" ] || continue
            key=$(secaudit_lower "$(printf '%s' "$line" | awk '{print $1}')")
            case "$key" in
                include|include_if_exists|include_dir)
                    spec=${line#*$key}
                    while IFS= read -r resolved; do
                        [ -n "$resolved" ] && queue="$queue"$'\n'"$resolved"
                    done < <(secaudit_include_expand_spec "$file" "$spec")
                    ;;
                *)
                    printf '%s\n' "$line"
                    ;;
            esac
        done < "$file"
    done
}

secaudit_file_guc() {
    local name="$1" blob
    [ -n "$_PG_CONF" ] && [ -f "$_PG_CONF" ] || return 0
    blob=$(secaudit_include_walk)
    printf '%s\n' "$blob" | awk -v want="$(secaudit_lower "$name")" '
        {
            n=tolower($1)
            if (n == want) {
                val=$0
                sub(/^[^=]*=[[:space:]]*/, "", val)
                gsub(/^[[:space:]]+/, "", val)
                gsub(/[[:space:]]+$/, "", val)
                gsub(/^['\''"]/, "", val)
                gsub(/['\''"]$/, "", val)
                last=val
            }
        }
        END { if (last != "") print last }
    '
}

secaudit_guc_load_catalog() {
    local name setting ctx src unit pend
    _PG_GUC_SETTING=()
    _PG_GUC_CONTEXT=()
    _PG_GUC_SOURCE=()
    _PG_GUC_UNIT=()
    _PG_GUC_PENDING=()
    if [ "$_PG_LIVE" -eq 1 ]; then
        while IFS='|' read -r name setting ctx src unit pend; do
            [ -n "$name" ] || continue
            _PG_GUC_SETTING["$name"]="$setting"
            _PG_GUC_CONTEXT["$name"]="$ctx"
            _PG_GUC_SOURCE["$name"]="$src"
            _PG_GUC_UNIT["$name"]="$unit"
            _PG_GUC_PENDING["$name"]="$pend"
        done < <(secaudit_psql_exec "SELECT name || '|' || COALESCE(setting,'') || '|' || COALESCE(context,'') || '|' || COALESCE(source,'') || '|' || COALESCE(unit,'') || '|' || COALESCE(pending_restart::text,'f') FROM pg_settings;")
    fi
}

secaudit_guc_get() {
    local name="$1" v
    v="${_PG_GUC_SETTING[$name]-}"
    if [ -n "$v" ]; then
        printf '%s' "$v"
        return 0
    fi
    secaudit_file_guc "$name"
}

secaudit_guc_ctx_dump() {
    local ctx="$1" name
    if [ "$_PG_LIVE" -eq 1 ]; then
        for name in "${!_PG_GUC_SETTING[@]}"; do
            if [ "${_PG_GUC_CONTEXT[$name]}" = "$ctx" ]; then
                printf '%s=%s ' "$name" "${_PG_GUC_SETTING[$name]}"
            fi
        done
        return 0
    fi
    printf '%s' "(catalog unavailable; file fallback)"
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

secaudit_unit_names() {
    local maj="${_PG_MAJOR:-}"
    printf '%s\n' postgresql
    if [ -n "$maj" ]; then
        printf '%s\n' "postgresql-${maj}" "postgresql${maj}" "postgresql@${maj}-main" "postgresql@${maj}"
    fi
    printf '%s\n' postgresql-9.6 postgresql-10 postgresql-11 postgresql-12 postgresql-13 postgresql-14 postgresql-15 postgresql-16 postgresql-17
}

secaudit_unit_is_enabled() {
    local u st
    secaudit_have_bin systemctl || return 1
    for u in $(secaudit_unit_names); do
        st=$(systemctl is-enabled "$u" 2>/dev/null || true)
        case "$st" in
            enabled|static|alias|generated|indirect)
                printf '%s:%s' "$u" "$st"
                return 0
                ;;
        esac
    done
    return 1
}

secaudit_unit_is_active() {
    local u
    secaudit_have_bin systemctl || return 1
    for u in $(secaudit_unit_names); do
        systemctl is-active "$u" 2>/dev/null | grep -q '^active$' && return 0
    done
    return 1
}

secaudit_layout_datadir() {
    local d found
    if [ -n "$_PG_DATADIR_OVERRIDE" ] && [ -d "$_PG_DATADIR_OVERRIDE" ]; then
        printf '%s' "$_PG_DATADIR_OVERRIDE"
        return 0
    fi
    d=$(secaudit_guc_get data_directory)
    if [ -n "$d" ] && [ -d "$d" ]; then
        printf '%s' "$d"
        return 0
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
    f=$(secaudit_guc_get config_file)
    [ -n "$f" ] && [ -f "$f" ] && { printf '%s' "$f"; return 0; }
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
    f=$(secaudit_guc_get hba_file)
    [ -n "$f" ] && [ -f "$f" ] && { printf '%s' "$f"; return 0; }
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

secaudit_hba_load_rules() {
    _PG_HBA_RULES=""
    if [ "$_PG_LIVE" -eq 1 ] && { [ -z "$_PG_MAJOR" ] || secaudit_major_ge 10; }; then
        _PG_HBA_RULES=$(secaudit_psql_exec "SELECT COALESCE(type,'') || '|' || COALESCE(array_to_string(database,','),'') || '|' || COALESCE(array_to_string(user_name,','),'') || '|' || COALESCE(address,'') || '|' || COALESCE(auth_method,'') FROM pg_hba_file_rules;" 2>/dev/null || true)
    fi
    if [ -z "$_PG_HBA_RULES" ] && [ -n "$_PG_HBA" ] && [ -f "$_PG_HBA" ]; then
        _PG_HBA_RULES=$(awk '
            {
                line=$0
                sub(/[[:space:]]*#.*$/, "", line)
                if (line ~ /^(local|host|hostssl|hostnossl)[[:space:]]/) {
                    n=split(line, a, /[[:space:]]+/)
                    printf "%s||||%s\n", a[1], a[n]
                }
            }
        ' "$_PG_HBA")
    fi
}

secaudit_ext_load() {
    _PG_EXT_CACHE=""
    if [ "$_PG_LIVE" -eq 1 ]; then
        _PG_EXT_CACHE=$(secaudit_psql_exec "SELECT extname FROM pg_extension UNION SELECT name FROM pg_available_extensions;" 2>/dev/null || true)
    fi
}

secaudit_ext_has() {
    local name="$1"
    printf '%s\n' "$_PG_EXT_CACHE" | grep -qx "$name" && return 0
    if [ "$_PG_LIVE" -eq 1 ]; then
        secaudit_psql_exec "SELECT 1 FROM pg_available_extensions WHERE name='${name}';" | grep -q '^1$'
        return $?
    fi
    return 1
}

secaudit_home_postgres() {
    getent passwd postgres 2>/dev/null | awk -F: '{print $6}' | head -1
}

secaudit_syslog_daemon_ok() {
    if secaudit_have_bin systemctl; then
        systemctl is-active rsyslog syslog-ng systemd-journald 2>/dev/null | grep -q '^active$' && return 0
    fi
    pgrep -x rsyslogd >/dev/null 2>&1 && return 0
    pgrep -x syslog-ng >/dev/null 2>&1 && return 0
    return 1
}

# --- GUC judge helpers (report themselves) ---
secaudit_check_guc_on() {
    local num="$1" name="$2" v
    v=$(secaudit_guc_get "$name")
    if secaudit_bool_on "$v"; then
        secaudit_report_pass "$num" "${name}=${v} src=${_PG_GUC_SOURCE[$name]:-file}"
    else
        secaudit_report_fail "$num" "${name}='${v:-unset}' (expected on)"
    fi
}

secaudit_check_guc_off() {
    local num="$1" name="$2" v
    v=$(secaudit_guc_get "$name")
    if secaudit_bool_off "$v"; then
        secaudit_report_pass "$num" "${name}=${v:-off}"
    else
        secaudit_report_fail "$num" "${name}='${v}' (expected off)"
    fi
}

secaudit_check_guc_eq() {
    local num="$1" name="$2" want="$3" v
    v=$(secaudit_guc_get "$name")
    if [ "$(secaudit_lower "$v")" = "$(secaudit_lower "$want")" ]; then
        secaudit_report_pass "$num" "${name}=${v}"
    else
        secaudit_report_fail "$num" "${name}='${v:-unset}' (expected ${want})"
    fi
}

secaudit_check_guc_not() {
    local num="$1" name="$2" bad="$3" v
    v=$(secaudit_guc_get "$name")
    if [ -z "$v" ]; then
        secaudit_report_fail "$num" "${name} is unset (must not be ${bad})"
        return 0
    fi
    if [ "$(secaudit_lower "$v")" = "$(secaudit_lower "$bad")" ]; then
        secaudit_report_fail "$num" "${name}=${v} (must not be ${bad})"
    else
        secaudit_report_pass "$num" "${name}=${v}"
    fi
}

secaudit_check_guc_set() {
    local num="$1" name="$2" v
    v=$(secaudit_guc_get "$name")
    if [ -n "$v" ]; then
        secaudit_report_pass "$num" "${name}=${v}"
    else
        secaudit_report_fail "$num" "${name} is empty"
    fi
}

# --- checks ---
secaudit_check_systemd() {
    local num="$1" enabled active wants=""
    enabled=$(secaudit_unit_is_enabled || true)
    if secaudit_unit_is_active; then
        active="active"
    else
        active="inactive"
    fi
    if secaudit_have_bin systemctl; then
        wants=$(systemctl list-dependencies multi-user.target 2>/dev/null | grep -i postgresql | tr '\n' ' ')
    fi
    if [ -n "$enabled" ]; then
        secaudit_report_pass "$num" "systemd unit enabled (${enabled}) state=${active} wants=${wants:-n/a}"
    else
        secaudit_report_fail "$num" "postgresql is not enabled in systemd (state=${active} major=${_PG_MAJOR:-unknown})"
    fi
}

secaudit_check_cluster() {
    local num="$1" dir ver mode owner
    dir="${_PG_DATADIR}"
    if [ -z "$dir" ] || [ ! -d "$dir" ]; then
        secaudit_report_fail "$num" "data_directory missing (PGDATA /var/lib/pgsql/*/data or /var/lib/postgresql)"
        return 0
    fi
    ver=$(secaudit_trim "$(tr -d '\r' < "$dir/PG_VERSION" 2>/dev/null)")
    mode=$(secaudit_path_mode_octal "$dir")
    owner=$(secaudit_path_owner_user "$dir")
    if [ -z "$ver" ]; then
        secaudit_report_fail "$num" "PG_VERSION missing at ${dir}"
        return 0
    fi
    if [ "$mode" != "700" ] || [ "$owner" != "postgres" ]; then
        secaudit_report_fail "$num" "cluster ${dir} mode=${mode} owner=${owner} (expected 700 postgres) PG_VERSION=${ver}"
        return 0
    fi
    secaudit_report_pass "$num" "PostgreSQL ${_PG_MAJOR:-$ver} cluster ${dir} PG_VERSION=${ver} mode=${mode} live=${_PG_LIVE}"
}

secaudit_check_umask() {
    local num="$1" home raw="" src="" f line
    home=$(secaudit_home_postgres)
    for f in "${home}/.bash_profile" "${home}/.profile" /var/lib/pgsql/.bash_profile; do
        [ -f "$f" ] || continue
        line=$(grep -E '^[[:space:]]*umask[[:space:]]+' "$f" 2>/dev/null | grep -v '#' | tail -1)
        if [ -n "$line" ]; then
            raw=$(printf '%s' "$line" | awk '{print $2}')
            src="$f"
            break
        fi
    done
    if [ -z "$raw" ] && secaudit_have_bin runuser; then
        raw=$(secaudit_exec_with_timeout 5 runuser -u postgres -- sh -c 'umask' 2>/dev/null)
        src="runuser"
    fi
    case "$(secaudit_trim "$raw")" in
        077|0077|77) secaudit_report_pass "$num" "postgres umask=${raw} (${src})" ;;
        "") secaudit_report_fail "$num" "postgres umask is not configured (expected 077)" ;;
        *) secaudit_report_fail "$num" "postgres umask=${raw} (expected 077)" ;;
    esac
}

secaudit_check_wheel() {
    local num="$1" members
    if ! getent group pg_wheel >/dev/null 2>&1; then
        secaudit_report_pass "$num" "pg_wheel group is not defined"
        return 0
    fi
    members=$(getent group pg_wheel | awk -F: '{print $4}')
    if printf '%s' "$members" | tr ',' '\n' | grep -qx postgres; then
        secaudit_report_fail "$num" "postgres is a member of pg_wheel (${members})"
        return 0
    fi
    secaudit_report_pass "$num" "pg_wheel members=${members:-none}"
}

secaudit_check_log_destination() {
    local num="$1" v
    v=$(secaudit_guc_get log_destination)
    if printf '%s' "$v" | grep -Eq 'stderr|csvlog|syslog'; then
        secaudit_report_pass "$num" "log_destination=${v}"
    else
        secaudit_report_fail "$num" "log_destination='${v:-unset}' (expected stderr/csvlog/syslog)"
    fi
}

secaudit_check_log_directory() {
    local num="$1" v dest
    v=$(secaudit_guc_get log_directory)
    if [ -z "$v" ] || [ "$v" = "/" ]; then
        secaudit_report_fail "$num" "log_directory='${v:-unset}'"
        return 0
    fi
    case "$v" in
        /*) dest="$v" ;;
        *) dest="${_PG_DATADIR:+$_PG_DATADIR/}$v" ;;
    esac
    secaudit_report_pass "$num" "log_directory=${v} resolved=${dest}"
}

secaudit_check_log_file_mode() {
    local num="$1" v n
    v=$(secaudit_guc_get log_file_mode)
    n=$(secaudit_mode_norm "$v")
    case "$n" in
        600|640) secaudit_report_pass "$num" "log_file_mode=${v}" ;;
        *) secaudit_report_fail "$num" "log_file_mode='${v:-unset}' (expected 0600/0640)" ;;
    esac
}

secaudit_check_syslog_facility() {
    local num="$1" v dest
    v=$(secaudit_guc_get syslog_facility)
    dest=$(secaudit_guc_get log_destination)
    case "$(secaudit_lower "$v")" in
        local0|local1|local2|local3|local4|local5|local6|local7)
            if printf '%s' "$dest" | grep -q syslog && ! secaudit_syslog_daemon_ok; then
                secaudit_report_fail "$num" "syslog_facility=${v} but rsyslog/syslog-ng is not active"
            else
                secaudit_report_pass "$num" "syslog_facility=${v} dest=${dest}"
            fi
            ;;
        *)
            secaudit_report_fail "$num" "syslog_facility='${v:-unset}' (expected local0-local7)"
            ;;
    esac
}

secaudit_check_min_messages() {
    local num="$1" v
    v=$(secaudit_lower "$(secaudit_guc_get log_min_messages)")
    [ -z "$v" ] && v="warning"
    case "$v" in
        debug5|debug4|debug3|debug2|debug1|info|notice|log|warning)
            secaudit_report_pass "$num" "log_min_messages=${v}"
            ;;
        *)
            secaudit_report_fail "$num" "log_min_messages=${v}"
            ;;
    esac
}

secaudit_check_error_verbosity() {
    local num="$1" v
    v=$(secaudit_lower "$(secaudit_guc_get log_error_verbosity)")
    [ -z "$v" ] && v="default"
    case "$v" in
        default|verbose) secaudit_report_pass "$num" "log_error_verbosity=${v}" ;;
        *) secaudit_report_fail "$num" "log_error_verbosity=${v} (expected default/verbose)" ;;
    esac
}

secaudit_check_timezone() {
    local num="$1" tz os=""
    tz=$(secaudit_guc_get log_timezone)
    if secaudit_have_bin timedatectl; then
        os=$(timedatectl 2>/dev/null | awk -F': ' '/Time zone:/{print $2; exit}' | awk '{print $1}')
    fi
    if [ -z "$tz" ]; then
        secaudit_report_fail "$num" "log_timezone unset"
        return 0
    fi
    case "$(secaudit_lower "$tz")" in
        gmt|utc|etc/utc) secaudit_report_pass "$num" "log_timezone=${tz}" ;;
        *)
            if [ "$tz" = "$os" ]; then
                secaudit_report_pass "$num" "log_timezone=${tz} matches OS"
            else
                secaudit_report_fail "$num" "log_timezone=${tz} OS=${os:-n/a}"
            fi
            ;;
    esac
}

secaudit_check_pgaudit() {
    local num="$1" libs
    libs=$(secaudit_guc_get shared_preload_libraries)
    if printf '%s' "$libs" | grep -q pgaudit; then
        secaudit_report_pass "$num" "pgaudit preloaded (${libs})"
    else
        secaudit_report_fail "$num" "pgaudit missing from shared_preload_libraries ('${libs:-unset}')"
    fi
}

secaudit_check_sudo() {
    local num="$1" hits
    hits=$(grep -E '^[[:space:]]*%pg_wheel' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -v '#' | tr '\n' ' ')
    if printf '%s' "$hits" | grep -Eq 'su[[:space:]]+-[[:space:]]*postgres|/bin/su'; then
        secaudit_report_pass "$num" "sudoers pg_wheel: ${hits}"
    else
        secaudit_report_fail "$num" "no %pg_wheel su - postgres rule"
    fi
}

secaudit_check_rolsuper() {
    local num="$1" extra
    if [ "$_PG_LIVE" -ne 1 ]; then
        secaudit_report_fail "$num" "cannot query pg_authid (no live session)"
        return 0
    fi
    extra=$(secaudit_psql_exec "SELECT rolname FROM pg_authid WHERE rolsuper AND rolname NOT IN ('postgres','rds_superuser') ORDER BY 1;")
    extra=$(secaudit_trim "$(printf '%s' "$extra" | tr '\n' ' ')")
    if [ -z "$extra" ]; then
        secaudit_report_pass "$num" "pg_authid: only postgres has rolsuper"
    else
        secaudit_report_fail "$num" "extra rolsuper in pg_authid: ${extra}"
    fi
}

secaudit_check_secdefiner() {
    local num="$1" n
    if [ "$_PG_LIVE" -ne 1 ]; then
        secaudit_report_fail "$num" "cannot query pg_proc (no live session)"
        return 0
    fi
    n=$(secaudit_psql_exec "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON p.pronamespace=n.oid WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND p.prosecdef;")
    n=$(secaudit_trim "$n")
    if [ "${n:-1}" = "0" ]; then
        secaudit_report_pass "$num" "no non-catalog SECURITY DEFINER functions"
    else
        secaudit_report_fail "$num" "found ${n} SECURITY DEFINER function(s) outside catalogs"
    fi
}

secaudit_check_default_roles() {
    local num="$1" su members
    if [ "$_PG_LIVE" -ne 1 ]; then
        secaudit_report_fail "$num" "cannot query pg_authid for default roles"
        return 0
    fi
    su=$(secaudit_psql_exec "SELECT rolname FROM pg_authid WHERE rolsuper ORDER BY 1;" | tr '\n' ' ')
    members=$(secaudit_psql_exec "SELECT r.rolname || '->' || m.rolname FROM pg_auth_members am JOIN pg_roles r ON am.roleid=r.oid JOIN pg_roles m ON am.member=m.oid WHERE r.rolname LIKE 'pg_%' ORDER BY 1;" | tr '\n' ' ')
    if [ "$(secaudit_trim "$su")" = "postgres" ]; then
        secaudit_report_pass "$num" "superusers=postgres pg_* grants=${members:-none}"
    else
        secaudit_report_fail "$num" "superusers=${su} (expected postgres only)"
    fi
}

secaudit_check_hba_local_peer() {
    local num="$1" type method users
    if [ -z "$_PG_HBA_RULES" ]; then
        secaudit_report_fail "$num" "pg_hba_file_rules/pg_hba.conf produced no rows"
        return 0
    fi
    while IFS='|' read -r type _ users _ method; do
        [ "$type" = "local" ] || continue
        if [ "$(secaudit_lower "$method")" = "trust" ]; then
            secaudit_report_fail "$num" "local ${users} uses trust"
            return 0
        fi
        if [ "$(secaudit_lower "$method")" = "peer" ]; then
            secaudit_report_pass "$num" "local ${users:-all} peer (pg_hba_file_rules)"
            return 0
        fi
    done <<EOF
${_PG_HBA_RULES}
EOF
    secaudit_report_fail "$num" "no local peer rule in pg_hba_file_rules"
}

secaudit_check_hba_host_auth() {
    local num="$1" type method weak="" scram="" md5="" other=""
    if [ -z "$_PG_HBA_RULES" ]; then
        secaudit_report_fail "$num" "no host rules available"
        return 0
    fi
    while IFS='|' read -r type _ _ _ method; do
        printf '%s' "$type" | grep -q '^host' || continue
        case "$(secaudit_lower "$method")" in
            trust|password)
                weak="${weak} ${method}"
                ;;
            ident)
                weak="${weak} ident"
                ;;
            scram-sha-256)
                scram="${scram} scram"
                ;;
            md5)
                md5="${md5} md5"
                ;;
            cert|gss|sspi|pam|ldap|radius|reject)
                other="${other} ${method}"
                ;;
        esac
    done <<EOF
${_PG_HBA_RULES}
EOF
    if [ -n "${weak// /}" ]; then
        secaudit_report_fail "$num" "host pg_hba uses trust/password/ident (${weak# })"
        return 0
    fi
    if [ -n "${scram// /}" ]; then
        if [ -n "${md5// /}" ]; then
            secaudit_report_pass "$num" "host uses scram-sha-256 (md5 also present; prefer scram) ${other}"
        else
            secaudit_report_pass "$num" "host uses scram-sha-256 ${other}"
        fi
        return 0
    fi
    if [ -n "${md5// /}" ]; then
        if secaudit_major_ge 10; then
            secaudit_report_pass "$num" "host uses md5 (scram-sha-256 preferred on PG${_PG_MAJOR}+) ${other}"
        else
            secaudit_report_pass "$num" "host uses md5 (scram-sha-256 not available on PG${_PG_MAJOR:-9}) ${other}"
        fi
        return 0
    fi
    if [ -n "${other// /}" ]; then
        secaudit_report_pass "$num" "host uses ${other# }"
        return 0
    fi
    secaudit_report_fail "$num" "host lines lack md5/scram/cert"
}

secaudit_check_backend() {
    local num="$1" ign delay conn disc
    ign=$(secaudit_guc_get ignore_system_indexes)
    delay=$(secaudit_guc_get post_auth_delay)
    conn=$(secaudit_guc_get log_connections)
    disc=$(secaudit_guc_get log_disconnections)
    [ -z "$ign" ] && ign=off
    [ -z "$delay" ] && delay=0
    if secaudit_bool_off "$ign" && [ "$delay" = "0" ] && secaudit_bool_on "$conn" && secaudit_bool_on "$disc"; then
        secaudit_report_pass "$num" "backend ignore_system_indexes=${ign} post_auth_delay=${delay} log_connections=${conn} log_disconnections=${disc}"
    else
        secaudit_report_fail "$num" "backend ignore_system_indexes=${ign} post_auth_delay=${delay} log_connections=${conn} log_disconnections=${disc}"
    fi
}

secaudit_check_postmaster_bundle() {
    local num="$1" dump
    dump=$(secaudit_guc_ctx_dump postmaster)
    secaudit_report_pass "$num" "postmaster context: listen=$(secaudit_guc_get listen_addresses) port=$(secaudit_guc_get port) ssl=$(secaudit_guc_get ssl) ${dump:0:160}"
}

secaudit_check_sighup_bundle() {
    local num="$1"
    secaudit_report_pass "$num" "SIGHUP: dest=$(secaudit_guc_get log_destination) dir=$(secaudit_guc_get log_directory) mode=$(secaudit_guc_get log_file_mode) ident=$(secaudit_guc_get syslog_ident)"
}

secaudit_check_super_bundle() {
    local num="$1"
    secaudit_report_pass "$num" "superuser: ignore_checksum_failure=$(secaudit_guc_get ignore_checksum_failure) log_statement=$(secaudit_guc_get log_statement) log_min_messages=$(secaudit_guc_get log_min_messages)"
}

secaudit_check_user_bundle() {
    local num="$1"
    secaudit_report_pass "$num" "user: password_encryption=$(secaudit_guc_get password_encryption) isolation=$(secaudit_guc_get default_transaction_isolation) backslash_quote=$(secaudit_guc_get backslash_quote)"
}

secaudit_check_listen() {
    local num="$1" v
    v=$(secaudit_guc_get listen_addresses)
    [ -z "$v" ] && v="localhost"
    if printf '%s' "$v" | grep -q '\*'; then
        secaudit_report_fail "$num" "listen_addresses=${v} is wildcard"
    else
        secaudit_report_pass "$num" "listen_addresses=${v}"
    fi
}

secaudit_check_ssl_file() {
    local num="$1" name="$2" hint="$3" v
    v=$(secaudit_guc_get "$name")
    if [ -z "$v" ]; then
        secaudit_report_fail "$num" "${name} is empty"
        return 0
    fi
    if [ -n "$hint" ] && ! printf '%s' "$v" | grep -q "$hint"; then
        secaudit_report_fail "$num" "${name}=${v} (expected ${hint})"
        return 0
    fi
    secaudit_report_pass "$num" "${name}=${v}"
}

secaudit_check_ssl_ciphers() {
    local num="$1" v cleaned
    v=$(secaudit_guc_get ssl_ciphers)
    if [ -z "$v" ] || [ "$(secaudit_lower "$v")" = "none" ]; then
        secaudit_report_fail "$num" "ssl_ciphers='${v:-unset}'"
        return 0
    fi
    # Ignore OpenSSL exclusion tokens like !DES / !MD5 / !NULL so negated weak
    # suites do not false-positive the substring match.
    cleaned=$(printf '%s' "$v" | sed -E 's/![A-Za-z0-9_+-]+//g')
    if printf '%s' "$cleaned" | grep -qiE '(^|:)(RC4|MD5|NULL|EXPORT|DES|3DES)(:|$)'; then
        secaudit_report_fail "$num" "ssl_ciphers weak tokens (${v})"
        return 0
    fi
    secaudit_report_pass "$num" "ssl_ciphers=${v}"
}

secaudit_check_unix_perm() {
    local num="$1" v n
    v=$(secaudit_guc_get unix_socket_permissions)
    [ -z "$v" ] && v="0777"
    n=$(secaudit_mode_norm "$v")
    case "$n" in
        770|700|750) secaudit_report_pass "$num" "unix_socket_permissions=${v}" ;;
        *) secaudit_report_fail "$num" "unix_socket_permissions=${v} (expected 0770, not 0777)" ;;
    esac
}

secaudit_check_unix_group() {
    local num="$1" v
    v=$(secaudit_guc_get unix_socket_group)
    if [ -n "$v" ]; then
        secaudit_report_pass "$num" "unix_socket_group=${v}"
    else
        secaudit_report_fail "$num" "unix_socket_group is empty"
    fi
}

secaudit_check_event_source() {
    local num="$1" v
    v=$(secaudit_guc_get event_source)
    secaudit_report_pass "$num" "event_source=${v:-unset (UNIX)}"
}

secaudit_check_krb_key() {
    local num="$1" v rules
    v=$(secaudit_guc_get krb_server_keyfile)
    rules=$(printf '%s\n' "$_PG_HBA_RULES" | awk -F'|' '$5 ~ /gss|sspi/')
    if [ -n "$rules" ] && [ -z "$v" ]; then
        secaudit_report_fail "$num" "krb_server_keyfile empty while gss/sspi is in pg_hba_file_rules"
        return 0
    fi
    secaudit_report_pass "$num" "krb_server_keyfile=${v:-unset (no gss)}"
}

secaudit_check_autovacuum_log() {
    local num="$1" v
    v=$(secaudit_guc_get log_autovacuum_min_duration)
    [ -z "$v" ] && v="-1"
    if [ "$v" = "-1" ]; then
        secaudit_report_fail "$num" "log_autovacuum_min_duration=-1"
    else
        secaudit_report_pass "$num" "log_autovacuum_min_duration=${v} unit=${_PG_GUC_UNIT[log_autovacuum_min_duration]:-ms}"
    fi
}

secaudit_check_rotation_age() {
    local num="$1" v
    v=$(secaudit_guc_get log_rotation_age)
    [ -z "$v" ] && v="1440"
    if [ "$v" = "0" ]; then
        secaudit_report_fail "$num" "log_rotation_age=0"
    else
        secaudit_report_pass "$num" "log_rotation_age=${v} unit=${_PG_GUC_UNIT[log_rotation_age]:-min}"
    fi
}

secaudit_check_password_encryption() {
    local num="$1" v
    v=$(secaudit_guc_get password_encryption)
    case "$(secaudit_lower "$v")" in
        scram-sha-256)
            secaudit_report_pass "$num" "password_encryption=scram-sha-256 (PG${_PG_MAJOR:-})"
            ;;
        md5|on)
            if secaudit_major_ge 10; then
                secaudit_report_pass "$num" "password_encryption=${v} (md5 accepted on PG${_PG_MAJOR}; scram-sha-256 preferred)"
            else
                secaudit_report_pass "$num" "password_encryption=${v} (md5 expected on PG${_PG_MAJOR:-9})"
            fi
            ;;
        *)
            secaudit_report_fail "$num" "password_encryption='${v:-unset}'"
            ;;
    esac
}

secaudit_check_idle_tx() {
    local num="$1" v
    v=$(secaudit_guc_get idle_in_transaction_session_timeout)
    [ -z "$v" ] && v="0"
    if [ "$v" = "0" ]; then
        secaudit_report_fail "$num" "idle_in_transaction_session_timeout=0"
    else
        secaudit_report_pass "$num" "idle_in_transaction_session_timeout=${v}"
    fi
}

secaudit_check_fips() {
    local num="$1" flag ossl=""
    flag=$(cat /proc/sys/crypto/fips_enabled 2>/dev/null || true)
    secaudit_have_bin openssl && ossl=$(openssl version 2>/dev/null)
    if [ "$flag" = "1" ]; then
        secaudit_report_pass "$num" "fips_enabled=1 ${ossl}"
    else
        secaudit_report_fail "$num" "fips_enabled=${flag:-missing}"
    fi
}

secaudit_check_ssl() {
    local num="$1" v cert key
    v=$(secaudit_guc_get ssl)
    cert=$(secaudit_guc_get ssl_cert_file)
    key=$(secaudit_guc_get ssl_key_file)
    if secaudit_bool_on "$v" && [ -n "$cert" ] && [ -n "$key" ]; then
        secaudit_report_pass "$num" "ssl=${v} cert=${cert} key=${key}"
    else
        secaudit_report_fail "$num" "ssl='${v:-off}' cert='${cert}' key='${key}'"
    fi
}

secaudit_check_pgcrypto() {
    local num="$1" installed
    if secaudit_ext_has pgcrypto; then
        installed=$(secaudit_psql_exec "SELECT 1 FROM pg_extension WHERE extname='pgcrypto';" 2>/dev/null | head -1)
        secaudit_report_pass "$num" "pgcrypto available (installed_in_db=${installed:-0})"
    else
        secaudit_report_fail "$num" "pgcrypto not in pg_available_extensions"
    fi
}

secaudit_check_config_outside() {
    local num="$1" data cfg hba ident bad=""
    data="${_PG_DATADIR}"
    cfg=$(secaudit_guc_get config_file)
    hba=$(secaudit_guc_get hba_file)
    ident=$(secaudit_guc_get ident_file)
    [ -z "$cfg" ] && cfg="$_PG_CONF"
    [ -z "$hba" ] && hba="$_PG_HBA"
    if [ -z "$data" ]; then
        secaudit_report_fail "$num" "data_directory unknown"
        return 0
    fi
    case "$cfg" in "$data"/*) bad="${bad} config_file" ;; esac
    case "$hba" in "$data"/*) bad="${bad} hba_file" ;; esac
    case "$ident" in "$data"/*) bad="${bad} ident_file" ;; esac
    if [ -n "$bad" ]; then
        secaudit_report_fail "$num" "inside PGDATA:${bad} cfg=${cfg} hba=${hba}"
    else
        secaudit_report_pass "$num" "config_file=${cfg} hba_file=${hba} ident_file=${ident} outside ${data}"
    fi
}

secaudit_check_subdirs() {
    local num="$1" logdir wal walname
    logdir=$(secaudit_guc_get log_directory)
    walname=$(secaudit_wal_dirname)
    wal="${_PG_DATADIR:+$_PG_DATADIR/$walname}"
    case "$logdir" in
        /*)
            case "$logdir" in
                "${_PG_DATADIR}"/*)
                    secaudit_report_fail "$num" "log_directory ${logdir} still under PGDATA"
                    return 0
                    ;;
            esac
            ;;
        log|pg_log|"")
            secaudit_report_fail "$num" "log_directory=${logdir:-log} remains inside the data directory"
            return 0
            ;;
    esac
    if [ -d "$wal" ] && [ ! -L "$wal" ]; then
        secaudit_report_fail "$num" "${walname} is inside PGDATA (${wal}); relocate WAL"
        return 0
    fi
    secaudit_report_pass "$num" "log_directory=${logdir} ${walname}=$(ls -ld "$wal" 2>/dev/null | awk '{print $1,$9}')"
}

secaudit_check_pgbackrest() {
    local num="$1"
    if secaudit_have_bin pgbackrest && secaudit_exec_with_timeout 10 pgbackrest info >/dev/null 2>&1; then
        secaudit_report_pass "$num" "pgbackrest info succeeded"
    else
        secaudit_report_fail "$num" "pgBackRest missing or unconfigured"
    fi
}

secaudit_check_pg_permissions() {
    local num="$1"
    if secaudit_ext_has pg_permissions || secaudit_ext_has pg_permission; then
        secaudit_report_pass "$num" "pg_permissions extension is available"
    else
        secaudit_report_fail "$num" "pg_permissions / pg_permission is not installed"
    fi
}

secaudit_check_set_user() {
    local num="$1"
    if secaudit_ext_has set_user; then
        secaudit_report_pass "$num" "set_user is available"
    else
        secaudit_report_fail "$num" "set_user extension is not installed"
    fi
}

secaudit_check_log_filename() {
    local num="$1" v
    v=$(secaudit_guc_get log_filename)
    if [ -z "$v" ]; then
        secaudit_report_fail "$num" "log_filename unset"
        return 0
    fi
    if printf '%s' "$v" | grep -q '%'; then
        secaudit_report_pass "$num" "log_filename=${v} (strftime)"
    else
        secaudit_report_fail "$num" "log_filename=${v} should contain a strftime % pattern"
    fi
}

secaudit_check_rotation_size() {
    local num="$1" v
    v=$(secaudit_guc_get log_rotation_size)
    [ -z "$v" ] && v="10240"
    if [ "$v" = "0" ]; then
        secaudit_report_fail "$num" "log_rotation_size=0 disables size rotation"
    else
        secaudit_report_pass "$num" "log_rotation_size=${v}"
    fi
}

secaudit_check_dml_revoke() {
    local num="$1" admin public_dml closed
    if [ "$_PG_LIVE" -ne 1 ]; then
        secaudit_report_fail "$num" "cannot inspect table_privileges / pg_database.datallowconn"
        return 0
    fi
    admin=$(secaudit_psql_exec "SELECT rolname FROM pg_authid WHERE rolcanlogin AND NOT rolsuper AND (rolcreatedb OR rolcreaterole) ORDER BY 1;" | tr '\n' ' ')
    public_dml=$(secaudit_psql_exec "SELECT count(*) FROM information_schema.table_privileges WHERE grantee='PUBLIC' AND privilege_type IN ('INSERT','UPDATE','DELETE','TRUNCATE');")
    closed=$(secaudit_psql_exec "SELECT datname FROM pg_database WHERE NOT datallowconn AND datname NOT IN ('template0') ORDER BY 1;" | tr '\n' ' ')
    if [ -n "$(secaudit_trim "$admin")" ]; then
        secaudit_report_fail "$num" "login roles with CREATEDB/CREATEROLE: ${admin}"
        return 0
    fi
    if [ "${public_dml:-0}" != "0" ]; then
        secaudit_report_fail "$num" "PUBLIC has DML on ${public_dml} table(s)"
        return 0
    fi
    secaudit_report_pass "$num" "DML locked down; datallowconn=false extras=${closed:-none}"
}

secaudit_check_wal_archive() {
    local num="$1" mode cmd
    mode=$(secaudit_guc_get archive_mode)
    cmd=$(secaudit_guc_get archive_command)
    if secaudit_bool_on "$mode" || [ "$(secaudit_lower "$mode")" = "always" ]; then
        if [ -n "$cmd" ] && [ "$cmd" != "(disabled)" ]; then
            secaudit_report_pass "$num" "archive_mode=${mode} archive_command set"
            return 0
        fi
    fi
    secaudit_report_fail "$num" "WAL archiving archive_mode=${mode} archive_command='${cmd}'"
}

secaudit_check_backslash() {
    local num="$1" v
    v=$(secaudit_lower "$(secaudit_guc_get backslash_quote)")
    [ -z "$v" ] && v="safe_encoding"
    case "$v" in
        safe_encoding|off) secaudit_report_pass "$num" "backslash_quote=${v}" ;;
        *) secaudit_report_fail "$num" "backslash_quote=${v}" ;;
    esac
}

secaudit_check_isolation() {
    local num="$1" v
    v=$(secaudit_lower "$(secaudit_guc_get default_transaction_isolation)")
    if printf '%s' "$v" | grep -q 'read committed'; then
        secaudit_report_pass "$num" "default_transaction_isolation=${v}"
    else
        secaudit_report_fail "$num" "default_transaction_isolation='${v:-unset}'"
    fi
}

secaudit_check_tcpka() {
    local num="$1"
    secaudit_report_pass "$num" "tcp_keepalives_idle=$(secaudit_guc_get tcp_keepalives_idle)"
}

secaudit_check_db_user_ns() {
    local num="$1" v
    if secaudit_major_ge 15; then
        secaudit_report_pass "$num" "db_user_namespace removed in PostgreSQL ${_PG_MAJOR} (always off)"
        return 0
    fi
    v=$(secaudit_guc_get db_user_namespace)
    if secaudit_bool_off "$v"; then
        secaudit_report_pass "$num" "db_user_namespace=${v:-off}"
    else
        secaudit_report_fail "$num" "db_user_namespace=${v}"
    fi
}

secaudit_check_krb_case() {
    local num="$1" v
    v=$(secaudit_guc_get krb_caseins_users)
    if secaudit_bool_off "$v"; then
        secaudit_report_pass "$num" "krb_caseins_users=${v:-off}"
    else
        secaudit_report_fail "$num" "krb_caseins_users=${v}"
    fi
}

secaudit_check_ssl_prefer() {
    local num="$1" v
    v=$(secaudit_guc_get ssl_prefer_server_ciphers)
    if secaudit_bool_on "$v" || [ -z "$v" ]; then
        secaudit_report_pass "$num" "ssl_prefer_server_ciphers=${v:-on}"
    else
        secaudit_report_fail "$num" "ssl_prefer_server_ciphers=${v}"
    fi
}

secaudit_check_ssl_ecdh() {
    local num="$1" v
    v=$(secaudit_guc_get ssl_ecdh_curve)
    [ -z "$v" ] && v="prime256v1"
    if [ "$(secaudit_lower "$v")" = "none" ]; then
        secaudit_report_fail "$num" "ssl_ecdh_curve=none"
    else
        secaudit_report_pass "$num" "ssl_ecdh_curve=${v}"
    fi
}

secaudit_check_ignore_checksum() {
    local num="$1" v
    v=$(secaudit_guc_get ignore_checksum_failure)
    if secaudit_bool_off "$v"; then
        secaudit_report_pass "$num" "ignore_checksum_failure=${v:-off}"
    else
        secaudit_report_fail "$num" "ignore_checksum_failure=${v}"
    fi
}

# --- runners ---
secaudit_run_systemd_and_cluster() {
    secaudit_check_systemd 1
    secaudit_check_cluster 2
    secaudit_check_umask 3
    secaudit_check_wheel 4
}

secaudit_run_logging_core() {
    secaudit_check_log_destination 5
    secaudit_check_guc_on 6 logging_collector
    secaudit_check_log_directory 7
    secaudit_check_log_file_mode 8
    secaudit_check_syslog_facility 9
    secaudit_check_min_messages 10
    secaudit_check_guc_off 11 debug_print_parse
    secaudit_check_guc_off 12 debug_print_rewritten
    secaudit_check_guc_off 13 debug_print_plan
    secaudit_check_guc_on 14 log_connections
    secaudit_check_guc_on 15 log_disconnections
    secaudit_check_error_verbosity 16
    secaudit_check_guc_off 17 log_hostname
    secaudit_check_guc_not 18 log_statement none
    secaudit_check_timezone 19
    secaudit_check_pgaudit 20
}

secaudit_run_auth_and_roles() {
    secaudit_check_sudo 21
    secaudit_check_rolsuper 22
    secaudit_check_secdefiner 23
    secaudit_check_default_roles 24
    secaudit_check_hba_local_peer 25
    secaudit_check_hba_host_auth 26
}

secaudit_run_runtime_bundles() {
    secaudit_check_backend 27
    secaudit_check_postmaster_bundle 28
    secaudit_check_sighup_bundle 29
    secaudit_check_super_bundle 30
    secaudit_check_user_bundle 31
}

secaudit_run_crypto_and_layout() {
    secaudit_check_fips 32
    secaudit_check_ssl 33
    secaudit_check_pgcrypto 34
    secaudit_check_config_outside 35
    secaudit_check_subdirs 36
    secaudit_check_pgbackrest 37
    secaudit_check_pg_permissions 38
    secaudit_check_set_user 39
}

secaudit_run_backend_detail() {
    secaudit_check_guc_on 40 log_connections
    secaudit_check_guc_on 41 log_disconnections
    secaudit_check_guc_eq 42 post_auth_delay 0
}

secaudit_run_postmaster_detail() {
    secaudit_check_event_source 43
    secaudit_check_listen 44
    secaudit_check_guc_on 45 logging_collector
    secaudit_check_guc_set 46 port
    secaudit_check_guc_on 47 ssl
    secaudit_check_ssl_file 48 ssl_ca_file ""
    secaudit_check_ssl_file 49 ssl_cert_file server.crt
    secaudit_check_ssl_ciphers 50
    secaudit_check_ssl_file 51 ssl_crl_file ""
    secaudit_check_ssl_ecdh 52
    secaudit_check_ssl_file 53 ssl_key_file server.key
    secaudit_check_ssl_prefer 54
    secaudit_check_unix_group 55
    secaudit_check_unix_perm 56
}

secaudit_run_sighup_detail() {
    secaudit_check_db_user_ns 57
    secaudit_check_krb_case 58
    secaudit_check_krb_key 59
    secaudit_check_autovacuum_log 60
    secaudit_check_log_destination 61
    secaudit_check_log_directory 62
    secaudit_check_log_file_mode 63
    secaudit_check_rotation_age 64
    secaudit_check_guc_set 65 log_timezone
    secaudit_check_syslog_facility 66
    secaudit_check_guc_set 67 syslog_ident
}

secaudit_run_super_detail() {
    secaudit_check_ignore_checksum 68
    secaudit_check_error_verbosity 69
    secaudit_check_min_messages 70
    secaudit_check_guc_not 71 log_statement none
}

secaudit_run_user_detail() {
    secaudit_check_backslash 72
    secaudit_check_isolation 73
    secaudit_check_idle_tx 74
    secaudit_check_password_encryption 75
    secaudit_check_tcpka 76
}

secaudit_run_tls_files() {
    secaudit_check_ssl_file 77 ssl_ca_file ""
    secaudit_check_ssl_file 78 ssl_cert_file server.crt
    secaudit_check_ssl_file 79 ssl_crl_file ""
    secaudit_check_ssl_file 80 ssl_key_file server.key
    secaudit_check_log_directory 81
}

secaudit_run_logging_extra() {
    secaudit_check_log_filename 82
    secaudit_check_guc_on 83 log_truncate_on_rotation
    secaudit_check_rotation_age 84
    secaudit_check_rotation_size 85
    secaudit_check_guc_set 86 syslog_ident
    secaudit_check_guc_on 87 debug_pretty_print
    secaudit_check_dml_revoke 88
    secaudit_check_wal_archive 89
}

# --- bootstrap / main ---
secaudit_bootstrap_postgres() {
    if ! secaudit_pg_installed; then
        secaudit_skip_all_rules "PostgreSQL (psql/postgres) is not installed"
        return 1
    fi

    _PG_PSQL=$(secaudit_locate_psql || true)
    secaudit_probe_live || true
    secaudit_guc_load_catalog
    _PG_DATADIR=$(secaudit_layout_datadir || true)
    _PG_CONF=$(secaudit_layout_conf || true)
    _PG_HBA=$(secaudit_layout_hba || true)
    secaudit_detect_major || true
    secaudit_hba_load_rules
    secaudit_ext_load
    return 0
}

secaudit_main() {
    secaudit_parse_args "$@"

    if ! secaudit_bootstrap_postgres; then
        exit 0
    fi

    secaudit_run_systemd_and_cluster
    secaudit_run_logging_core
    secaudit_run_auth_and_roles
    secaudit_run_runtime_bundles
    secaudit_run_crypto_and_layout
    secaudit_run_backend_detail
    secaudit_run_postmaster_detail
    secaudit_run_sighup_detail
    secaudit_run_super_detail
    secaudit_run_user_detail
    secaudit_run_tls_files
    secaudit_run_logging_extra
    exit 0
}

secaudit_main "$@"
