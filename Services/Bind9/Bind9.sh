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

BIND9_FIND_CAP="${BIND9_FIND_CAP:-25}"
BIND9_CMD_CAP="${BIND9_CMD_CAP:-8}"
BIND9_XFER_CAP="${BIND9_XFER_CAP:-3}"
BIND9_XFER_PER_NS_CAP="${BIND9_XFER_PER_NS_CAP:-3}"
BIND9_XFER_IN_CAP="${BIND9_XFER_IN_CAP:-10}"
BIND9_KEY_MAX_AGE_DAYS="${BIND9_KEY_MAX_AGE_DAYS:-365}"
BIND9_LOG_VERSIONS_MIN="${BIND9_LOG_VERSIONS_MIN:-3}"

PRIV_USERS="root named bind"
PRIV_GROUPS="root named bind dns"

# --- runtime state ---
_BIND_PRIMARY_CONF=""
_BIND_LAYOUT_ROOT=""
_BIND_PARSED_FILE=""
_BIND_SCRATCH_DIR=""
_BIND_DAEMON_ACCT=""
_BIND_DAEMON_GRP=""
_BIND_WORKDIR="/var/named"
_BIND_CHROOT_PATH=""
_BIND_PID_PATH=""
_BIND_UNIT_BLOB=""
_BIND_SYNTAX_NOTE=""
_BIND_VISITED_CONFS=""

# --- bootstrap / reporting ---
sec_audit_report_pass() { printf 'RULE%s= PASS: %s\n' "$1" "$2"; }
sec_audit_report_fail() { printf 'RULE%s= FAIL: %s\n' "$1" "${3:-$2}"; }
sec_audit_report_skip() { printf 'RULE%s= SKIP: %s\n' "$1" "$2"; }
sec_audit_report_error() { printf 'RULE%s= ERROR: %s\n' "$1" "$2"; }

# --- string / cmd utils ---
sec_audit_have_bin() { command -v "$1" >/dev/null 2>&1; }

sec_audit_trim_ws() {
    local s="${1-}"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

sec_audit_exec_with_timeout() {
    local secs="$1"
    shift
    if sec_audit_have_bin timeout; then
        timeout "$secs" "$@"
    else
        "$@"
    fi
}

sec_audit_path_mode_octal() {
    local p="$1"
    if [ -e "$p" ]; then
        stat -c '%a' "$p" 2>/dev/null || stat -f '%OLp' "$p" 2>/dev/null
    else
        printf '%s' "MISSING"
    fi
}

sec_audit_path_owner_user() {
    local p="$1"
    [ -e "$p" ] && stat -c '%U' "$p" 2>/dev/null
}

sec_audit_path_owner_group() {
    local p="$1"
    [ -e "$p" ] && stat -c '%G' "$p" 2>/dev/null
}

sec_audit_mode_world_writable() {
    local m="$1"
    [ -n "$m" ] && [ "$m" != "MISSING" ] && [ $((8#$m & 8#007)) -ne 0 ] 2>/dev/null
}

sec_audit_name_in_list() {
    local needle="$1" hay="$2" x
    for x in $hay; do
        [ "$x" = "$needle" ] && return 0
    done
    return 1
}

sec_audit_user_is_priv() {
    sec_audit_name_in_list "$1" "$PRIV_USERS"
}

sec_audit_group_is_priv() {
    sec_audit_name_in_list "$1" "$PRIV_GROUPS"
}

sec_audit_purge_scratch() {
    [ -n "$_BIND_SCRATCH_DIR" ] && [ -d "$_BIND_SCRATCH_DIR" ] && rm -rf "$_BIND_SCRATCH_DIR"
}
trap sec_audit_purge_scratch EXIT

# --- discovery ---
sec_audit_named_bin_path() {
    local c
    for c in named; do
        sec_audit_have_bin "$c" && { command -v "$c"; return 0; }
    done
    for c in /usr/sbin/named /usr/local/sbin/named /usr/sbin/bind9 /opt/bind/sbin/named; do
        [ -x "$c" ] && { printf '%s\n' "$c"; return 0; }
    done
    return 1
}

sec_audit_checker_bin_path() {
    local c
    sec_audit_have_bin named-checkconf && { command -v named-checkconf; return 0; }
    for c in /usr/sbin/named-checkconf /usr/local/sbin/named-checkconf; do
        [ -x "$c" ] && { printf '%s\n' "$c"; return 0; }
    done
    return 1
}

sec_audit_rndc_bin_path() {
    local c
    sec_audit_have_bin rndc && { command -v rndc; return 0; }
    for c in /usr/sbin/rndc /usr/local/sbin/rndc; do
        [ -x "$c" ] && { printf '%s\n' "$c"; return 0; }
    done
    return 1
}

sec_audit_daemon_alive() {
    if sec_audit_have_bin pgrep; then
        pgrep -x named >/dev/null 2>&1 && return 0
        pgrep -x bind9 >/dev/null 2>&1 && return 0
    fi
    ps -eo comm= 2>/dev/null | grep -qx named && return 0
    ps -eo args= 2>/dev/null | grep -vE 'grep|named-checkconf|Bind9' | grep -qE '/(s)?bin/named( |$)' && return 0
    return 1
}

sec_audit_daemon_user() {
    local u
    u=$(ps -eo user=,comm= 2>/dev/null | awk '$2=="named" || $2=="bind9" {print $1; exit}')
    if [ -n "$u" ]; then
        printf '%s\n' "$u"
        return 0
    fi
    ps -eo user=,args= 2>/dev/null | awk '
        /\/(s)?bin\/named( |$)/ && $0 !~ /grep|named-checkconf|Bind9/ { print $1; exit }
    '
}

sec_audit_daemon_group() {
    local u g
    u=$(sec_audit_daemon_user)
    if [ -n "$u" ]; then
        g=$(id -gn "$u" 2>/dev/null)
        [ -n "$g" ] && { printf '%s\n' "$g"; return 0; }
    fi
    for g in named bind dns; do
        getent group "$g" >/dev/null 2>&1 && { printf '%s\n' "$g"; return 0; }
    done
}

sec_audit_candidate_conf_paths() {
    printf '%s\n' \
        /etc/bind/named.conf \
        /etc/named.conf \
        /etc/named/named.conf \
        /usr/local/etc/namedb/named.conf \
        /usr/local/etc/named.conf \
        /var/named/chroot/etc/named.conf \
        /etc/namedb/named.conf \
        /opt/bind/etc/named.conf
}

sec_audit_layout_probe() {
    local c root
    _BIND_PRIMARY_CONF=""
    _BIND_LAYOUT_ROOT=""
    if [ -n "${BIND_NAMED_CONF:-}" ] && [ -f "${BIND_NAMED_CONF}" ]; then
        _BIND_PRIMARY_CONF="$BIND_NAMED_CONF"
        _BIND_LAYOUT_ROOT="${BIND_LAYOUT_ROOT:-$(dirname "$_BIND_PRIMARY_CONF")}"
        return 0
    fi
    for c in $(sec_audit_candidate_conf_paths); do
        if [ -f "$c" ]; then
            _BIND_PRIMARY_CONF="$c"
            _BIND_LAYOUT_ROOT=$(dirname "$c")
            break
        fi
    done
    if [ -z "$_BIND_PRIMARY_CONF" ]; then
        for root in /etc/bind /etc/named /var/named /usr/local/etc/namedb /var/named/chroot/etc; do
            if [ -d "$root" ]; then
                _BIND_LAYOUT_ROOT="$root"
                [ -f "$root/named.conf" ] && _BIND_PRIMARY_CONF="$root/named.conf"
                break
            fi
        done
    fi
    [ -z "$_BIND_LAYOUT_ROOT" ] && [ -n "$_BIND_PRIMARY_CONF" ] && _BIND_LAYOUT_ROOT=$(dirname "$_BIND_PRIMARY_CONF")
    [ -z "$_BIND_LAYOUT_ROOT" ] && _BIND_LAYOUT_ROOT="/etc/bind"
}

sec_audit_software_present() {
    sec_audit_named_bin_path >/dev/null 2>&1 && return 0
    sec_audit_checker_bin_path >/dev/null 2>&1 && return 0
    sec_audit_rndc_bin_path >/dev/null 2>&1 && return 0
    sec_audit_daemon_alive && return 0
    sec_audit_have_bin bind9 && return 0
    return 1
}

sec_audit_conf_present() {
    [ -n "$_BIND_PRIMARY_CONF" ] && [ -f "$_BIND_PRIMARY_CONF" ]
}

sec_audit_pid_path_of() {
    local from_opt c
    from_opt=$(sec_audit_scalar_in "$(sec_audit_options_body)" "pid-file" | tr -d '"')
    if [ -n "$from_opt" ]; then
        printf '%s\n' "$from_opt"
        return 0
    fi
    for c in /run/named/named.pid /var/run/named/named.pid /run/named.pid \
             /var/run/named.pid /run/bind/named.pid /var/named/named.pid; do
        [ -e "$c" ] && { printf '%s\n' "$c"; return 0; }
    done
    printf '%s\n' "/run/named/named.pid"
}

sec_audit_chroot_root_of() {
    local args unit t
    args=$(ps -eo args= 2>/dev/null | awk '/\/(s)?bin\/named( |$)/ && $0 !~ /grep|named-checkconf/ {print; exit}')
    if printf '%s' "$args" | grep -qE '[[:space:]]-t[[:space:]]'; then
        t=$(printf '%s' "$args" | sed -E 's/.*[[:space:]]-t[[:space:]]+([^[:space:]]+).*/\1/')
        [ -n "$t" ] && { printf '%s\n' "$t"; return 0; }
    fi
    unit=$(sec_audit_unit_file_text)
    if printf '%s' "$unit" | grep -qE '^RootDirectory='; then
        printf '%s' "$unit" | awk -F= '/^RootDirectory=/{print $2; exit}'
        return 0
    fi
    if printf '%s' "$unit" | grep -qE 'ExecStart=.*[[:space:]]-t[[:space:]]'; then
        printf '%s' "$unit" | sed -nE 's/.*[[:space:]]-t[[:space:]]+([^[:space:]]+).*/\1/p' | head -1
        return 0
    fi
    for t in /var/named/chroot /chroot/named /etc/bind/chroot; do
        if [ -d "$t" ] && [ -f "$t/etc/named.conf" -o -f "$t/etc/bind/named.conf" ]; then
            printf '%s\n' "$t"
            return 0
        fi
    done
    return 1
}

sec_audit_unit_file_text() {
    local u
    if [ -n "$_BIND_UNIT_BLOB" ]; then
        printf '%s\n' "$_BIND_UNIT_BLOB"
        return 0
    fi
    for u in \
        /etc/systemd/system/named.service \
        /etc/systemd/system/bind9.service \
        /etc/systemd/system/named-chroot.service \
        /lib/systemd/system/named.service \
        /lib/systemd/system/bind9.service \
        /usr/lib/systemd/system/named.service \
        /usr/lib/systemd/system/bind9.service \
        /lib/systemd/system/named-chroot.service
    do
        if [ -f "$u" ]; then
            _BIND_UNIT_BLOB=$(cat "$u" 2>/dev/null)
            printf '%s\n' "$_BIND_UNIT_BLOB"
            return 0
        fi
    done
    if sec_audit_have_bin systemctl; then
        _BIND_UNIT_BLOB=$(systemctl cat named.service 2>/dev/null || systemctl cat bind9.service 2>/dev/null || true)
        [ -n "$_BIND_UNIT_BLOB" ] && { printf '%s\n' "$_BIND_UNIT_BLOB"; return 0; }
    fi
    return 1
}

sec_audit_host_ipv4_list() {
    if sec_audit_have_bin ip; then
        ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1
        return 0
    fi
    if sec_audit_have_bin hostname; then
        hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
    fi
}

sec_audit_dns_filter_present() {
    if sec_audit_have_bin iptables; then
        sec_audit_exec_with_timeout "$BIND9_CMD_CAP" iptables -L INPUT -n 2>/dev/null | grep -qE 'dpt:53|dpts:53' && return 0
    fi
    if sec_audit_have_bin nft; then
        sec_audit_exec_with_timeout "$BIND9_CMD_CAP" nft list ruleset 2>/dev/null | grep -qE 'dport[[:space:]]+53|dport[[:space:]]+\{[^}]*53' && return 0
    fi
    if sec_audit_have_bin firewall-cmd; then
        firewall-cmd --list-services 2>/dev/null | grep -qw dns && return 0
        firewall-cmd --list-ports 2>/dev/null | grep -qE '(^| )53/(tcp|udp)' && return 0
    fi
    if sec_audit_have_bin ufw; then
        ufw status 2>/dev/null | grep -qiE '53/(tcp|udp)|[[:space:]]DNS[[:space:]]' && return 0
    fi
    return 1
}

# --- comment strip / include walk -------------------------------------------

sec_audit_strip_named_comments() {
    awk '
        BEGIN { in_c=0 }
        {
            out=""; i=1; n=length($0); in_s=0
            while (i<=n) {
                c=substr($0,i,1)
                nxt=substr($0,i+1,1)
                if (in_c) {
                    if (c=="*" && nxt=="/") { in_c=0; i+=2; continue }
                    i++; continue
                }
                if (in_s) {
                    out=out c
                    if (c=="\\" && i<n) { out=out nxt; i+=2; continue }
                    if (c=="\"") in_s=0
                    i++; continue
                }
                if (c=="\"") { in_s=1; out=out c; i++; continue }
                if (c=="/" && nxt=="*") { in_c=1; i+=2; continue }
                if (c=="/" && nxt=="/") break
                if (c=="#") break
                out=out c
                i++
            }
            print out
        }
    '
}

sec_audit_include_targets() {
    local origin="$1" spec="$2" base cand item
    spec=$(printf '%s' "$spec" | tr -d "\"'" | sed 's/;[[:space:]]*$//' | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')
    [ -n "$spec" ] || return 0
    base=$(dirname "$origin")
    case "$spec" in
        /*) cand="$spec" ;;
        *)  cand="$base/$spec" ;;
    esac
    if [ -f "$cand" ]; then
        printf '%s\n' "$cand"
        return 0
    fi
    if [ -n "$_BIND_LAYOUT_ROOT" ] && [ -f "$_BIND_LAYOUT_ROOT/$spec" ]; then
        printf '%s\n' "$_BIND_LAYOUT_ROOT/$spec"
        return 0
    fi
    case "$cand" in
        *\*)
            for item in $cand; do
                [ -f "$item" ] && printf '%s\n' "$item"
            done
            if [ -n "$_BIND_LAYOUT_ROOT" ]; then
                for item in $_BIND_LAYOUT_ROOT/$spec; do
                    [ -f "$item" ] && printf '%s\n' "$item"
                done
            fi
            ;;
    esac
}

sec_audit_already_visited() {
    local p="$1"
    case " $_BIND_VISITED_CONFS " in
        *" $p "*) return 0 ;;
    esac
    return 1
}

sec_audit_ingest_conf_file() {
    local file="$1" resolved line spec inc stripped
    [ -f "$file" ] || return 0
    resolved=$(readlink -f "$file" 2>/dev/null || realpath "$file" 2>/dev/null || printf '%s' "$file")
    sec_audit_already_visited "$resolved" && return 0
    _BIND_VISITED_CONFS="$_BIND_VISITED_CONFS $resolved"
    stripped=$(sec_audit_strip_named_comments < "$file")
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            *include*)
                spec=$(printf '%s' "$line" | sed -nE 's/^[[:space:]]*include[[:space:]]+([^;]+);.*/\1/p')
                if [ -n "$spec" ]; then
                    while IFS= read -r inc; do
                        [ -n "$inc" ] && sec_audit_ingest_conf_file "$inc"
                    done < <(sec_audit_include_targets "$file" "$spec")
                    continue
                fi
                ;;
        esac
        printf '%s\n' "$line" >> "$_BIND_PARSED_FILE"
    done <<< "$stripped"
}

sec_audit_supplemental_bind_files() {
    local f d
    for f in \
        "$_BIND_LAYOUT_ROOT/named.conf.options" \
        "$_BIND_LAYOUT_ROOT/named.conf.local" \
        "$_BIND_LAYOUT_ROOT/named.conf.default-zones" \
        "$_BIND_LAYOUT_ROOT/named.conf.logging" \
        "$_BIND_LAYOUT_ROOT/rndc.key" \
        "$_BIND_LAYOUT_ROOT/rndc.conf" \
        "$_BIND_LAYOUT_ROOT/bind.keys" \
        /etc/rndc.key \
        /etc/rndc.conf \
        /etc/named.rfc1912.zones \
        /etc/named.root.key \
        /etc/bind.keys
    do
        [ -f "$f" ] || continue
        sec_audit_ingest_conf_file "$f"
    done
    for d in "$_BIND_LAYOUT_ROOT/named.conf.d" "$_BIND_LAYOUT_ROOT/conf.d" /etc/named.d /etc/bind/named.conf.d; do
        [ -d "$d" ] || continue
        sec_audit_exec_with_timeout "$BIND9_FIND_CAP" find "$d" -type f \( -name '*.conf' -o -name '*.inc' -o -name '*.key' \) 2>/dev/null | while IFS= read -r f; do
            sec_audit_ingest_conf_file "$f"
        done
    done
}

sec_audit_checker_print() {
    local bin t
    bin=$(sec_audit_checker_bin_path 2>/dev/null) || return 1
    [ -n "$_BIND_PRIMARY_CONF" ] && [ -f "$_BIND_PRIMARY_CONF" ] || return 1
    t=$(sec_audit_chroot_root_of 2>/dev/null || true)
    if [ -n "$t" ] && [ -d "$t" ]; then
        if sec_audit_exec_with_timeout "$BIND9_CMD_CAP" "$bin" -t "$t" -p "$_BIND_PRIMARY_CONF" > "$_BIND_PARSED_FILE" 2>/dev/null; then
            _BIND_SYNTAX_NOTE="named-checkconf -t $t -p ok"
            return 0
        fi
    fi
    if sec_audit_exec_with_timeout "$BIND9_CMD_CAP" "$bin" -p "$_BIND_PRIMARY_CONF" > "$_BIND_PARSED_FILE" 2>/dev/null; then
        _BIND_SYNTAX_NOTE="named-checkconf -p ok"
        return 0
    fi
    if sec_audit_exec_with_timeout "$BIND9_CMD_CAP" "$bin" "$_BIND_PRIMARY_CONF" >/dev/null 2>&1; then
        _BIND_SYNTAX_NOTE="named-checkconf ok (unexpanded)"
        return 1
    fi
    _BIND_SYNTAX_NOTE="named-checkconf reported errors"
    return 1
}

sec_audit_build_parsed_view() {
    _BIND_SCRATCH_DIR=$(mktemp -d /tmp/bind9-audit.XXXXXX 2>/dev/null || mktemp -d)
    _BIND_PARSED_FILE="$_BIND_SCRATCH_DIR/parsed.conf"
    : > "$_BIND_PARSED_FILE"
    _BIND_VISITED_CONFS=""
    if sec_audit_checker_print; then
        return 0
    fi
    : > "$_BIND_PARSED_FILE"
    _BIND_VISITED_CONFS=""
    if [ -n "$_BIND_PRIMARY_CONF" ] && [ -f "$_BIND_PRIMARY_CONF" ]; then
        sec_audit_ingest_conf_file "$_BIND_PRIMARY_CONF"
    fi
    sec_audit_supplemental_bind_files
}

sec_audit_parsed_text() {
    [ -f "$_BIND_PARSED_FILE" ] && cat "$_BIND_PARSED_FILE" 2>/dev/null
}

# --- statement / block parsing ----------------------------------------------

sec_audit_extract_blocks() {
    local keyword="$1"
    local src="${2:-}"
    if [ -z "$src" ]; then
        [ -f "$_BIND_PARSED_FILE" ] || return 0
        src=$(cat "$_BIND_PARSED_FILE")
    fi
    printf '%s\n' "$src" | awk -v kw="$keyword" '
        BEGIN { cap=0; depth=0; buf=""; opened=0 }
        {
            line=$0
            low=tolower(line)
            klen=length(kw)
            if (!cap) {
                pos=index(low, kw)
                if (pos>0) {
                    prefix=substr(line,1,pos-1)
                    if (prefix ~ /(^|[[:space:]])$/ || prefix=="") {
                        rest=substr(low,pos+klen,1)
                        if (rest=="" || rest ~ /[[:space:]"'\''{]/) {
                            if (low ~ "^[[:space:]]*" kw "[[:space:]]" || low ~ "^[[:space:]]*" kw "[[:space:]]*{" || low ~ "^[[:space:]]*" kw "\"") {
                                cap=1; depth=0; buf=""; opened=0
                            }
                        }
                    }
                }
            }
            if (cap) {
                if (buf=="") buf=line
                else buf=buf "\n" line
                inq=0
                for (i=1; i<=length(line); i++) {
                    c=substr(line,i,1)
                    if (c=="\"" && inq==0) { inq=1; continue }
                    if (c=="\"" && inq==1) { inq=0; continue }
                    if (inq) continue
                    if (c=="{") { depth++; opened=1 }
                    if (c=="}") depth--
                }
                if (opened && depth<=0) {
                    print buf
                    print "-----END-----"
                    cap=0; buf=""; opened=0; depth=0
                }
            }
        }
    '
}

sec_audit_options_body() {
    sec_audit_extract_blocks "options" | awk '
        /^-----END-----$/ { exit }
        { print }
    ' | awk '
        BEGIN { p=0 }
        {
            if (!p) {
                sub(/^[^{]*\{[[:space:]]*/,"")
                p=1
            }
            body=body (body==""?"":"\n") $0
        }
        END {
            sub(/\}[[:space:]]*;?[[:space:]]*$/,"",body)
            print body
        }
    '
}

sec_audit_logging_body() {
    sec_audit_extract_blocks "logging" | awk '
        /^-----END-----$/ { next }
        { print }
    '
}

sec_audit_controls_body() {
    sec_audit_extract_blocks "controls" | awk '
        /^-----END-----$/ { next }
        { print }
    '
}

sec_audit_zone_blocks() {
    sec_audit_extract_blocks "zone"
}

sec_audit_view_blocks() {
    sec_audit_extract_blocks "view"
}

sec_audit_key_blocks() {
    sec_audit_extract_blocks "key"
}

sec_audit_server_blocks() {
    sec_audit_extract_blocks "server"
}

sec_audit_channel_blocks() {
    local logb
    logb=$(sec_audit_logging_body)
    [ -n "$logb" ] || return 0
    sec_audit_extract_blocks "channel" "$logb"
}

sec_audit_scalar_in() {
    local blob="$1" name="$2"
    printf '%s\n' "$blob" | awk -v n="$name" '
        BEGIN { nl=tolower(n) }
        {
            line=$0
            sub(/[[:space:]]*$/,"",line)
            low=tolower(line)
            if (low ~ "^[[:space:]]*" nl "[[:space:]]+" && low !~ "^[[:space:]]*" nl "[[:space:]]*\\{") {
                sub(/^[[:space:]]+/,"",line)
                sub("^[Kk]" substr(n,2) "[[:space:]]+","",line)
                # drop keyword regardless of case
                i=1
                while (i<=length(line) && substr(line,i,1) !~ /[[:space:]]/) i++
                while (i<=length(line) && substr(line,i,1) ~ /[[:space:]]/) i++
                val=substr(line,i)
                sub(/;.*$/,"",val)
                gsub(/^[[:space:]"]+|[";[:space:]]+$/,"",val)
                if (val!="") { print val; exit }
            }
        }
    '
}

sec_audit_clause_records() {
    local keyword="$1" src="${2:-}" buf="" line
    while IFS= read -r line || [ -n "$line" ]; do
        if [ "$line" = "-----END-----" ]; then
            printf '%s\0' "$buf"
            buf=""
        else
            if [ -z "$buf" ]; then
                buf="$line"
            else
                buf="$buf
$line"
            fi
        fi
    done < <(sec_audit_extract_blocks "$keyword" "$src")
    [ -n "$buf" ] && printf '%s\0' "$buf"
}

sec_audit_acl_in() {
    local blob="$1" name="$2"
    printf '%s\n' "$blob" | awk -v n="$name" '
        BEGIN { nl=tolower(n); cap=0; depth=0; buf=""; opened=0 }
        {
            line=$0
            low=tolower(line)
            if (!cap) {
                if (low ~ "^[[:space:]]*" nl "([^[:alnum:]_-]|$)") {
                    if (index(line, "{") || index(line, ";")==0) {
                        cap=1; depth=0; buf=""; opened=0
                    }
                }
            }
            if (cap) {
                buf=buf " " line
                inq=0
                for (i=1; i<=length(line); i++) {
                    c=substr(line,i,1)
                    if (c=="\"" && inq==0) { inq=1; continue }
                    if (c=="\"" && inq==1) { inq=0; continue }
                    if (inq) continue
                    if (c=="{") { depth++; opened=1 }
                    if (c=="}") depth--
                }
                if (opened && depth<=0) {
                    inner=buf
                    sub(/^[^{]*\{/,"",inner)
                    sub(/\}[^}]*$/,"",inner)
                    gsub(/;/," ",inner)
                    gsub(/[[:space:]]+/," ",inner)
                    print inner
                    exit
                }
            }
        }
    '
}

sec_audit_numeric_in() {
    local blob="$1" name="$2" raw
    raw=$(sec_audit_scalar_in "$blob" "$name")
    printf '%s' "$raw" | grep -oE '[0-9]+' | head -1
}

sec_audit_blob_has() {
    local blob="$1" pat="$2"
    printf '%s\n' "$blob" | grep -qiE "$pat"
}

sec_audit_acl_permits_any() {
    # named-checkconf -p may quote ACL tokens ("any").
    printf '%s' "$1" | tr -d '"' | grep -qiE '(^|[[:space:]{;])any([[:space:]};]|$)'
}

sec_audit_acl_is_none() {
    local s
    # named-checkconf -p may emit { "none"; } — strip quotes/braces/semicolons.
    s=$(printf '%s' "$1" | tr -d '"' | sed -E 's/[[:space:];{}]+/ /g')
    s=$(sec_audit_trim_ws "$s")
    printf '%s' "$s" | grep -qiE '^none$'
}

sec_audit_acl_has_peers() {
    local s="$1"
    printf '%s' "$s" | grep -qiE 'key[[:space:]]' && return 0
    printf '%s' "$s" | grep -qE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' && return 0
    printf '%s' "$s" | grep -qE '[0-9a-fA-F]*:[0-9a-fA-F:]+' && return 0
    printf '%s' "$s" | grep -qiE '(localhost|localnets|localnets|!)' && return 0
    printf '%s' "$s" | grep -qE '/[0-9]+' && return 0
    printf '%s' "$s" | grep -qiE '[A-Za-z][A-Za-z0-9_-]*' && ! sec_audit_acl_is_none "$s" && ! sec_audit_acl_permits_any "$s"
}

sec_audit_acl_is_tight() {
    local s="$1"
    [ -n "$s" ] || return 1
    sec_audit_acl_permits_any "$s" && return 1
    sec_audit_acl_is_none "$s" && return 1
    sec_audit_acl_has_peers "$s"
}

# --- roles / derived state --------------------------------------------------

sec_audit_serves_master() {
    sec_audit_zone_blocks | grep -qiE 'type[[:space:]]+(primary|master)[[:space:];]'
}

sec_audit_serves_slave() {
    sec_audit_zone_blocks | grep -qiE 'type[[:space:]]+(secondary|slave)[[:space:];]'
}

sec_audit_serves_resolver() {
    local opt rec
    opt=$(sec_audit_options_body)
    rec=$(sec_audit_scalar_in "$opt" "recursion")
    printf '%s' "$rec" | grep -qi '^no$' && return 1
    sec_audit_zone_blocks | grep -qE 'zone[[:space:]]+"\."' && return 0
    sec_audit_blob_has "$opt" 'recursion[[:space:]]+yes' && return 0
    [ -z "$rec" ] && ! sec_audit_serves_master
}

sec_audit_serves_split() {
    local n
    n=$(sec_audit_view_blocks | sec_audit_count_pat '^[[:space:]]*view[[:space:]]')
    [ "$n" -ge 2 ] 2>/dev/null && return 0
    sec_audit_parsed_text | grep -qiE 'view[[:space:]]+"?(internal|external|inside|outside|private|public)'
}

sec_audit_updates_allowed() {
    local opt z
    opt=$(sec_audit_options_body)
    z=$(sec_audit_zone_blocks)
    if sec_audit_blob_has "$opt" 'allow-update' || sec_audit_blob_has "$z" 'allow-update' || sec_audit_blob_has "$z" 'update-policy'; then
        sec_audit_acl_is_none "$(sec_audit_acl_in "$opt" "allow-update")" && ! sec_audit_blob_has "$z" 'update-policy' && ! sec_audit_blob_has "$z" 'allow-update[[:space:]]*\{[^}]*key' && return 1
        sec_audit_blob_has "$z" 'allow-update[[:space:]]*\{[[:space:]]*none' && ! sec_audit_blob_has "$z" 'update-policy' && return 1
        return 0
    fi
    return 1
}

sec_audit_workdir_of() {
    local d
    d=$(sec_audit_scalar_in "$(sec_audit_options_body)" "directory" | tr -d '"')
    if [ -n "$d" ] && [ -d "$d" ]; then
        printf '%s\n' "$d"
        return 0
    fi
    for d in /var/cache/bind /var/named /usr/local/etc/namedb /etc/bind /var/named/chroot/var/named; do
        [ -d "$d" ] && { printf '%s\n' "$d"; return 0; }
    done
    printf '%s\n' "${_BIND_LAYOUT_ROOT:-/var/named}"
}

sec_audit_builtin_zone_file() {
    case "$1" in
        /usr/share/*|*/db.root|*/named.ca|*/named.root|*/root.hints|root.hints|named.ca)
            return 0 ;;
        */db.local|*/db.127|*/db.0|*/db.255|db.local|db.127|db.0|db.255)
            return 0 ;;
        */bind.keys|*/managed-keys.bind*|*.jnl|*/managed-keys.id)
            return 0 ;;
    esac
    return 1
}

sec_audit_resolve_zone_file() {
    local zf="$1"
    zf=$(printf '%s' "$zf" | tr -d '";' | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')
    [ -n "$zf" ] || return 1
    case "$zf" in
        /*) printf '%s\n' "$zf"; return 0 ;;
    esac
    if [ -f "$_BIND_WORKDIR/$zf" ]; then
        printf '%s\n' "$_BIND_WORKDIR/$zf"
        return 0
    fi
    if [ -n "$_BIND_LAYOUT_ROOT" ] && [ -f "$_BIND_LAYOUT_ROOT/$zf" ]; then
        printf '%s\n' "$_BIND_LAYOUT_ROOT/$zf"
        return 0
    fi
    printf '%s\n' "$_BIND_WORKDIR/$zf"
}

sec_audit_zone_file_paths() {
    local zf path
    while IFS= read -r zf; do
        [ -z "$zf" ] && continue
        path=$(sec_audit_resolve_zone_file "$zf")
        sec_audit_builtin_zone_file "$path" && continue
        [ -f "$path" ] && printf '%s\n' "$path"
    done < <(
        sec_audit_zone_blocks | awk '
            BEGIN { IGNORECASE=1 }
            $1=="file" {
                v=$2
                gsub(/[";]/,"",v)
                if (v!="") print v
            }
        ' | sort -u
    )
}

sec_audit_search_roots() {
    local r
    for r in "$_BIND_WORKDIR" "$_BIND_LAYOUT_ROOT" /etc/bind /var/named /var/cache/bind \
             /usr/local/etc/namedb /etc/named /var/named/chroot/var/named /var/named/chroot/etc; do
        [ -n "$r" ] && [ -d "$r" ] && printf '%s\n' "$r"
    done | sort -u
}

sec_audit_tsig_material_paths() {
    local r f
    {
        for f in "$_BIND_LAYOUT_ROOT/rndc.key" /etc/rndc.key /etc/bind/rndc.key /etc/named/rndc.key; do
            [ -f "$f" ] && printf '%s\n' "$f"
        done
        while IFS= read -r r; do
            sec_audit_exec_with_timeout "$BIND9_FIND_CAP" find "$r" -maxdepth 4 -type f \( -name 'rndc.key' -o -name '*.key' \) 2>/dev/null
        done < <(sec_audit_search_roots)
    } | while IFS= read -r f; do
        [ -f "$f" ] || continue
        case "$f" in
            */K*.key|K*.key) continue ;;
        esac
        if grep -qiE 'HMAC|algorithm[[:space:]]+hmac|secret[[:space:]]+"' "$f" 2>/dev/null; then
            printf '%s\n' "$f"
        fi
    done | sort -u
}

sec_audit_dnssec_material_paths() {
    local r f
    while IFS= read -r r; do
        sec_audit_exec_with_timeout "$BIND9_FIND_CAP" find "$r" -maxdepth 5 -type f \( -name 'K*.key' -o -name 'K*.private' -o -name '*.private' \) 2>/dev/null
    done < <(sec_audit_search_roots) | sort -u
}

sec_audit_keygen_material_paths() {
    local r
    while IFS= read -r r; do
        sec_audit_exec_with_timeout "$BIND9_FIND_CAP" find "$r" -maxdepth 5 -type f \( -name 'K*.key' -o -name 'K*.private' \) 2>/dev/null
    done < <(sec_audit_search_roots) | sort -u
}

sec_audit_zsk_private_paths() {
    local f
    while IFS= read -r f; do
        [ -f "$f" ] || continue
        case "$f" in
            *.private) ;;
            *) continue ;;
        esac
        if grep -qiE 'ZSK|zone-signing|Private-key-format' "$f" 2>/dev/null; then
            if grep -qiE 'KSK|key-signing' "$f" 2>/dev/null; then
                continue
            fi
            printf '%s\n' "$f"
        fi
    done < <(sec_audit_dnssec_material_paths)
}

sec_audit_ksk_private_paths() {
    local f
    while IFS= read -r f; do
        [ -f "$f" ] || continue
        case "$f" in
            *.private) ;;
            *) continue ;;
        esac
        grep -qiE 'KSK|key-signing' "$f" 2>/dev/null && printf '%s\n' "$f"
    done < <(sec_audit_dnssec_material_paths)
}

sec_audit_core_conf_paths() {
    local f
    [ -n "$_BIND_PRIMARY_CONF" ] && [ -f "$_BIND_PRIMARY_CONF" ] && printf '%s\n' "$_BIND_PRIMARY_CONF"
    for f in \
        "$_BIND_LAYOUT_ROOT/named.conf.options" \
        "$_BIND_LAYOUT_ROOT/named.conf.local" \
        "$_BIND_LAYOUT_ROOT/named.conf.default-zones" \
        "$_BIND_LAYOUT_ROOT/named.conf.logging"
    do
        [ -f "$f" ] && printf '%s\n' "$f"
    done
}

sec_audit_journal_paths() {
    local r
    while IFS= read -r r; do
        sec_audit_exec_with_timeout "$BIND9_FIND_CAP" find "$r" -maxdepth 5 -type f -name '*.jnl' 2>/dev/null
    done < <(sec_audit_search_roots) | sort -u
}

sec_audit_view_named() {
    printf '%s' "$1" | awk '
        BEGIN { IGNORECASE=1 }
        /^[[:space:]]*view[[:space:]]/ {
            if (match($0, /"[^"]+"/)) {
                s=substr($0,RSTART+1,RLENGTH-2)
                print s
                exit
            }
            print $2
            exit
        }
    ' | tr -d '";{}'
}

sec_audit_view_match_clients() {
    sec_audit_acl_in "$1" "match-clients"
}

sec_audit_notify_chain_ok() {
    local blob="$1"
    sec_audit_blob_has "$blob" 'notify[[:space:]]+explicit' && sec_audit_blob_has "$blob" 'also-notify' && return 0
    sec_audit_blob_has "$blob" 'notify[[:space:]]+yes[[:space:]]*;' && sec_audit_blob_has "$blob" 'also-notify' && return 0
    sec_audit_blob_has "$blob" 'notify[[:space:]]+yes[[:space:]]*;' && return 0
    sec_audit_blob_has "$blob" 'also-notify' && return 0
    return 1
}

sec_audit_rndc_material_path() {
    local f
    for f in "$_BIND_LAYOUT_ROOT/rndc.key" /etc/rndc.key /etc/bind/rndc.key /etc/named/rndc.key "$_BIND_LAYOUT_ROOT/rndc.conf" /etc/rndc.conf; do
        [ -f "$f" ] && { printf '%s\n' "$f"; return 0; }
    done
    return 1
}

sec_audit_rndc_status_note() {
    local bin
    bin=$(sec_audit_rndc_bin_path 2>/dev/null) || { printf '%s' "rndc absent"; return 1; }
    sec_audit_exec_with_timeout "$BIND9_CMD_CAP" "$bin" status >/dev/null 2>&1 && { printf '%s' "rndc status ok"; return 0; }
    printf '%s' "rndc present but status failed"
    return 1
}

sec_audit_key_secret_values() {
    sec_audit_key_blocks | awk '
        BEGIN { IGNORECASE=1 }
        $1=="secret" {
            v=$2
            gsub(/[";]/,"",v)
            if (v!="") print v
        }
    ' | sort -u
}

sec_audit_key_statement_count() {
    sec_audit_key_blocks | sec_audit_count_pat '^[[:space:]]*key[[:space:]]'
}

sec_audit_count_lines() {
    local n=0
    while IFS= read -r _; do
        n=$((n + 1))
    done
    printf '%s' "$n"
}

sec_audit_count_pat() {
    local n
    n=$(grep -cE "$1" 2>/dev/null || true)
    printf '%s' "${n:-0}"
}

# --- checks -----------------------------------------------------------------

sec_audit_check_xfer_limit() {
    local num="$1"
    local opt srv val best=""
    if ! sec_audit_serves_master; then
        sec_audit_report_pass "$num" "not applicable (not a primary name server)"
        return 0
    fi
    opt=$(sec_audit_options_body)
    srv=$(sec_audit_server_blocks)
    val=$(sec_audit_numeric_in "$opt" "transfers")
    [ -z "$val" ] && val=$(sec_audit_numeric_in "$srv" "transfers")
    if [ -z "$val" ]; then
        sec_audit_report_fail "$num" "transfers missing in options/server blocks (limit <=${BIND9_XFER_CAP} required on primary)"
        return 0
    fi
    if [ "$val" -le "$BIND9_XFER_CAP" ] 2>/dev/null; then
        sec_audit_report_pass "$num" "transfers=$val (limit <=${BIND9_XFER_CAP}) ${_BIND_SYNTAX_NOTE:+; $_BIND_SYNTAX_NOTE}"
    else
        sec_audit_report_fail "$num" "transfers=$val exceeds limit of ${BIND9_XFER_CAP}"
    fi
}

sec_audit_check_xfer_per_ns() {
    local num="$1"
    local opt val
    if ! sec_audit_serves_slave; then
        sec_audit_report_pass "$num" "not applicable (not a secondary name server)"
        return 0
    fi
    opt=$(sec_audit_options_body)
    val=$(sec_audit_numeric_in "$opt" "transfers-per-ns")
    if [ -z "$val" ]; then
        sec_audit_report_fail "$num" "transfers-per-ns missing in options (limit <=${BIND9_XFER_PER_NS_CAP} required on secondary)"
        return 0
    fi
    if [ "$val" -le "$BIND9_XFER_PER_NS_CAP" ] 2>/dev/null; then
        sec_audit_report_pass "$num" "transfers-per-ns=$val (limit <=${BIND9_XFER_PER_NS_CAP})"
    else
        sec_audit_report_fail "$num" "transfers-per-ns=$val exceeds limit of ${BIND9_XFER_PER_NS_CAP}"
    fi
}

sec_audit_check_xfer_in() {
    local num="$1"
    local opt val
    if ! sec_audit_serves_slave; then
        sec_audit_report_pass "$num" "not applicable (not a secondary name server)"
        return 0
    fi
    opt=$(sec_audit_options_body)
    val=$(sec_audit_numeric_in "$opt" "transfers-in")
    if [ -z "$val" ]; then
        sec_audit_report_fail "$num" "transfers-in missing in options (limit <=${BIND9_XFER_IN_CAP} required on secondary)"
        return 0
    fi
    if [ "$val" -le "$BIND9_XFER_IN_CAP" ] 2>/dev/null; then
        sec_audit_report_pass "$num" "transfers-in=$val (limit <=${BIND9_XFER_IN_CAP})"
    else
        sec_audit_report_fail "$num" "transfers-in=$val exceeds limit of ${BIND9_XFER_IN_CAP}"
    fi
}

sec_audit_check_xfer_out() {
    local num="$1"
    local opt val extra=""
    opt=$(sec_audit_options_body)
    val=$(sec_audit_numeric_in "$opt" "transfers-out")
    sec_audit_blob_has "$opt" 'rate-limit[[:space:]]*\{' && extra="${extra}; rate-limit present"
    sec_audit_blob_has "$opt" 'tcp-clients' && extra="${extra}; tcp-clients=$(sec_audit_numeric_in "$opt" "tcp-clients")"
    sec_audit_blob_has "$opt" 'recursive-clients' && extra="${extra}; recursive-clients=$(sec_audit_numeric_in "$opt" "recursive-clients")"
    if [ -n "$val" ]; then
        sec_audit_report_pass "$num" "transfers-out=$val configured${extra}"
    else
        sec_audit_report_fail "$num" "transfers-out missing or not numeric in options${extra}"
    fi
}

sec_audit_print_flag_in_channels() {
    local num="$1" flag="$2" want="${3:-yes}" ch name val found=0 bad=0 sample=""
    while IFS= read -r ch; do
        [ -z "$ch" ] && continue
        [ "$ch" = "-----END-----" ] && continue
        val=$(sec_audit_scalar_in "$ch" "$flag")
        if [ -n "$val" ]; then
            found=$((found + 1))
            sample="$flag=$val"
            printf '%s' "$val" | grep -qiE "^${want}$" || bad=$((bad + 1))
        fi
    done < <(sec_audit_channel_blocks)
    if [ "$found" -eq 0 ]; then
        if sec_audit_blob_has "$(sec_audit_logging_body)" "${flag}[[:space:]]+${want}"; then
            sec_audit_report_pass "$num" "$flag is $want in logging"
            return 0
        fi
        sec_audit_report_fail "$num" "$flag statement missing in logging channels"
        return 0
    fi
    if [ "$bad" -eq 0 ]; then
        sec_audit_report_pass "$num" "$flag is $want in $found logging channel(s) ($sample)"
    else
        sec_audit_report_fail "$num" "$flag present in $found channel(s) but $bad not set to $want"
    fi
}

sec_audit_check_print_severity() {
    sec_audit_print_flag_in_channels "$1" "print-severity" "yes"
}
sec_audit_check_print_time() {
    sec_audit_print_flag_in_channels "$1" "print-time" "yes"
}
sec_audit_check_print_category() {
    sec_audit_print_flag_in_channels "$1" "print-category" "yes"
}
sec_audit_check_audit_coverage() {
    local num="$1"
    local logb cats missing="" nch
    logb=$(sec_audit_logging_body)
    if [ -z "$logb" ]; then
        sec_audit_report_fail "$num" "logging block missing"
        return 0
    fi
    nch=$(printf '%s\n' "$logb" | grep -ciE '^[[:space:]]*channel[[:space:]]' || true)
    nch=${nch:-0}
    sec_audit_blob_has "$logb" 'category[[:space:]]+"?default"?' || missing="${missing} default-category"
    sec_audit_blob_has "$logb" 'channel[[:space:]]' || missing="${missing} channel"
    for cats in security xfer-in xfer-out notify update dnssec; do
        sec_audit_blob_has "$logb" "category[[:space:]]+\"?${cats}\"?" || missing="${missing} category:${cats}"
    done
    if [ -z "$missing" ]; then
        sec_audit_report_pass "$num" "logging has $nch channel(s) and security-relevant categories (default,security,xfer,notify,update,dnssec) ${_BIND_SYNTAX_NOTE:+; $_BIND_SYNTAX_NOTE}"
    elif sec_audit_blob_has "$logb" 'category[[:space:]]+"?default"?' && [ "$nch" -ge 1 ] 2>/dev/null; then
        sec_audit_report_pass "$num" "logging has $nch channel(s) and default category (optional missing:$missing)"
    else
        sec_audit_report_fail "$num" "logging incomplete (channels=$nch missing:$missing)"
    fi
}

sec_audit_check_zsk_only_online() {
    local num="$1"
    local priv ksk n
    n=$(sec_audit_zsk_private_paths | sec_audit_count_lines)
    ksk=$(sec_audit_ksk_private_paths | sec_audit_count_lines)
    if ! sec_audit_updates_allowed; then
        sec_audit_report_pass "$num" "not applicable (dynamic updates disabled); ZSK private files=$n"
        return 0
    fi
    if [ "$ksk" -gt 0 ] 2>/dev/null; then
        sec_audit_report_fail "$num" "dynamic updates enabled but $ksk KSK private file(s) on server (only ZSK may be online)"
        return 0
    fi
    if [ "$n" -le 1 ] 2>/dev/null; then
        sec_audit_report_pass "$num" "dynamic updates enabled; ZSK private count=$n (KSK offline)"
    else
        sec_audit_report_fail "$num" "dynamic updates enabled but ZSK private count=$n (expected <=1 active ZSK)"
    fi
}

sec_audit_check_ksk_offline() {
    local num="$1"
    local n sample=""
    n=$(sec_audit_ksk_private_paths | sec_audit_count_lines)
    sample=$(sec_audit_ksk_private_paths | head -3 | tr '\n' ' ')
    if [ "$n" -eq 0 ] 2>/dev/null; then
        sec_audit_report_pass "$num" "no KSK private keys on server (count=0)"
    else
        sec_audit_report_fail "$num" "$n KSK private key file(s) found on server ($sample)"
    fi
}

sec_audit_scan_key_owner() {
    local num="$1" expect="$2" files n=0 bad=0 owner f
    files=$(sec_audit_tsig_material_paths)
    if [ -z "$files" ]; then
        if [ "$(sec_audit_key_statement_count)" -gt 0 ] 2>/dev/null; then
            files=$(sec_audit_core_conf_paths)
        fi
    fi
    if [ -z "$files" ]; then
        sec_audit_report_pass "$num" "no TSIG key files found under bind directories"
        return 0
    fi
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        n=$((n + 1))
        owner=$(sec_audit_path_owner_user "$f")
        case "$expect" in
            named)
                if [ "$owner" != "$_BIND_DAEMON_ACCT" ] && [ "$owner" != "named" ] && [ "$owner" != "bind" ]; then
                    bad=$((bad + 1))
                fi
                ;;
            priv)
                sec_audit_user_is_priv "$owner" || bad=$((bad + 1))
                ;;
        esac
    done <<< "$files"
    if [ "$n" -eq 0 ]; then
        sec_audit_report_pass "$num" "no TSIG key files found"
        return 0
    fi
    if [ "$bad" -eq 0 ]; then
        sec_audit_report_pass "$num" "all $n TSIG key file(s) owned by expected account (named=${_BIND_DAEMON_ACCT:-unknown})"
    else
        sec_audit_report_fail "$num" "$bad of $n TSIG key file(s) have unexpected owner"
    fi
}

sec_audit_check_tsig_owner_named() {
    local num="$1"
    if [ -z "$_BIND_DAEMON_ACCT" ]; then
        _BIND_DAEMON_ACCT=$(sec_audit_daemon_user)
    fi
    if [ -z "$_BIND_DAEMON_ACCT" ]; then
        for _BIND_DAEMON_ACCT in named bind; do
            getent passwd "$_BIND_DAEMON_ACCT" >/dev/null 2>&1 && break
        done
    fi
    if [ -z "$_BIND_DAEMON_ACCT" ]; then
        sec_audit_report_fail "$num" "unable to determine named process user for TSIG ownership check"
        return 0
    fi
    sec_audit_scan_key_owner "$num" named
}

sec_audit_check_tsig_mode() {
    local num="$1"
    local f n=0 bad=0 mode files
    files=$(sec_audit_tsig_material_paths)
    if [ -z "$files" ] && [ "$(sec_audit_key_statement_count)" -gt 0 ] 2>/dev/null; then
        files=$(sec_audit_core_conf_paths)
    fi
    if [ -z "$files" ]; then
        sec_audit_report_pass "$num" "no TSIG key files found for mode check"
        return 0
    fi
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        n=$((n + 1))
        mode=$(sec_audit_path_mode_octal "$f")
        if [ "$mode" != "600" ] && [ "$mode" != "640" ] && [ "$mode" != "400" ] && [ "$mode" != "440" ]; then
            bad=$((bad + 1))
        elif sec_audit_mode_world_writable "$mode"; then
            bad=$((bad + 1))
        fi
    done <<< "$files"
    if [ "$bad" -eq 0 ]; then
        sec_audit_report_pass "$num" "all $n TSIG key file(s) have mode 600/640/400 (no other-access)"
    else
        sec_audit_report_fail "$num" "$bad of $n TSIG key file(s) are world-accessible or not 600/640/400"
    fi
}

sec_audit_check_tsig_unique() {
    local num="$1"
    local nkeys nsecrets
    nkeys=$(sec_audit_key_statement_count)
    nsecrets=$(sec_audit_key_secret_values | sec_audit_count_lines)
    if [ "$nkeys" -le 1 ] 2>/dev/null; then
        sec_audit_report_pass "$num" "$nkeys key statement(s); unique TSIG per host-pair not violated"
        return 0
    fi
    if [ "$nsecrets" -ge "$nkeys" ] 2>/dev/null; then
        sec_audit_report_pass "$num" "$nkeys key statements with $nsecrets distinct secret(s)"
    else
        sec_audit_report_fail "$num" "$nkeys key statements but only $nsecrets unique secret(s) (separate TSIG key-pairs required)"
    fi
}

sec_audit_check_tsig_priv_owner() {
    local num="$1"
    local f n=0 bad=0 owner files
    files=$(sec_audit_tsig_material_paths)
    [ -z "$files" ] && files=$(sec_audit_core_conf_paths)
    if [ -z "$(sec_audit_tsig_material_paths)" ] && [ "$(sec_audit_key_statement_count)" -eq 0 ] 2>/dev/null; then
        sec_audit_report_pass "$num" "no TSIG key files under bind directories"
        return 0
    fi
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        case "$f" in
            *.key|*/rndc.key|*/rndc.conf) ;;
            *) continue ;;
        esac
        n=$((n + 1))
        owner=$(sec_audit_path_owner_user "$f")
        sec_audit_user_is_priv "$owner" || [ "$owner" = "$_BIND_DAEMON_ACCT" ] || bad=$((bad + 1))
    done < <(sec_audit_tsig_material_paths)
    if [ "$n" -eq 0 ]; then
        sec_audit_report_pass "$num" "no TSIG key files; inline key statements inherit named.conf ownership"
        return 0
    fi
    if [ "$bad" -eq 0 ]; then
        sec_audit_report_pass "$num" "all $n TSIG key file(s) owned by privileged account"
    else
        sec_audit_report_fail "$num" "$bad of $n TSIG key file(s) not owned by privileged account"
    fi
}

sec_audit_check_tsig_priv_group() {
    local num="$1"
    local f n=0 bad=0 g
    if [ -z "$(sec_audit_tsig_material_paths)" ]; then
        sec_audit_report_pass "$num" "no TSIG key files under bind directories"
        return 0
    fi
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        n=$((n + 1))
        g=$(sec_audit_path_owner_group "$f")
        sec_audit_group_is_priv "$g" || [ "$g" = "$_BIND_DAEMON_GRP" ] || bad=$((bad + 1))
    done < <(sec_audit_tsig_material_paths)
    if [ "$bad" -eq 0 ]; then
        sec_audit_report_pass "$num" "all $n TSIG key file(s) group-owned by privileged account (${_BIND_DAEMON_GRP:-named/bind/root})"
    else
        sec_audit_report_fail "$num" "$bad of $n TSIG key file(s) not group-owned by privileged account"
    fi
}

sec_audit_check_split_zone_files() {
    local num="$1"
    local views inner files="" distinct=0
    if ! sec_audit_serves_split; then
        sec_audit_report_pass "$num" "not applicable (split DNS views not configured)"
        return 0
    fi
    while IFS= read -r -d '' views; do
        [ -z "$views" ] && continue
        inner=$(printf '%s' "$views" | awk 'BEGIN{IGNORECASE=1} $1=="file"{gsub(/[";]/,"",$2); print $2; exit}')
        [ -n "$inner" ] || continue
        case " $files " in
            *" $inner "*) ;;
            *) files="$files $inner"; distinct=$((distinct + 1)) ;;
        esac
    done < <(sec_audit_clause_records "view")
    if [ "$distinct" -ge 2 ] 2>/dev/null; then
        sec_audit_report_pass "$num" "split views use distinct zone files ($files )"
    else
        sec_audit_report_fail "$num" "internal/external views share zone file or file paths not resolved (files=$files)"
    fi
}

sec_audit_check_view_match() {
    local num="$1"
    local want="$1" role="$2" blk mc vname found=0
    if ! sec_audit_serves_split && ! sec_audit_parsed_text | grep -qiE "view[[:space:]]+\"?${want}"; then
        sec_audit_report_pass "$num" "not applicable (split DNS not configured)"
        return 0
    fi
    while IFS= read -r -d '' blk; do
        [ -z "$blk" ] && continue
        vname=$(sec_audit_view_named "$blk")
        printf '%s' "$vname" | grep -qiE "$want" || continue
        found=1
        mc=$(sec_audit_view_match_clients "$blk")
        if [ -z "$mc" ]; then
            sec_audit_report_fail "$num" "$role view '$vname' missing match-clients"
            return 0
        fi
        if sec_audit_acl_permits_any "$mc"; then
            sec_audit_report_fail "$num" "$role view '$vname' match-clients allows any"
            return 0
        fi
        sec_audit_report_pass "$num" "$role view '$vname' has restrictive match-clients ($mc)"
        return 0
    done < <(sec_audit_clause_records "view")
    if [ "$found" -eq 0 ]; then
        if sec_audit_serves_split; then
            sec_audit_report_fail "$num" "$role view matching '$want' not found"
        else
            sec_audit_report_pass "$num" "not applicable (split DNS not configured)"
        fi
        return 0
    fi
}

sec_audit_check_internal_match() {
    sec_audit_check_view_match "$1" "internal|inside|private|lan" "internal"
}
sec_audit_check_external_match() {
    sec_audit_check_view_match "$1" "external|outside|public|dmz" "external"
}
sec_audit_check_hidden_primary() {
    local num="$1"
    local ip hits=0 checked=0 zpath host
    if ! sec_audit_serves_master; then
        sec_audit_report_pass "$num" "not applicable (not a primary name server)"
        return 0
    fi
    while IFS= read -r ip; do
        [ -z "$ip" ] && continue
        checked=$((checked + 1))
        while IFS= read -r zpath; do
            [ -f "$zpath" ] || continue
            if grep -vE '^[[:space:]]*;' "$zpath" 2>/dev/null | grep -vE 'SOA' | grep -qE "${ip}([[:space:]]|$)"; then
                hits=$((hits + 1))
            fi
        done < <(sec_audit_zone_file_paths)
    done < <(sec_audit_host_ipv4_list)
    host=$(hostname -s 2>/dev/null || hostname 2>/dev/null || true)
    if [ "$checked" -eq 0 ]; then
        sec_audit_report_pass "$num" "no global IPv4 addresses detected for hidden-primary verification"
        return 0
    fi
    if [ "$hits" -eq 0 ]; then
        sec_audit_report_pass "$num" "server IP(s) not present in zone NS/A data (checked $checked address(es); host=${host:-unset})"
    else
        sec_audit_report_fail "$num" "hidden primary IP appears in $hits zone-file occurrence(s)"
    fi
}

sec_audit_check_nsec3() {
    local num="$1"
    local zpath total=0 nsec=0 policy=0
    sec_audit_blob_has "$(sec_audit_options_body)" 'dnssec-policy' && policy=1
    sec_audit_blob_has "$(sec_audit_parsed_text)" 'dnssec-policy' && policy=1
    sec_audit_blob_has "$(sec_audit_parsed_text)" 'nsec3param' && policy=1
    while IFS= read -r zpath; do
        [ -f "$zpath" ] || continue
        total=$((total + 1))
        if grep -qE 'NSEC3|NSEC3PARAM' "$zpath" 2>/dev/null; then
            nsec=$((nsec + 1))
        fi
    done < <(sec_audit_zone_file_paths)
    if [ "$total" -eq 0 ]; then
        if [ "$policy" -eq 1 ]; then
            sec_audit_report_pass "$num" "no zone files on disk; dnssec-policy/nsec3param present in named.conf"
        else
            sec_audit_report_pass "$num" "no zone files found for NSEC3 verification"
        fi
        return 0
    fi
    if [ "$nsec" -gt 0 ] || [ "$policy" -eq 1 ]; then
        sec_audit_report_pass "$num" "NSEC3/dnssec-policy indicators in $nsec of $total zone(s) (policy=$policy)"
    else
        sec_audit_report_fail "$num" "NSEC3 not found in $total zone file(s); required for internal restricted zones"
    fi
}

sec_audit_check_offline_when_static() {
    local num="$1"
    local n
    n=$(sec_audit_dnssec_material_paths | grep -c '\.private$' 2>/dev/null || true)
    n=${n:-0}
    if sec_audit_updates_allowed; then
        sec_audit_report_pass "$num" "not applicable (dynamic updates allowed); private key files=$n"
        return 0
    fi
    if [ "$n" -eq 0 ] 2>/dev/null; then
        sec_audit_report_pass "$num" "allow-update none/absent; private key count=0"
    else
        sec_audit_report_fail "$num" "dynamic updates disabled but $n private key file(s) remain on server"
    fi
}

sec_audit_scan_keygen() {
    local num="$1" field="$2" expect="$3" label="$4"
    local f n=0 bad=0 got
    if [ -z "$(sec_audit_keygen_material_paths)" ]; then
        sec_audit_report_pass "$num" "no dnssec-keygen K* files present (removed after copy is compliant)"
        return 0
    fi
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        n=$((n + 1))
        case "$field" in
            owner) got=$(sec_audit_path_owner_user "$f") ;;
            group) got=$(sec_audit_path_owner_group "$f") ;;
            mode)  got=$(sec_audit_path_mode_octal "$f") ;;
        esac
        if [ "$field" = "mode" ]; then
            [ "$got" = "$expect" ] || [ "$got" = "400" ] || [ "$got" = "440" ] || bad=$((bad + 1))
        else
            [ "$got" = "$expect" ] || bad=$((bad + 1))
        fi
    done < <(sec_audit_keygen_material_paths)
    if [ "$bad" -eq 0 ]; then
        sec_audit_report_pass "$num" "all $n dnssec-keygen file(s) $label"
    else
        sec_audit_report_fail "$num" "$bad of $n dnssec-keygen file(s) fail $label"
    fi
}

sec_audit_check_keygen_owner() {
    sec_audit_scan_keygen "$1" owner root "owned by root"
}
sec_audit_check_keygen_group() {
    sec_audit_scan_keygen "$1" group root "group-owned by root"
}
sec_audit_check_keygen_mode() {
    sec_audit_scan_keygen "$1" mode 400 "mode 400 (owner-read only)"
}
sec_audit_check_zsk_owner() {
    local num="$1"
    local f n=0 bad=0 owner
    if ! sec_audit_updates_allowed; then
        sec_audit_report_pass "$num" "not applicable (dynamic updates disabled)"
        return 0
    fi
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        n=$((n + 1))
        owner=$(sec_audit_path_owner_user "$f")
        [ "$owner" = "root" ] || bad=$((bad + 1))
    done < <(sec_audit_zsk_private_paths)
    if [ "$n" -eq 0 ]; then
        sec_audit_report_pass "$num" "no ZSK private files found while updates enabled (verify signing keys live elsewhere)"
        return 0
    fi
    if [ "$bad" -eq 0 ]; then
        sec_audit_report_pass "$num" "all $n ZSK private file(s) owned by root"
    else
        sec_audit_report_fail "$num" "$bad of $n ZSK private file(s) not owned by root"
    fi
}

sec_audit_check_zsk_group() {
    local num="$1"
    local f n=0 bad=0 g
    if ! sec_audit_updates_allowed; then
        sec_audit_report_pass "$num" "not applicable (dynamic updates disabled)"
        return 0
    fi
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        n=$((n + 1))
        g=$(sec_audit_path_owner_group "$f")
        [ "$g" = "root" ] || bad=$((bad + 1))
    done < <(sec_audit_zsk_private_paths)
    if [ "$n" -eq 0 ]; then
        sec_audit_report_pass "$num" "no ZSK private files found for group check"
        return 0
    fi
    if [ "$bad" -eq 0 ]; then
        sec_audit_report_pass "$num" "all $n ZSK private file(s) group-owned by root"
    else
        sec_audit_report_fail "$num" "$bad of $n ZSK private file(s) not group-owned by root"
    fi
}

sec_audit_check_slave_notify() {
    local num="$1"
    local opt zones
    if ! sec_audit_serves_slave; then
        sec_audit_report_pass "$num" "not applicable (not a secondary name server)"
        return 0
    fi
    opt=$(sec_audit_options_body)
    zones=$(sec_audit_zone_blocks)
    if sec_audit_notify_chain_ok "$zones" || sec_audit_notify_chain_ok "$opt"; then
        sec_audit_report_pass "$num" "secondary notify/also-notify configured for other authoritative servers"
        return 0
    fi
    if sec_audit_blob_has "$opt" 'notify[[:space:]]+no'; then
        sec_audit_report_fail "$num" "notify no in options; secondary must originate NOTIFY to other NS (notify explicit + also-notify)"
        return 0
    fi
    sec_audit_report_fail "$num" "notify/also-notify missing on secondary zones"
}

sec_audit_check_auth_no_recursion() {
    local num="$1"
    local opt rec aq ar zones
    opt=$(sec_audit_options_body)
    zones=$(sec_audit_zone_blocks)
    rec=$(sec_audit_scalar_in "$opt" "recursion")
    ar=$(sec_audit_acl_in "$opt" "allow-recursion")
    aq=$(sec_audit_acl_in "$opt" "allow-query")
    [ -z "$aq" ] && aq=$(sec_audit_acl_in "$zones" "allow-query")
    if sec_audit_serves_master || sec_audit_serves_slave; then
        if printf '%s' "$rec" | grep -qi '^no$' && { sec_audit_acl_is_none "$ar" || [ -z "$ar" ]; }; then
            if sec_audit_acl_is_tight "$aq" || sec_audit_acl_is_none "$aq"; then
                sec_audit_report_pass "$num" "authoritative role; recursion=no allow-recursion=${ar:-unset} allow-query=${aq:-unset}"
            else
                sec_audit_report_fail "$num" "recursion disabled but allow-query is unrestricted (${aq:-missing})"
            fi
            return 0
        fi
        sec_audit_report_fail "$num" "authoritative server must set recursion no and allow-recursion { none; } (recursion=${rec:-unset} allow-recursion=${ar:-unset})"
        return 0
    fi
    if sec_audit_serves_resolver; then
        if sec_audit_acl_is_tight "$ar" || sec_audit_acl_is_tight "$aq"; then
            sec_audit_report_pass "$num" "caching role; recursion restricted via ACL (allow-recursion=${ar:-unset})"
        else
            sec_audit_report_fail "$num" "caching server lacks restrictive allow-recursion/allow-query ACL"
        fi
        return 0
    fi
    sec_audit_report_pass "$num" "role not identified as authoritative/caching (recursion=${rec:-unset})"
}

sec_audit_check_master_notify() {
    local num="$1"
    local opt zones
    if ! sec_audit_serves_master; then
        sec_audit_report_pass "$num" "not applicable (not a primary name server)"
        return 0
    fi
    opt=$(sec_audit_options_body)
    zones=$(sec_audit_zone_blocks)
    if sec_audit_notify_chain_ok "$zones" || sec_audit_notify_chain_ok "$opt"; then
        sec_audit_report_pass "$num" "primary notify/also-notify configured for authorized secondaries"
        return 0
    fi
    if sec_audit_blob_has "$opt" 'notify[[:space:]]+no' && ! sec_audit_blob_has "$zones" 'notify[[:space:]]+explicit'; then
        sec_audit_report_fail "$num" "notify no without zone-level notify explicit/also-notify"
        return 0
    fi
    sec_audit_report_fail "$num" "primary missing notify explicit/also-notify for authorized secondaries"
}

sec_audit_check_root_hints_valid() {
    local num="$1"
    local zfile zpath ns=0
    if ! sec_audit_serves_resolver; then
        sec_audit_report_pass "$num" "not applicable (not a caching resolver)"
        return 0
    fi
    zfile=$(sec_audit_zone_blocks | awk '
        BEGIN { IGNORECASE=1; z=0 }
        /^[[:space:]]*zone[[:space:]]+"\."/ { z=1 }
        z && $1=="file" { gsub(/[";]/,"",$2); print $2; exit }
        z && /^-----END-----$/ { z=0 }
    ')
    zpath=$(sec_audit_resolve_zone_file "${zfile:-root.hints}")
    if [ ! -f "$zpath" ]; then
        for zpath in /usr/share/dns/root.hints /etc/bind/db.root /var/named/named.ca /usr/share/bind/named.ca; do
            [ -f "$zpath" ] && break
        done
    fi
    if [ -f "$zpath" ]; then
        ns=$(grep -cE 'IN[[:space:]]+NS[[:space:]]+' "$zpath" 2>/dev/null || true)
        ns=${ns:-0}
        if [ "$ns" -ge 1 ] 2>/dev/null; then
            sec_audit_report_pass "$num" "root hints $zpath present with $ns NS record(s)"
        else
            sec_audit_report_fail "$num" "root hints $zpath missing NS records"
        fi
    else
        sec_audit_report_fail "$num" "root hints file not found (file=${zfile:-unset})"
    fi
}

sec_audit_check_auth_no_root_master() {
    local num="$1"
    local z
    if ! sec_audit_serves_master; then
        sec_audit_report_pass "$num" "not applicable (not an authoritative primary)"
        return 0
    fi
    z=$(sec_audit_zone_blocks)
    if printf '%s' "$z" | awk '
        BEGIN { IGNORECASE=1; z=0; bad=0 }
        /^[[:space:]]*zone[[:space:]]+"\."/ { z=1 }
        z && /type[[:space:]]+(master|primary)/ { bad=1 }
        z && /^-----END-----$/ { z=0 }
        END { exit bad?0:1 }
    '; then
        sec_audit_report_fail "$num" "root zone configured as master/primary on authoritative server"
        return 0
    fi
    if sec_audit_serves_resolver; then
        sec_audit_report_pass "$num" "authoritative+resolver mix; root zone is not type master"
        return 0
    fi
    if printf '%s' "$z" | grep -qE 'zone[[:space:]]+"\."'; then
        sec_audit_report_pass "$num" "root zone present as hint (prefer empty/removed on pure authoritative hosts)"
    else
        sec_audit_report_pass "$num" "no root zone on authoritative primary (hint file absent/removed)"
    fi
}

sec_audit_check_allow_transfer() {
    local num="$1"
    local opt zones at
    if ! sec_audit_serves_master && ! sec_audit_serves_slave; then
        sec_audit_report_pass "$num" "not applicable (no authoritative zones)"
        return 0
    fi
    opt=$(sec_audit_options_body)
    zones=$(sec_audit_zone_blocks)
    at=$(sec_audit_acl_in "$opt" "allow-transfer")
    [ -z "$at" ] && at=$(sec_audit_acl_in "$zones" "allow-transfer")
    if sec_audit_acl_is_none "$at"; then
        sec_audit_report_pass "$num" "allow-transfer { none; }"
        return 0
    fi
    if printf '%s' "$at" | grep -qiE 'key[[:space:]]' || sec_audit_acl_has_peers "$at"; then
        if sec_audit_acl_permits_any "$at"; then
            sec_audit_report_fail "$num" "allow-transfer permits any ($at)"
        else
            sec_audit_report_pass "$num" "allow-transfer restricted ($at)"
        fi
        return 0
    fi
    if sec_audit_blob_has "$opt" 'allow-transfer' || sec_audit_blob_has "$zones" 'allow-transfer'; then
        sec_audit_report_fail "$num" "allow-transfer present but not restricted to keys/peers ($at)"
    else
        sec_audit_report_fail "$num" "allow-transfer statement missing (defaults to any on older BIND)"
    fi
}

sec_audit_check_split_roles() {
    local num="$1"
    local names="" n=0 vname mc blk internal_pos="" external_pos="" i=0
    while IFS= read -r -d '' blk; do
        [ -z "$blk" ] && continue
        vname=$(sec_audit_view_named "$blk")
        [ -n "$vname" ] || continue
        i=$((i + 1))
        n=$((n + 1))
        names="$names $vname"
        mc=$(sec_audit_view_match_clients "$blk")
        printf '%s' "$vname" | grep -qiE 'internal|inside|private' && internal_pos="$i"
        printf '%s' "$vname" | grep -qiE 'external|outside|public' && external_pos="$i"
        if [ -z "$mc" ] || sec_audit_acl_permits_any "$mc"; then
            :
        fi
    done < <(sec_audit_clause_records "view")
    if [ "$n" -lt 2 ] 2>/dev/null; then
        if sec_audit_serves_master && sec_audit_serves_resolver; then
            sec_audit_report_fail "$num" "authoritative and recursive roles combined without split views"
            return 0
        fi
        sec_audit_report_pass "$num" "single-role host (views=$n); internal/external split not configured"
        return 0
    fi
    if [ -n "$internal_pos" ] && [ -n "$external_pos" ] && [ "$internal_pos" -lt "$external_pos" ]; then
        sec_audit_report_pass "$num" "split views$names ; internal precedes external"
        return 0
    fi
    if [ "$n" -ge 2 ]; then
        sec_audit_report_pass "$num" "split views configured ($names) with match-clients"
        return 0
    fi
    sec_audit_report_fail "$num" "views present but internal/external role separation not evident ($names)"
}

sec_audit_check_random_port() {
    local num="$1"
    local opt stripped qs
    opt=$(sec_audit_options_body)
    stripped=$(printf '%s\n' "$opt" | awk '
        BEGIN { cap=0; depth=0 }
        {
            low=tolower($0)
            if (!cap && low ~ /^[[:space:]]*listen-on(-v6)?[[:space:]]/) { cap=1; depth=0 }
            if (cap) {
                for (i=1;i<=length($0);i++) {
                    c=substr($0,i,1)
                    if (c=="{") depth++
                    if (c=="}") depth--
                }
                if (depth<=0) cap=0
                next
            }
            print
        }
    ')
    if printf '%s' "$stripped" | grep -qiE '^[[:space:]]*port[[:space:]]+[0-9]+'; then
        sec_audit_report_fail "$num" "fixed port directive in options outside listen-on"
        return 0
    fi
    qs=$(printf '%s' "$opt" | grep -iE 'query-source(-v6)?' | tr '\n' ' ')
    if printf '%s' "$qs" | grep -qiE 'port[[:space:]]+(\*|0)[[:space:]]*;'; then
        sec_audit_report_pass "$num" "query-source port randomized ($qs)"
        return 0
    fi
    if printf '%s' "$qs" | grep -qiE 'port[[:space:]]+[0-9]+'; then
        sec_audit_report_fail "$num" "query-source uses a fixed port ($qs)"
        return 0
    fi
    sec_audit_report_pass "$num" "no fixed options port; query-source unset (BIND default uses random UDP ports)"
}

sec_audit_check_mgmt_iface() {
    local num="$1"
    local ifaces=0 listen any=0 ctl
    ifaces=$(sec_audit_host_ipv4_list | sec_audit_count_lines)
    listen=$(sec_audit_acl_in "$(sec_audit_options_body)" "listen-on")
    sec_audit_acl_permits_any "$listen" && any=1
    [ -z "$listen" ] && any=1
    ctl=$(sec_audit_controls_body)
    if [ "$ifaces" -ge 2 ] 2>/dev/null; then
        sec_audit_report_pass "$num" "$ifaces global IPv4 address(es); verify dedicated management path (listen-on=${listen:-any})"
        return 0
    fi
    if sec_audit_blob_has "$ctl" 'inet[[:space:]]+127\.0\.0\.1' && [ "$any" -eq 0 ]; then
        sec_audit_report_pass "$num" "single data IP but listen-on is specific and rndc/controls bound to 127.0.0.1"
        return 0
    fi
    sec_audit_report_fail "$num" "only $ifaces global interface(s); dedicated management separation not evident (listen-on=${listen:-unset})"
}

sec_audit_check_conf_group() {
    local num="$1"
    local f n=0 bad=0 g sample=""
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        n=$((n + 1))
        g=$(sec_audit_path_owner_group "$f")
        sample="${sample}${f}:$g "
        sec_audit_group_is_priv "$g" || [ "$g" = "$_BIND_DAEMON_GRP" ] || bad=$((bad + 1))
    done < <(sec_audit_core_conf_paths)
    if [ "$n" -eq 0 ]; then
        sec_audit_report_fail "$num" "named.conf not found for group ownership check"
        return 0
    fi
    if [ "$bad" -eq 0 ]; then
        sec_audit_report_pass "$num" "core named.conf file(s) group-owned by DNS admin ($sample)"
    else
        sec_audit_report_fail "$num" "$bad of $n core config file(s) not in privileged DNS group ($sample)"
    fi
}

sec_audit_check_conf_owner() {
    local num="$1"
    local f n=0 bad=0 o sample=""
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        n=$((n + 1))
        o=$(sec_audit_path_owner_user "$f")
        sample="${sample}${f}:$o "
        sec_audit_user_is_priv "$o" || [ "$o" = "$_BIND_DAEMON_ACCT" ] || bad=$((bad + 1))
    done < <(sec_audit_core_conf_paths)
    if [ "$n" -eq 0 ]; then
        sec_audit_report_fail "$num" "named.conf not found for ownership check"
        return 0
    fi
    if [ "$bad" -eq 0 ]; then
        sec_audit_report_pass "$num" "core named.conf file(s) owned by root or named ($sample)"
    else
        sec_audit_report_fail "$num" "$bad of $n core config file(s) not owned by root/named ($sample)"
    fi
}

sec_audit_check_nonroot_daemon() {
    local num="$1"
    local u unit extra=""
    u="${_BIND_DAEMON_ACCT:-$(sec_audit_daemon_user)}"
    unit=$(sec_audit_unit_file_text)
    sec_audit_blob_has "$unit" '^User=(named|bind)' && extra="; systemd User= non-root"
    printf '%s' "$unit" | grep -qE 'ExecStart=.*[[:space:]]-u[[:space:]]+(named|bind)' && extra="$extra; ExecStart -u"
    extra="$extra; $(sec_audit_rndc_status_note 2>/dev/null || true)"
    if sec_audit_daemon_alive; then
        if [ -n "$u" ] && [ "$u" != "root" ]; then
            sec_audit_report_pass "$num" "named running as $u (non-root)$extra"
        else
            sec_audit_report_fail "$num" "named running as ${u:-unknown}; must drop root$extra"
        fi
        return 0
    fi
    if [ -n "$u" ] && [ "$u" != "root" ]; then
        sec_audit_report_pass "$num" "named not running; configured account $u is non-root$extra"
        return 0
    fi
    if printf '%s' "$unit" | grep -qE '^User=(named|bind)'; then
        sec_audit_report_pass "$num" "named not running; systemd unit drops privileges$extra"
        return 0
    fi
    sec_audit_report_fail "$num" "unable to confirm named runs with limited privileges$extra"
}

sec_audit_check_key_age() {
    local num="$1"
    local f n=0 old=0
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        n=$((n + 1))
        if [ -n "$(find "$f" -maxdepth 0 -mtime +${BIND9_KEY_MAX_AGE_DAYS} 2>/dev/null)" ]; then
            old=$((old + 1))
        fi
    done < <( { sec_audit_tsig_material_paths; sec_audit_dnssec_material_paths; } | sort -u )
    if [ "$n" -eq 0 ]; then
        sec_audit_report_pass "$num" "no TSIG/DNSSEC key files found for age verification"
        return 0
    fi
    if [ "$old" -eq 0 ]; then
        sec_audit_report_pass "$num" "all $n key file(s) modified within ${BIND9_KEY_MAX_AGE_DAYS} days"
    else
        sec_audit_report_fail "$num" "$old of $n key file(s) older than ${BIND9_KEY_MAX_AGE_DAYS} days"
    fi
}

sec_audit_check_conf_mode() {
    local num="$1"
    local f n=0 bad=0 mode sample="" j
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        n=$((n + 1))
        mode=$(sec_audit_path_mode_octal "$f")
        sample="${sample}$(basename "$f")=$mode "
        if [ "$mode" != "640" ] && [ "$mode" != "600" ] && [ "$mode" != "440" ] && [ "$mode" != "400" ]; then
            bad=$((bad + 1))
        elif sec_audit_mode_world_writable "$mode"; then
            bad=$((bad + 1))
        fi
    done < <(sec_audit_core_conf_paths)
    while IFS= read -r j; do
        [ -z "$j" ] && continue
        n=$((n + 1))
        mode=$(sec_audit_path_mode_octal "$j")
        if sec_audit_mode_world_writable "$mode"; then
            bad=$((bad + 1))
            sample="${sample}$(basename "$j")=$mode "
        fi
    done < <(sec_audit_journal_paths)
    if [ -n "$_BIND_PID_PATH" ] && [ -e "$_BIND_PID_PATH" ]; then
        mode=$(sec_audit_path_mode_octal "$_BIND_PID_PATH")
        sample="${sample}pid=$mode "
    fi
    if [ "$n" -eq 0 ]; then
        sec_audit_report_fail "$num" "named.conf not found for permission check"
        return 0
    fi
    if [ "$bad" -eq 0 ]; then
        sec_audit_report_pass "$num" "core config/journal modes use least privilege ($sample)"
    else
        sec_audit_report_fail "$num" "$bad path(s) exceed least-privilege modes ($sample; expected 640/600 on named.conf)"
    fi
}

sec_audit_check_host_firewall() {
    local num="$1"
    if sec_audit_dns_filter_present; then
        sec_audit_report_pass "$num" "host firewall rules detected for DNS port 53"
    else
        sec_audit_report_fail "$num" "no DNS firewall rules found in iptables/nftables/firewalld/ufw"
    fi
}

sec_audit_check_dnssec_integrity() {
    local num="$1"
    local opt signed=0 total=0 zpath val
    opt=$(sec_audit_options_body)
    val=$(sec_audit_scalar_in "$opt" "dnssec-validation")
    while IFS= read -r zpath; do
        [ -f "$zpath" ] || continue
        total=$((total + 1))
        grep -q 'DNSKEY' "$zpath" 2>/dev/null && signed=$((signed + 1))
    done < <(sec_audit_zone_file_paths)
    if sec_audit_blob_has "$opt" 'dnssec-policy' || sec_audit_blob_has "$(sec_audit_parsed_text)" 'dnssec-policy'; then
        sec_audit_report_pass "$num" "dnssec-policy configured; DNSKEY in $signed of $total zone(s); dnssec-validation=${val:-unset}"
        return 0
    fi
    if printf '%s' "$val" | grep -qiE '^(yes|auto)$'; then
        sec_audit_report_pass "$num" "dnssec-validation=$val; DNSKEY in $signed of $total zone(s)"
        return 0
    fi
    if sec_audit_blob_has "$opt" 'dnssec-enable[[:space:]]+yes' && [ "$signed" -gt 0 ]; then
        sec_audit_report_pass "$num" "dnssec-enable yes; signed zones=$signed/$total"
        return 0
    fi
    sec_audit_report_fail "$num" "dnssec-validation not yes/auto (${val:-missing}) and no dnssec-policy/DNSKEY evidence"
}

sec_audit_check_log_severity() {
    local num="$1"
    local logb
    logb=$(sec_audit_logging_body)
    if sec_audit_blob_has "$logb" 'severity[[:space:]]+(info|dynamic|debug)'; then
        sec_audit_report_pass "$num" "logging channel severity is info (or more verbose)"
    else
        sec_audit_report_fail "$num" "severity info not configured in logging channel"
    fi
}

sec_audit_check_listen_port() {
    local num="$1"
    local opt bad=0 line port extra="" val hn sid
    opt=$(sec_audit_options_body)
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        port=$(printf '%s' "$line" | sed -nE 's/.*port[[:space:]]+([0-9]+).*/\1/p')
        [ -n "$port" ] && [ "$port" != "53" ] && bad=1
    done < <(printf '%s\n' "$opt" | grep -iE 'listen-on(-v6)?')
    val=$(sec_audit_scalar_in "$opt" "version")
    hn=$(sec_audit_scalar_in "$opt" "hostname")
    sid=$(sec_audit_scalar_in "$opt" "server-id")
    extra="version=${val:-unset} hostname=${hn:-unset} server-id=${sid:-unset}"
    if [ "$bad" -eq 0 ]; then
        sec_audit_report_pass "$num" "listen-on uses default or port 53 ($extra)"
    else
        sec_audit_report_fail "$num" "listen-on configured with port other than 53 ($extra)"
    fi
}

sec_audit_check_tsig_auth() {
    local num="$1"
    local opt zones at au keys nkeys
    opt=$(sec_audit_options_body)
    zones=$(sec_audit_zone_blocks)
    at=$(sec_audit_acl_in "$opt" "allow-transfer")
    [ -z "$at" ] && at=$(sec_audit_acl_in "$zones" "allow-transfer")
    au=$(sec_audit_acl_in "$opt" "allow-update")
    [ -z "$au" ] && au=$(sec_audit_acl_in "$zones" "allow-update")
    nkeys=$(sec_audit_key_statement_count)
    keys=$(sec_audit_server_blocks)
    if sec_audit_acl_is_none "$at" && ! sec_audit_updates_allowed; then
        sec_audit_report_pass "$num" "zone transfers disabled (allow-transfer none) and no dynamic updates; TSIG not required for xfer"
        return 0
    fi
    if [ "$nkeys" -ge 1 ] 2>/dev/null && { printf '%s' "$at$au$keys" | grep -qiE 'key[[:space:]]'; }; then
        sec_audit_report_pass "$num" "TSIG key statements=$nkeys; allow-transfer/update/server keys reference a key"
        return 0
    fi
    if [ "$nkeys" -ge 1 ] 2>/dev/null && sec_audit_blob_has "$keys" 'keys[[:space:]]*\{'; then
        sec_audit_report_pass "$num" "TSIG keys defined and server { keys } present"
        return 0
    fi
    sec_audit_report_fail "$num" "server-server TSIG not evident (key statements=$nkeys allow-transfer=$at)"
}

sec_audit_check_tsig_pairs() {
    local num="$1"
    local nkeys nsecrets nsrv
    nkeys=$(sec_audit_key_statement_count)
    nsecrets=$(sec_audit_key_secret_values | sec_audit_count_lines)
    nsrv=$(sec_audit_server_blocks | sec_audit_count_pat '^[[:space:]]*server[[:space:]]')
    if [ "$nkeys" -le 1 ] 2>/dev/null; then
        sec_audit_report_pass "$num" "$nkeys key statement(s), $nsrv server block(s); unique pair usage not violated"
        return 0
    fi
    if [ "$nsecrets" -ge "$nkeys" ] 2>/dev/null; then
        sec_audit_report_pass "$num" "$nkeys distinct TSIG secrets across $nkeys key statements (server blocks=$nsrv)"
    else
        sec_audit_report_fail "$num" "shared TSIG secret: $nkeys keys but $nsecrets unique secret(s)"
    fi
}

sec_audit_check_chroot_jail() {
    local num="$1"
    local root unit extra=""
    root=$(sec_audit_chroot_root_of 2>/dev/null || true)
    unit=$(sec_audit_unit_file_text)
    sec_audit_blob_has "$unit" 'named-chroot' && extra="; named-chroot unit"
    if [ -n "$root" ]; then
        sec_audit_report_pass "$num" "chroot detected at $root$extra"
        return 0
    fi
    if printf '%s' "$unit" | grep -qE '^RootDirectory='; then
        sec_audit_report_pass "$num" "systemd RootDirectory chroot configured$extra"
        return 0
    fi
    if sec_audit_daemon_alive; then
        sec_audit_report_fail "$num" "named running without chroot (-t) or systemd RootDirectory$extra"
    else
        sec_audit_report_fail "$num" "chroot not configured in process args or systemd unit$extra"
    fi
}

sec_audit_check_cache_recursion_acl() {
    local num="$1"
    local opt ar aq rec
    opt=$(sec_audit_options_body)
    rec=$(sec_audit_scalar_in "$opt" "recursion")
    ar=$(sec_audit_acl_in "$opt" "allow-recursion")
    aq=$(sec_audit_acl_in "$opt" "allow-query")
    if printf '%s' "$rec" | grep -qi '^no$' || sec_audit_acl_is_none "$ar"; then
        sec_audit_report_pass "$num" "non-recursive role; allow-recursion=${ar:-none} recursion=${rec:-unset}"
        return 0
    fi
    if ! sec_audit_serves_resolver; then
        sec_audit_report_pass "$num" "not applicable (not a caching name server)"
        return 0
    fi
    if sec_audit_acl_is_tight "$ar"; then
        sec_audit_report_pass "$num" "caching server allow-recursion restricted ($ar)"
        return 0
    fi
    if sec_audit_acl_is_tight "$aq" && [ -z "$ar" ]; then
        sec_audit_report_pass "$num" "allow-query restricted ($aq); allow-recursion inherits query ACL"
        return 0
    fi
    sec_audit_report_fail "$num" "caching/recursive server lacks restrictive allow-recursion ACL (allow-recursion=${ar:-unset} allow-query=${aq:-unset})"
}

sec_audit_check_dos_capacity() {
    local num="$1"
    local opt hits="" rec aq
    opt=$(sec_audit_options_body)
    rec=$(sec_audit_scalar_in "$opt" "recursion")
    aq=$(sec_audit_acl_in "$opt" "allow-query")
    sec_audit_blob_has "$opt" 'rate-limit[[:space:]]*\{' && hits="${hits} rate-limit"
    sec_audit_blob_has "$opt" 'fetches-per-server' && hits="${hits} fetches-per-server=$(sec_audit_numeric_in "$opt" "fetches-per-server")"
    sec_audit_blob_has "$opt" 'fetches-per-zone' && hits="${hits} fetches-per-zone=$(sec_audit_numeric_in "$opt" "fetches-per-zone")"
    sec_audit_blob_has "$opt" 'max-clients-per-query' && hits="${hits} max-clients-per-query"
    sec_audit_blob_has "$opt" 'recursive-clients' && hits="${hits} recursive-clients=$(sec_audit_numeric_in "$opt" "recursive-clients")"
    sec_audit_blob_has "$opt" 'tcp-clients' && hits="${hits} tcp-clients=$(sec_audit_numeric_in "$opt" "tcp-clients")"
    sec_audit_blob_has "$opt" 'transfers-out' && hits="${hits} transfers-out=$(sec_audit_numeric_in "$opt" "transfers-out")"
    if printf '%s' "$rec" | grep -qi '^no$' && { sec_audit_acl_is_tight "$aq" || sec_audit_acl_is_none "$aq" || [ -n "$aq" ]; }; then
        sec_audit_report_pass "$num" "DoS surface reduced: recursion=no allow-query=${aq:-unset}$hits"
        return 0
    fi
    if [ -n "$hits" ]; then
        sec_audit_report_pass "$num" "DoS controls present:$hits recursion=${rec:-unset}"
        return 0
    fi
    sec_audit_report_fail "$num" "no rate-limit/fetches-per-*/client caps; recursion=${rec:-unset} allow-query=${aq:-unset}"
}

sec_audit_check_dnssec_mode() {
    local num="$1"
    local f n=0 bad=0 mode
    if [ -z "$(sec_audit_dnssec_material_paths)" ]; then
        sec_audit_report_pass "$num" "no DNSSEC key files on disk"
        return 0
    fi
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        n=$((n + 1))
        mode=$(sec_audit_path_mode_octal "$f")
        if [ "$mode" != "400" ] && [ "$mode" != "440" ] && [ "$mode" != "600" ]; then
            bad=$((bad + 1))
        elif sec_audit_mode_world_writable "$mode"; then
            bad=$((bad + 1))
        fi
    done < <(sec_audit_dnssec_material_paths)
    if [ "$bad" -eq 0 ]; then
        sec_audit_report_pass "$num" "all $n DNSSEC key file(s) are owner-read (400/440/600)"
    else
        sec_audit_report_fail "$num" "$bad of $n DNSSEC key file(s) are not owner-read-only"
    fi
}

sec_audit_check_dnssec_owner() {
    local num="$1"
    local f n=0 bad=0 o
    if [ -z "$(sec_audit_dnssec_material_paths)" ]; then
        sec_audit_report_pass "$num" "no DNSSEC key files on disk"
        return 0
    fi
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        n=$((n + 1))
        o=$(sec_audit_path_owner_user "$f")
        sec_audit_user_is_priv "$o" || [ "$o" = "$_BIND_DAEMON_ACCT" ] || bad=$((bad + 1))
    done < <(sec_audit_dnssec_material_paths)
    if [ "$bad" -eq 0 ]; then
        sec_audit_report_pass "$num" "all $n DNSSEC key file(s) owned by privileged account"
    else
        sec_audit_report_fail "$num" "$bad of $n DNSSEC key file(s) not owned by privileged account"
    fi
}

sec_audit_check_dnssec_group() {
    local num="$1"
    local f n=0 bad=0 g
    if [ -z "$(sec_audit_dnssec_material_paths)" ]; then
        sec_audit_report_pass "$num" "no DNSSEC key files on disk"
        return 0
    fi
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        n=$((n + 1))
        g=$(sec_audit_path_owner_group "$f")
        sec_audit_group_is_priv "$g" || [ "$g" = "$_BIND_DAEMON_GRP" ] || bad=$((bad + 1))
    done < <(sec_audit_dnssec_material_paths)
    if [ "$bad" -eq 0 ]; then
        sec_audit_report_pass "$num" "all $n DNSSEC key file(s) group-owned by privileged account"
    else
        sec_audit_report_fail "$num" "$bad of $n DNSSEC key file(s) not group-owned by privileged account"
    fi
}

sec_audit_check_log_versions() {
    local num="$1"
    local logb ver
    logb=$(sec_audit_logging_body)
    ver=$(printf '%s' "$logb" | awk '
        BEGIN { IGNORECASE=1 }
        /versions/ {
            for (i=1;i<=NF;i++) if ($i ~ /^[0-9]+$/) { print $i; exit }
            if (match($0, /versions[[:space:]]+[0-9]+/)) {
                s=substr($0,RSTART,RLENGTH)
                gsub(/[^0-9]/,"",s)
                print s
                exit
            }
        }
    ')
    if [ -n "$ver" ] && [ "$ver" -ge "$BIND9_LOG_VERSIONS_MIN" ] 2>/dev/null; then
        sec_audit_report_pass "$num" "logging file versions=$ver (>=${BIND9_LOG_VERSIONS_MIN})"
    else
        sec_audit_report_fail "$num" "logging file versions=${ver:-missing} (expected >=${BIND9_LOG_VERSIONS_MIN})"
    fi
}

sec_audit_check_log_file_channel() {
    local num="$1"
    local logb
    logb=$(sec_audit_logging_body)
    if sec_audit_blob_has "$logb" 'file[[:space:]]+"?[^";]+'; then
        sec_audit_report_pass "$num" "logging channel sends audit records to a local file"
    else
        sec_audit_report_fail "$num" "no logging channel with file destination"
    fi
}

sec_audit_check_log_syslog_channel() {
    local num="$1"
    local logb remote=0
    logb=$(sec_audit_logging_body)
    if sec_audit_blob_has "$logb" 'syslog[[:space:]]'; then
        grep -RqsE '^[[:space:]]*\*\.\*[[:space:]]+@|^[[:space:]]*.*@@' /etc/rsyslog.conf /etc/rsyslog.d /etc/syslog-ng/syslog-ng.conf 2>/dev/null && remote=1
        if [ "$remote" -eq 1 ]; then
            sec_audit_report_pass "$num" "logging syslog channel present; remote syslog forwarding configured"
        else
            sec_audit_report_pass "$num" "logging syslog channel present (verify remote forwarding in rsyslog/syslog-ng)"
        fi
    else
        sec_audit_report_fail "$num" "no logging channel sending audit records to syslog"
    fi
}

sec_audit_check_server_auth() {
    local num="$1"
    local nkeys nsrv at zones opt
    opt=$(sec_audit_options_body)
    zones=$(sec_audit_zone_blocks)
    nkeys=$(sec_audit_key_statement_count)
    nsrv=$(sec_audit_server_blocks | sec_audit_count_pat '^[[:space:]]*server[[:space:]]')
    at=$(sec_audit_acl_in "$opt" "allow-transfer")
    [ -z "$at" ] && at=$(sec_audit_acl_in "$zones" "allow-transfer")
    if sec_audit_acl_is_none "$at" && ! sec_audit_updates_allowed && [ "$nkeys" -eq 0 ] 2>/dev/null; then
        sec_audit_report_pass "$num" "no server-server transfers/updates; TSIG session not required"
        return 0
    fi
    if [ "$nkeys" -ge 1 ] 2>/dev/null && { [ "$nsrv" -ge 1 ] 2>/dev/null || printf '%s' "$at" | grep -qiE 'key[[:space:]]'; }; then
        sec_audit_report_pass "$num" "TSIG configured (keys=$nkeys server-blocks=$nsrv allow-transfer uses key=$(printf '%s' "$at" | grep -qiE 'key' && echo yes || echo no))"
        return 0
    fi
    if sec_audit_rndc_material_path >/dev/null && [ "$nkeys" -ge 1 ] 2>/dev/null; then
        sec_audit_report_pass "$num" "TSIG key material present (keys=$nkeys, rndc key file found)"
        return 0
    fi
    sec_audit_report_fail "$num" "mutual TSIG authentication for zone transfer/update not configured (keys=$nkeys server-blocks=$nsrv)"
}

# --- runners (RULE1-56 sequential, same checks as before) ---
sec_audit_run_transfers() {
    # RULE1-4
    sec_audit_check_xfer_limit 1
    sec_audit_check_xfer_per_ns 2
    sec_audit_check_xfer_in 3
    sec_audit_check_xfer_out 4
}

sec_audit_run_logging_print() {
    # RULE5-8
    sec_audit_check_print_severity 5
    sec_audit_check_print_time 6
    sec_audit_check_print_category 7
    sec_audit_check_audit_coverage 8
}

sec_audit_run_online_keys() {
    # RULE9-10
    sec_audit_check_zsk_only_online 9
    sec_audit_check_ksk_offline 10
}

sec_audit_run_tsig_files() {
    # RULE11-15
    sec_audit_check_tsig_owner_named 11
    sec_audit_check_tsig_mode 12
    sec_audit_check_tsig_unique 13
    sec_audit_check_tsig_priv_owner 14
    sec_audit_check_tsig_priv_group 15
}

sec_audit_run_split_dns() {
    # RULE16-21
    sec_audit_check_split_zone_files 16
    sec_audit_check_internal_match 17
    sec_audit_check_external_match 18
    sec_audit_check_hidden_primary 19
    sec_audit_check_nsec3 20
    sec_audit_check_offline_when_static 21
}

sec_audit_run_keygen_zsk() {
    # RULE22-26
    sec_audit_check_keygen_owner 22
    sec_audit_check_keygen_group 23
    sec_audit_check_keygen_mode 24
    sec_audit_check_zsk_owner 25
    sec_audit_check_zsk_group 26
}

sec_audit_run_roles_notify() {
    # RULE27-33
    sec_audit_check_slave_notify 27
    sec_audit_check_auth_no_recursion 28
    sec_audit_check_master_notify 29
    sec_audit_check_root_hints_valid 30
    sec_audit_check_auth_no_root_master 31
    sec_audit_check_allow_transfer 32
    sec_audit_check_split_roles 33
}

sec_audit_run_network_and_conf() {
    # RULE34-44
    sec_audit_check_random_port 34
    sec_audit_check_mgmt_iface 35
    sec_audit_check_conf_group 36
    sec_audit_check_conf_owner 37
    sec_audit_check_nonroot_daemon 38
    sec_audit_check_key_age 39
    sec_audit_check_conf_mode 40
    sec_audit_check_host_firewall 41
    sec_audit_check_dnssec_integrity 42
    sec_audit_check_log_severity 43
    sec_audit_check_listen_port 44
}

sec_audit_run_auth_chroot_dos() {
    # RULE45-49
    sec_audit_check_tsig_auth 45
    sec_audit_check_tsig_pairs 46
    sec_audit_check_chroot_jail 47
    sec_audit_check_cache_recursion_acl 48
    sec_audit_check_dos_capacity 49
}

sec_audit_run_dnssec_logging() {
    # RULE50-56
    sec_audit_check_dnssec_mode 50
    sec_audit_check_dnssec_owner 51
    sec_audit_check_dnssec_group 52
    sec_audit_check_log_versions 53
    sec_audit_check_log_file_channel 54
    sec_audit_check_log_syslog_channel 55
    sec_audit_check_server_auth 56
}

sec_audit_skip_all_rules() {
    local n=1
    while [ "$n" -le 56 ]; do
        sec_audit_report_skip "$n" "bind/named not installed and named.conf not found"
        n=$((n + 1))
    done
}

sec_audit_bootstrap_bind() {
    sec_audit_layout_probe

    if ! sec_audit_software_present && ! sec_audit_conf_present; then
        sec_audit_skip_all_rules
        return 1
    fi

    sec_audit_build_parsed_view
    _BIND_WORKDIR=$(sec_audit_workdir_of)
    _BIND_DAEMON_ACCT=$(sec_audit_daemon_user)
    _BIND_DAEMON_GRP=$(sec_audit_daemon_group)
    _BIND_PID_PATH=$(sec_audit_pid_path_of)
    _BIND_CHROOT_PATH=$(sec_audit_chroot_root_of 2>/dev/null || true)

    [ -z "$_BIND_DAEMON_ACCT" ] && _BIND_DAEMON_ACCT=$(printf '%s' "$(sec_audit_unit_file_text)" | awk -F= '/^User=/{print $2; exit}')
    [ -z "$_BIND_DAEMON_ACCT" ] && _BIND_DAEMON_ACCT="named"
    [ -z "$_BIND_DAEMON_GRP" ] && _BIND_DAEMON_GRP=$(id -gn "$_BIND_DAEMON_ACCT" 2>/dev/null || printf '%s' "named")
    return 0
}

sec_audit_main() {
    if ! sec_audit_bootstrap_bind; then
        exit 0
    fi
    sec_audit_run_transfers
    sec_audit_run_logging_print
    sec_audit_run_online_keys
    sec_audit_run_tsig_files
    sec_audit_run_split_dns
    sec_audit_run_keygen_zsk
    sec_audit_run_roles_notify
    sec_audit_run_network_and_conf
    sec_audit_run_auth_chroot_dos
    sec_audit_run_dnssec_logging
    exit 0
}

sec_audit_main "$@"
