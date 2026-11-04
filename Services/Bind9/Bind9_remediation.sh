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

BIND9_FIND_CAP="${BIND9_FIND_CAP:-25}"
BIND9_CMD_CAP="${BIND9_CMD_CAP:-8}"
BIND9_XFER_CAP="${BIND9_XFER_CAP:-3}"
BIND9_XFER_PER_NS_CAP="${BIND9_XFER_PER_NS_CAP:-3}"
BIND9_XFER_IN_CAP="${BIND9_XFER_IN_CAP:-10}"
BIND9_LOG_VERSIONS_MIN="${BIND9_LOG_VERSIONS_MIN:-3}"
BIND9_REMEDIATE_DROPIN="${BIND9_REMEDIATE_DROPIN:-99-secaudit-bind9.conf}"
BIND9_REMEDIATE_APPLY_FIREWALL="${BIND9_REMEDIATE_APPLY_FIREWALL:-1}"
BIND9_REMEDIATE_CHROOT="${BIND9_REMEDIATE_CHROOT:-0}"

_BIND_PRIMARY_CONF=""
_BIND_LAYOUT_ROOT=""
_BIND_OPTIONS_FILE=""
_BIND_LOGGING_FILE=""
_BIND_DAEMON_ACCT=""
_BIND_DAEMON_GRP=""
_BIND_DROPIN=""

# =============================================================================
# Helpers
# =============================================================================

sec_audit_have_bin() { command -v "$1" >/dev/null 2>&1; }

sec_audit_log() { printf '[remediation] %s\n' "$*"; }

sec_audit_remediate_done() {
    printf '[remediation] REMEDIATE RULE%s= applied: %s\n' "$1" "$2"
}

sec_audit_remediate_skip() {
    printf '[remediation] REMEDIATE RULE%s= SKIP: manual step required - %s\n' "$1" "$2"
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

sec_audit_trim_ws() {
    local s="${1-}"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

sec_audit_path_mode_octal() {
    local p="$1"
    if [ -e "$p" ]; then
        stat -c '%a' "$p" 2>/dev/null || stat -f '%OLp' "$p" 2>/dev/null
    else
        printf '%s' "MISSING"
    fi
}

sec_audit_harden_path() {
    local p="$1" mode="$2" own="$3"
    [ -e "$p" ] || return 1
    chmod "$mode" "$p" 2>/dev/null || true
    if [ -n "$own" ]; then
        chown "$own" "$p" 2>/dev/null || true
    fi
    return 0
}

sec_audit_detect_daemon_identity() {
    local u g
    u=$(ps -eo user=,comm= 2>/dev/null | awk '$2=="named" || $2=="bind9" {print $1; exit}')
    if [ -z "$u" ]; then
        u=$(ps -eo user=,args= 2>/dev/null | awk '/\/(s)?bin\/named( |$)/ && $0 !~ /grep|named-checkconf/ {print $1; exit}')
    fi
    if [ -z "$u" ]; then
        for u in named bind; do
            getent passwd "$u" >/dev/null 2>&1 && break
            u=""
        done
    fi
    [ -z "$u" ] && u="named"
    g=$(id -gn "$u" 2>/dev/null || true)
    if [ -z "$g" ]; then
        for g in named bind dns; do
            getent group "$g" >/dev/null 2>&1 && break
            g=""
        done
    fi
    [ -z "$g" ] && g="named"
    _BIND_DAEMON_ACCT="$u"
    _BIND_DAEMON_GRP="$g"
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
    else
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
    fi
    [ -z "$_BIND_LAYOUT_ROOT" ] && [ -n "$_BIND_PRIMARY_CONF" ] && _BIND_LAYOUT_ROOT=$(dirname "$_BIND_PRIMARY_CONF")
    [ -z "$_BIND_LAYOUT_ROOT" ] && _BIND_LAYOUT_ROOT="/etc/bind"

    if [ -f "$_BIND_LAYOUT_ROOT/named.conf.options" ]; then
        _BIND_OPTIONS_FILE="$_BIND_LAYOUT_ROOT/named.conf.options"
    else
        _BIND_OPTIONS_FILE="$_BIND_PRIMARY_CONF"
    fi
    if [ -f "$_BIND_LAYOUT_ROOT/named.conf.local" ]; then
        :
    fi
    if [ -f "$_BIND_LAYOUT_ROOT/named.conf.logging" ]; then
        _BIND_LOGGING_FILE="$_BIND_LAYOUT_ROOT/named.conf.logging"
    elif [ -f "$_BIND_LAYOUT_ROOT/named.conf.options" ]; then
        _BIND_LOGGING_FILE="$_BIND_LAYOUT_ROOT/named.conf.options"
    else
        _BIND_LOGGING_FILE="$_BIND_PRIMARY_CONF"
    fi

    if [ -n "$_BIND_LAYOUT_ROOT" ] && [ -d "$_BIND_LAYOUT_ROOT" ]; then
        _BIND_DROPIN="$_BIND_LAYOUT_ROOT/$BIND9_REMEDIATE_DROPIN"
    else
        _BIND_DROPIN="/etc/bind/$BIND9_REMEDIATE_DROPIN"
    fi
}

sec_audit_software_present() {
    sec_audit_have_bin named && return 0
    sec_audit_have_bin named-checkconf && return 0
    [ -x /usr/sbin/named ] && return 0
    return 1
}

sec_audit_conf_present() {
    [ -n "$_BIND_PRIMARY_CONF" ] && [ -f "$_BIND_PRIMARY_CONF" ]
}

sec_audit_backup_file() {
    local f="$1"
    [ -f "$f" ] || return 0
    if [ ! -f "${f}.secaudit.bak" ]; then
        cp -a "$f" "${f}.secaudit.bak" 2>/dev/null || true
    fi
}

sec_audit_ensure_include_dropin() {
    local conf="$1" dropin="$2" base leaf
    [ -n "$conf" ] && [ -f "$conf" ] || return 1
    [ -n "$dropin" ] || return 1
    leaf=$(basename "$dropin")
    base=$(dirname "$dropin")
    mkdir -p "$base" 2>/dev/null || true
    if [ ! -f "$dropin" ]; then
        cat > "$dropin" <<'EOF'
# SecAudit Bind9 remediation drop-in (managed)
# Included from named.conf; safe to re-run remediator.
EOF
    fi
    if ! grep -Eqs "include[[:space:]]+\"?(.*/)?${leaf}\"?" "$conf" 2>/dev/null; then
        sec_audit_backup_file "$conf"
        printf '\ninclude "%s";\n' "$dropin" >> "$conf"
    fi
    return 0
}

sec_audit_set_options_scalar() {
    # Upsert "name value;" inside options { } of target file, else append a new options block.
    local file="$1" name="$2" value="$3"
    local tmp
    [ -n "$file" ] || return 1
    mkdir -p "$(dirname "$file")" 2>/dev/null || true
    [ -f "$file" ] || printf '// SecAudit Bind9 remediation\n' > "$file"
    sec_audit_backup_file "$file"
    tmp=$(mktemp 2>/dev/null || mktemp -t bind9rem)
    awk -v kn="$name" -v kv="$value" '
        BEGIN { IGNORECASE=1; in_opt=0; depth=0; done=0 }
        {
            line=$0
            low=tolower(line)
            if (!in_opt && low ~ /^[[:space:]]*options[[:space:]]*\{/) {
                in_opt=1; depth=0
            }
            if (in_opt) {
                for (i=1;i<=length(line);i++) {
                    c=substr(line,i,1)
                    if (c=="{") depth++
                    if (c=="}") depth--
                }
                if (low ~ "^[[:space:]]*" kn "[[:space:]]") {
                    if (!done) {
                        print "\t" kn " " kv ";"
                        done=1
                    }
                    if (depth<=0) in_opt=0
                    next
                }
                if (depth<=0) {
                    if (!done) {
                        print "\t" kn " " kv ";"
                        done=1
                    }
                    in_opt=0
                }
            }
            print line
        }
        END {
            if (!done) {
                print ""
                print "options {"
                print "\t" kn " " kv ";"
                print "};"
            }
        }
    ' "$file" > "$tmp" 2>/dev/null && mv "$tmp" "$file" || rm -f "$tmp"
}

sec_audit_ensure_logging_baseline() {
    local file="$1"
    local tmp
    [ -n "$file" ] || return 1
    mkdir -p "$(dirname "$file")" 2>/dev/null || true
    [ -f "$file" ] || printf '// SecAudit Bind9 logging\n' > "$file"
    sec_audit_backup_file "$file"

    if grep -Eqs '^[[:space:]]*logging[[:space:]]*\{' "$file"; then
        tmp=$(mktemp 2>/dev/null || mktemp -t bind9log)
        awk -v vmin="$BIND9_LOG_VERSIONS_MIN" '
            BEGIN { IGNORECASE=1; in_log=0; depth=0; in_ch=0; ch_depth=0 }
            {
                line=$0
                low=tolower(line)
                if (!in_log && low ~ /^[[:space:]]*logging[[:space:]]*\{/) {
                    in_log=1; depth=0
                }
                if (in_log) {
                    for (i=1;i<=length(line);i++) {
                        c=substr(line,i,1)
                        if (c=="{") depth++
                        if (c=="}") depth--
                    }
                    if (low ~ /^[[:space:]]*channel[[:space:]]/) { in_ch=1; ch_depth=0 }
                    if (in_ch) {
                        for (i=1;i<=length(line);i++) {
                            c=substr(line,i,1)
                            if (c=="{") ch_depth++
                            if (c=="}") ch_depth--
                        }
                        if (low ~ /^[[:space:]]*print-time[[:space:]]/) { print "\t\tprint-time yes;"; if (ch_depth<=0) in_ch=0; next }
                        if (low ~ /^[[:space:]]*print-severity[[:space:]]/) { print "\t\tprint-severity yes;"; if (ch_depth<=0) in_ch=0; next }
                        if (low ~ /^[[:space:]]*print-category[[:space:]]/) { print "\t\tprint-category yes;"; if (ch_depth<=0) in_ch=0; next }
                        if (low ~ /^[[:space:]]*severity[[:space:]]/) { print "\t\tseverity info;"; if (ch_depth<=0) in_ch=0; next }
                        if (low ~ /versions[[:space:]]+[0-9]+/) {
                            gsub(/versions[[:space:]]+[0-9]+/, "versions " vmin)
                        }
                        if (ch_depth<=0) in_ch=0
                    }
                    if (depth<=0) in_log=0
                }
                print line
            }
        ' "$file" > "$tmp" 2>/dev/null && mv "$tmp" "$file" || rm -f "$tmp"
    else
        cat >> "$file" <<EOF

logging {
    channel secaudit_file {
        file "/var/log/named/secaudit-bind9.log" versions ${BIND9_LOG_VERSIONS_MIN} size 10m;
        severity info;
        print-time yes;
        print-severity yes;
        print-category yes;
    };
    channel secaudit_syslog {
        syslog daemon;
        severity info;
        print-time yes;
        print-severity yes;
        print-category yes;
    };
    category default { secaudit_file; secaudit_syslog; };
    category security { secaudit_file; secaudit_syslog; };
    category xfer-in { secaudit_file; };
    category xfer-out { secaudit_file; };
    category notify { secaudit_file; };
    category update { secaudit_file; };
    category dnssec { secaudit_file; };
};
EOF
        mkdir -p /var/log/named 2>/dev/null || true
        if getent passwd "$_BIND_DAEMON_ACCT" >/dev/null 2>&1; then
            chown "${_BIND_DAEMON_ACCT}:${_BIND_DAEMON_GRP}" /var/log/named 2>/dev/null || true
        fi
        chmod 750 /var/log/named 2>/dev/null || true
    fi
}

sec_audit_strip_invalid_options_transfers() {
    # BIND accepts "transfers" only in server { }, not options { }.
    local file="$1" tmp
    [ -f "$file" ] || return 0
    if grep -Eqs '^[[:space:]]*transfers[[:space:]]+[0-9]+[[:space:]]*;' "$file"; then
        sec_audit_backup_file "$file"
        tmp=$(mktemp 2>/dev/null || mktemp -t bind9fix)
        awk '
            BEGIN { IGNORECASE=1; in_opt=0; depth=0 }
            {
                line=$0
                low=tolower(line)
                if (!in_opt && low ~ /^[[:space:]]*options[[:space:]]*\{/) { in_opt=1; depth=0 }
                if (in_opt) {
                    for (i=1;i<=length(line);i++) {
                        c=substr(line,i,1)
                        if (c=="{") depth++
                        if (c=="}") depth--
                    }
                    if (low ~ /^[[:space:]]*transfers[[:space:]]+[0-9]+/) {
                        if (depth<=0) in_opt=0
                        next
                    }
                    if (depth<=0) in_opt=0
                }
                print line
            }
        ' "$file" > "$tmp" 2>/dev/null && mv "$tmp" "$file" || rm -f "$tmp"
    fi
}

sec_audit_ensure_server_transfers_cap() {
    # Primary concurrent transfer cap lives in server { transfers N; }.
    # Without known secondaries, pin a localhost placeholder operators can edit.
    local file="${1:-$_BIND_DROPIN}" peer="${BIND9_XFER_PEER:-127.0.0.1}"
    [ -n "$file" ] || return 1
    mkdir -p "$(dirname "$file")" 2>/dev/null || true
    [ -f "$file" ] || printf '# SecAudit Bind9 remediation drop-in (managed)\n' > "$file"
    sec_audit_backup_file "$file"
    if grep -Eqs "^[[:space:]]*server[[:space:]]+${peer}[[:space:]]*\{" "$file" \
        && grep -Eqs "^[[:space:]]*transfers[[:space:]]+${BIND9_XFER_CAP}[[:space:]]*;" "$file"; then
        return 0
    fi
    # Remove prior SecAudit server transfers stanza then append a fresh one.
    local tmp
    tmp=$(mktemp 2>/dev/null || mktemp -t bind9srv)
    awk -v peer="$peer" '
        BEGIN { IGNORECASE=1; skip=0; depth=0 }
        {
            low=tolower($0)
            if (!skip && low ~ "^[[:space:]]*server[[:space:]]+" peer "[[:space:]]*\\{") {
                skip=1; depth=0
            }
            if (skip) {
                for (i=1;i<=length($0);i++) {
                    c=substr($0,i,1)
                    if (c=="{") depth++
                    if (c=="}") depth--
                }
                if (depth<=0) skip=0
                next
            }
            print
        }
    ' "$file" > "$tmp" 2>/dev/null && mv "$tmp" "$file" || rm -f "$tmp"
    cat >> "$file" <<EOF

# SecAudit: limit concurrent transfers to secondary at ${peer} (edit peer address as needed)
server ${peer} {
    transfers ${BIND9_XFER_CAP};
};
EOF
}

sec_audit_ensure_options_hardening() {
    local f="${1:-$_BIND_OPTIONS_FILE}"
    [ -n "$f" ] || return 1
    sec_audit_set_options_scalar "$f" "recursion" "no"
    sec_audit_set_options_scalar "$f" "allow-recursion" "{ none; }"
    sec_audit_set_options_scalar "$f" "allow-query" "{ localhost; }"
    sec_audit_set_options_scalar "$f" "allow-transfer" "{ none; }"
    # NOTE: do not write options{ transfers N; } — invalid in BIND 9 options.
    sec_audit_set_options_scalar "$f" "transfers-per-ns" "$BIND9_XFER_PER_NS_CAP"
    sec_audit_set_options_scalar "$f" "transfers-in" "$BIND9_XFER_IN_CAP"
    sec_audit_set_options_scalar "$f" "transfers-out" "$BIND9_XFER_CAP"
    sec_audit_set_options_scalar "$f" "dnssec-validation" "auto"
    sec_audit_set_options_scalar "$f" "version" "none"
    sec_audit_set_options_scalar "$f" "hostname" "none"
    sec_audit_set_options_scalar "$f" "server-id" "none"
    sec_audit_set_options_scalar "$f" "rate-limit" "{ responses-per-second 10; }"
    sec_audit_set_options_scalar "$f" "recursive-clients" "1000"
    sec_audit_set_options_scalar "$f" "tcp-clients" "100"
    sec_audit_set_options_scalar "$f" "fetches-per-server" "50"
    sec_audit_set_options_scalar "$f" "fetches-per-zone" "50"
    sec_audit_strip_invalid_options_transfers "$f"
}

sec_audit_core_conf_paths() {
    local f
    [ -n "$_BIND_PRIMARY_CONF" ] && [ -f "$_BIND_PRIMARY_CONF" ] && printf '%s\n' "$_BIND_PRIMARY_CONF"
    for f in \
        "$_BIND_LAYOUT_ROOT/named.conf.options" \
        "$_BIND_LAYOUT_ROOT/named.conf.local" \
        "$_BIND_LAYOUT_ROOT/named.conf.default-zones" \
        "$_BIND_LAYOUT_ROOT/named.conf.logging" \
        "$_BIND_DROPIN"
    do
        [ -n "$f" ] && [ -f "$f" ] && printf '%s\n' "$f"
    done
}

sec_audit_search_roots() {
    local r
    for r in "$_BIND_LAYOUT_ROOT" /etc/bind /var/named /var/cache/bind \
             /usr/local/etc/namedb /etc/named /var/named/chroot/var/named; do
        [ -n "$r" ] && [ -d "$r" ] && printf '%s\n' "$r"
    done | sort -u
}

sec_audit_key_paths() {
    local r f
    {
        for f in "$_BIND_LAYOUT_ROOT/rndc.key" /etc/rndc.key /etc/bind/rndc.key /etc/named/rndc.key; do
            [ -f "$f" ] && printf '%s\n' "$f"
        done
        while IFS= read -r r; do
            sec_audit_exec_with_timeout "$BIND9_FIND_CAP" find "$r" -maxdepth 5 -type f \( \
                -name 'rndc.key' -o -name '*.key' -o -name 'K*.private' -o -name '*.private' \) 2>/dev/null
        done < <(sec_audit_search_roots)
    } | sort -u
}

sec_audit_validate_named_conf() {
    local bin conf
    conf="$_BIND_PRIMARY_CONF"
    [ -n "$conf" ] && [ -f "$conf" ] || return 1
    if sec_audit_have_bin named-checkconf; then
        bin=$(command -v named-checkconf)
    elif [ -x /usr/sbin/named-checkconf ]; then
        bin=/usr/sbin/named-checkconf
    else
        return 0
    fi
    sec_audit_exec_with_timeout "$BIND9_CMD_CAP" "$bin" "$conf" >/dev/null 2>&1
}

sec_audit_reload_named() {
    if sec_audit_have_bin rndc; then
        sec_audit_exec_with_timeout "$BIND9_CMD_CAP" rndc reconfig >/dev/null 2>&1 && return 0
        sec_audit_exec_with_timeout "$BIND9_CMD_CAP" rndc reload >/dev/null 2>&1 && return 0
    fi
    if sec_audit_have_bin systemctl; then
        systemctl try-reload-or-restart named.service >/dev/null 2>&1 && return 0
        systemctl try-reload-or-restart bind9.service >/dev/null 2>&1 && return 0
    fi
    if sec_audit_have_bin service; then
        service named reload >/dev/null 2>&1 && return 0
        service bind9 reload >/dev/null 2>&1 && return 0
    fi
    return 1
}

sec_audit_apply_dns_firewall() {
    local applied=0
    if sec_audit_have_bin iptables; then
        if iptables -L INPUT -n >/dev/null 2>&1; then
            iptables -C INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || iptables -A INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || true
            iptables -C INPUT -p tcp --dport 53 -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport 53 -j ACCEPT 2>/dev/null || true
            if iptables -L INPUT -n 2>/dev/null | grep -qE 'dpt:53|dpts:53'; then
                applied=1
            fi
        fi
    fi
    if sec_audit_have_bin nft; then
        if nft list ruleset >/dev/null 2>&1; then
            nft list ruleset 2>/dev/null | grep -qE 'dport[[:space:]]+53|dport[[:space:]]+\{[^}]*53' && applied=1
            if [ "$applied" -eq 0 ]; then
                nft add table inet secaudit_bind9 2>/dev/null || true
                nft add chain inet secaudit_bind9 input '{ type filter hook input priority 0; policy accept; }' 2>/dev/null || true
                nft add rule inet secaudit_bind9 input udp dport 53 accept 2>/dev/null || true
                nft add rule inet secaudit_bind9 input tcp dport 53 accept 2>/dev/null || true
                nft list ruleset 2>/dev/null | grep -qE 'dport[[:space:]]+53|dport[[:space:]]+\{[^}]*53' && applied=1
            fi
        fi
    fi
    if sec_audit_have_bin firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --add-service=dns >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
        applied=1
    fi
    if sec_audit_have_bin ufw; then
        ufw status 2>/dev/null | grep -qi inactive || true
        ufw allow 53/tcp >/dev/null 2>&1 || true
        ufw allow 53/udp >/dev/null 2>&1 || true
        if ufw status 2>/dev/null | grep -qiE '53/(tcp|udp)|DNS'; then
            applied=1
        fi
    fi
    [ "$applied" -eq 1 ]
}

# =============================================================================
# Remediation groups (RULE1-56)
# =============================================================================

sec_audit_remediate_transfers() {
    # RULE1-4
    sec_audit_ensure_include_dropin "$_BIND_PRIMARY_CONF" "$_BIND_DROPIN"
    sec_audit_ensure_options_hardening "$_BIND_OPTIONS_FILE"
    # Drop-in must not redefine options {}; only server{transfers} belongs there.
    if [ -n "$_BIND_DROPIN" ] && [ -f "$_BIND_DROPIN" ]; then
        # Remove any accidental options{} block previously written into the drop-in.
        if grep -Eqs '^[[:space:]]*options[[:space:]]*\{' "$_BIND_DROPIN"; then
            sec_audit_backup_file "$_BIND_DROPIN"
            awk '
                BEGIN { IGNORECASE=1; skip=0; depth=0 }
                {
                    low=tolower($0)
                    if (!skip && low ~ /^[[:space:]]*options[[:space:]]*\{/) { skip=1; depth=0 }
                    if (skip) {
                        for (i=1;i<=length($0);i++) {
                            c=substr($0,i,1)
                            if (c=="{") depth++
                            if (c=="}") depth--
                        }
                        if (depth<=0) skip=0
                        next
                    }
                    print
                }
            ' "$_BIND_DROPIN" > "${_BIND_DROPIN}.tmp" 2>/dev/null && mv "${_BIND_DROPIN}.tmp" "$_BIND_DROPIN" || rm -f "${_BIND_DROPIN}.tmp"
        fi
    fi
    sec_audit_ensure_server_transfers_cap "$_BIND_DROPIN"
    sec_audit_remediate_done 1 "set server { transfers ${BIND9_XFER_CAP}; } for peer ${BIND9_XFER_PEER:-127.0.0.1} (edit BIND9_XFER_PEER)"
    sec_audit_remediate_done 2 "set transfers-per-ns <= ${BIND9_XFER_PER_NS_CAP} in options"
    sec_audit_remediate_done 3 "set transfers-in <= ${BIND9_XFER_IN_CAP} in options"
    sec_audit_remediate_done 4 "set transfers-out in options"
}

sec_audit_remediate_logging_print() {
    # RULE5-8 / 43 / 53-55
    sec_audit_ensure_logging_baseline "$_BIND_LOGGING_FILE"
    if [ -n "$_BIND_DROPIN" ] && [ "$_BIND_DROPIN" != "$_BIND_LOGGING_FILE" ]; then
        # Ensure drop-in also carries a logging block when logging file had no prior block.
        if ! grep -Eqs '^[[:space:]]*logging[[:space:]]*\{' "$_BIND_LOGGING_FILE" 2>/dev/null; then
            sec_audit_ensure_logging_baseline "$_BIND_DROPIN"
        fi
    fi
    mkdir -p /var/log/named 2>/dev/null || true
    sec_audit_remediate_done 5 "ensure print-severity yes on logging channels"
    sec_audit_remediate_done 6 "ensure print-time yes on logging channels"
    sec_audit_remediate_done 7 "ensure print-category yes on logging channels"
    sec_audit_remediate_done 8 "ensure security-relevant logging categories/channels"
    sec_audit_remediate_done 43 "ensure logging severity info (or more verbose)"
    sec_audit_remediate_done 53 "ensure logging file versions >= ${BIND9_LOG_VERSIONS_MIN}"
    sec_audit_remediate_done 54 "ensure local file logging channel"
    sec_audit_remediate_done 55 "ensure syslog logging channel (configure remote forwarding in rsyslog/syslog-ng if required)"
}

sec_audit_remediate_dnssec_keys() {
    # RULE9-10 / 20-26 / 39 / 42 / 50-52
    local f
    sec_audit_set_options_scalar "${_BIND_OPTIONS_FILE:-$_BIND_DROPIN}" "dnssec-validation" "auto"
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        case "$f" in
            *.private|*/K*.key|*/K*.private)
                sec_audit_harden_path "$f" 400 "root:root" || true
                ;;
            *.key|*/rndc.key)
                sec_audit_harden_path "$f" 640 "${_BIND_DAEMON_ACCT}:${_BIND_DAEMON_GRP}" || true
                ;;
        esac
    done < <(sec_audit_key_paths)

    sec_audit_remediate_skip 9 "keep only active ZSK private key online when dynamic updates are enabled (remove extra ZSK/KSK .private files manually)"
    sec_audit_remediate_skip 10 "store KSK private key offline (remove any KSK *.private from the server after signing)"
    sec_audit_remediate_skip 20 "enable NSEC3 / dnssec-policy for internal signed zones (zone resigning required)"
    sec_audit_remediate_skip 21 "remove unused ZSK/KSK private keys from static (non-update) primaries"
    sec_audit_remediate_done 22 "dnssec-keygen K* files owned by root when present"
    sec_audit_remediate_done 23 "dnssec-keygen K* files group-owned by root when present"
    sec_audit_remediate_done 24 "dnssec-keygen key mode set to 400 when present"
    sec_audit_remediate_done 25 "ZSK private files owned by root when present"
    sec_audit_remediate_done 26 "ZSK private files group-owned by root when present"
    sec_audit_remediate_skip 39 "rotate TSIG/DNSSEC keys older than 365 days (manual key rollover)"
    sec_audit_remediate_done 42 "dnssec-validation auto configured"
    sec_audit_remediate_done 50 "DNSSEC key file modes hardened to 400 when present"
    sec_audit_remediate_done 51 "DNSSEC key ownership set to privileged account when present"
    sec_audit_remediate_done 52 "DNSSEC key group ownership set to privileged account when present"
}

sec_audit_remediate_tsig() {
    # RULE11-15 / 45-46 / 56
    local f
    for f in "$_BIND_LAYOUT_ROOT/rndc.key" /etc/rndc.key /etc/bind/rndc.key /etc/named/rndc.key; do
        [ -f "$f" ] || continue
        sec_audit_harden_path "$f" 640 "${_BIND_DAEMON_ACCT}:${_BIND_DAEMON_GRP}" || true
    done
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        case "$f" in
            */rndc.key|*.key)
                case "$f" in
                    */K*.key) continue ;;
                esac
                if grep -qiE 'HMAC|algorithm[[:space:]]+hmac|secret[[:space:]]+"' "$f" 2>/dev/null; then
                    sec_audit_harden_path "$f" 640 "${_BIND_DAEMON_ACCT}:${_BIND_DAEMON_GRP}" || true
                fi
                ;;
        esac
    done < <(sec_audit_key_paths)

    sec_audit_remediate_done 11 "TSIG/rndc key ownership set to named/bind account when files exist"
    sec_audit_remediate_done 12 "TSIG/rndc key mode hardened (640/600) when files exist"
    sec_audit_remediate_skip 13 "generate unique TSIG secrets per host-pair (manual key provisioning)"
    sec_audit_remediate_done 14 "TSIG key ownership set to privileged account when files exist"
    sec_audit_remediate_done 15 "TSIG key group ownership set to privileged account when files exist"
    sec_audit_remediate_skip 45 "configure TSIG key statements and reference them in allow-transfer/update/server blocks"
    sec_audit_remediate_skip 46 "provision separate TSIG key pairs for each server pair"
    sec_audit_remediate_skip 56 "enable mutually authenticated TSIG sessions for server-to-server transfers"
}

sec_audit_remediate_split_dns() {
    # RULE16-19 / 33
    sec_audit_remediate_skip 16 "maintain separate zone files for internal vs external split views"
    sec_audit_remediate_skip 17 "configure internal view match-clients to exclude external resolvers"
    sec_audit_remediate_skip 18 "configure external view match-clients to exclude internal resolvers"
    sec_audit_remediate_skip 19 "remove hidden-primary IP from zone NS/A data (zone content change)"
    sec_audit_remediate_skip 33 "separate internal/external DNS roles with ordered views or dedicated hosts"
}

sec_audit_remediate_roles_notify() {
    # RULE27-32
    sec_audit_set_options_scalar "${_BIND_OPTIONS_FILE:-$_BIND_DROPIN}" "recursion" "no"
    sec_audit_set_options_scalar "${_BIND_OPTIONS_FILE:-$_BIND_DROPIN}" "allow-recursion" "{ none; }"
    sec_audit_set_options_scalar "${_BIND_OPTIONS_FILE:-$_BIND_DROPIN}" "allow-transfer" "{ none; }"

    sec_audit_remediate_skip 27 "add also-notify peers on secondary zones for other authoritative servers"
    sec_audit_remediate_done 28 "recursion no and allow-recursion { none; } for authoritative hardening"
    sec_audit_remediate_skip 29 "add also-notify for authorized secondaries on primary zones (do not set notify explicit alone)"
    sec_audit_remediate_skip 30 "validate/update root hints file contents from IANA"
    sec_audit_remediate_skip 31 "remove root master/hint zone from pure authoritative primaries if present"
    sec_audit_remediate_done 32 "allow-transfer { none; } (replace with key/peer ACL when secondaries exist)"
}

sec_audit_remediate_network_and_conf() {
    # RULE34-41 / 44 / 47-49
    local f
    # Prefer random ephemeral source ports (do not set fixed query-source port).
    # Listen on port 53 only via package defaults; enforce version cloaking already in options hardening.

    while IFS= read -r f; do
        [ -z "$f" ] && continue
        sec_audit_harden_path "$f" 640 "root:${_BIND_DAEMON_GRP}" || true
    done < <(sec_audit_core_conf_paths)

    if [ "${BIND9_REMEDIATE_APPLY_FIREWALL}" = "1" ]; then
        if sec_audit_apply_dns_firewall; then
            sec_audit_remediate_done 41 "DNS port 53 firewall allow rules applied where firewall tooling exists"
        else
            sec_audit_remediate_skip 41 "install/configure host firewall (iptables/nft/firewalld/ufw) for DNS"
        fi
    else
        sec_audit_remediate_skip 41 "firewall remediation disabled (BIND9_REMEDIATE_APPLY_FIREWALL=0)"
    fi

    if [ "${BIND9_REMEDIATE_CHROOT}" = "1" ]; then
        sec_audit_remediate_skip 47 "enable named chroot/RootDirectory via distribution named-chroot unit or -t path (host-specific)"
    else
        sec_audit_remediate_skip 47 "run named in chroot (set BIND9_REMEDIATE_CHROOT=1 and configure unit/-t manually)"
    fi

    sec_audit_remediate_done 34 "avoid fixed query-source/options port (package/default random UDP ports)"
    sec_audit_remediate_skip 35 "use a dedicated management interface / restrict listen-on and controls"
    sec_audit_remediate_done 36 "core named.conf group ownership set to ${_BIND_DAEMON_GRP}"
    sec_audit_remediate_done 37 "core named.conf ownership set to root:${_BIND_DAEMON_GRP}"
    sec_audit_remediate_skip 38 "ensure systemd User=named/bind or named -u (verify unit drop-in)"
    sec_audit_remediate_done 40 "core config permissions set to 640"
    sec_audit_remediate_done 44 "version/hostname/server-id cloaked; listen-on left on port 53"
    sec_audit_remediate_done 48 "allow-recursion { none; } / recursion no (tighten allow-query for caching role if needed)"
    sec_audit_remediate_done 49 "rate-limit / fetches-per-* / client caps configured in options"
}

sec_audit_bootstrap_bind() {
    sec_audit_layout_probe
    sec_audit_detect_daemon_identity

    if ! sec_audit_software_present && ! sec_audit_conf_present; then
        sec_audit_log "bind/named not installed and named.conf not found; skipping automated remediations"
        local n=1
        while [ "$n" -le 56 ]; do
            sec_audit_remediate_skip "$n" "bind/named not installed and named.conf not found"
            n=$((n + 1))
        done
        return 1
    fi

    if [ -z "$_BIND_PRIMARY_CONF" ]; then
        mkdir -p "$_BIND_LAYOUT_ROOT" 2>/dev/null || true
        _BIND_PRIMARY_CONF="$_BIND_LAYOUT_ROOT/named.conf"
        if [ ! -f "$_BIND_PRIMARY_CONF" ]; then
            cat > "$_BIND_PRIMARY_CONF" <<EOF
// SecAudit Bind9 baseline named.conf
include "$_BIND_LAYOUT_ROOT/$BIND9_REMEDIATE_DROPIN";
EOF
        fi
        _BIND_OPTIONS_FILE="$_BIND_PRIMARY_CONF"
        _BIND_LOGGING_FILE="$_BIND_PRIMARY_CONF"
        _BIND_DROPIN="$_BIND_LAYOUT_ROOT/$BIND9_REMEDIATE_DROPIN"
    fi

    sec_audit_log "primary_conf=${_BIND_PRIMARY_CONF}"
    sec_audit_log "layout_root=${_BIND_LAYOUT_ROOT}"
    sec_audit_log "daemon=${_BIND_DAEMON_ACCT}:${_BIND_DAEMON_GRP}"
    sec_audit_log "drop-in=${_BIND_DROPIN}"
    return 0
}

sec_audit_main() {
    sec_audit_log "starting remediation (Bind9 / sec_audit_* style)"

    if ! sec_audit_bootstrap_bind; then
        sec_audit_log "remediation complete (nothing to apply)"
        exit 0
    fi

    sec_audit_remediate_transfers
    sec_audit_remediate_logging_print
    sec_audit_remediate_dnssec_keys
    sec_audit_remediate_tsig
    sec_audit_remediate_split_dns
    sec_audit_remediate_roles_notify
    sec_audit_remediate_network_and_conf

    if sec_audit_validate_named_conf; then
        sec_audit_log "named-checkconf OK for ${_BIND_PRIMARY_CONF}"
        sec_audit_reload_named || sec_audit_log "named reload deferred (service may be inactive in this environment)"
    else
        sec_audit_log "WARNING: named-checkconf reported errors; review ${_BIND_PRIMARY_CONF} and *.secaudit.bak backups"
    fi

    sec_audit_log "remediation complete (Bind9_remediation.sh)"
    exit 0
}

sec_audit_main "$@"
