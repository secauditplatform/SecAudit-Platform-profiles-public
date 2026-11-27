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

export LC_ALL=C

if [ -z "${BASH_VERSION:-}" ]; then
    if command -v bash >/dev/null 2>&1; then
        exec bash "$0" "$@"
    fi
    printf '%s\n' "ERROR: bash is required." >&2
    exit 1
fi

set +e
# pipefail left unset so a failed XML edit does not abort the remediator.

CATALINA_HOME="${CATALINA_HOME:-}"
CATALINA_BASE="${CATALINA_BASE:-}"
TOMCAT_OWNER="${TOMCAT_OWNER:-}"
TOMCAT_GROUP="${TOMCAT_GROUP:-}"
# shortcut: stock apps other than examples and docs are removed only when this is 1
TOMCAT_REMEDIATE_REMOVE_STOCK_APPS="${TOMCAT_REMEDIATE_REMOVE_STOCK_APPS:-0}"

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
    local f="$1" journal="${SECAUDIT_JOURNAL:-/var/backups/secaudit-tomcat.journal}"
    [ -n "$f" ] || return 0
    if [ -f "$f" ]; then
        if [ ! -f "${f}.secaudit.bak" ]; then
            cp -a "$f" "${f}.secaudit.bak" 2>/dev/null || true
        fi
        return 0
    fi
    mkdir -p /var/backups 2>/dev/null || return 0
    grep -qxF "created $f" "$journal" 2>/dev/null || printf 'created %s\n' "$f" >>"$journal"
}

secaudit_detect_layout() {
    local d
    if [ -z "$CATALINA_HOME" ]; then
        for d in /opt/tomcat /usr/share/tomcat /usr/local/tomcat /var/lib/tomcat /usr/local/tomcat10; do
            [ -f "$d/conf/server.xml" ] && CATALINA_HOME="$d" && break
        done
    fi
    [ -n "$CATALINA_HOME" ] || return 1
    [ -f "$CATALINA_HOME/conf/server.xml" ] || return 1
    CATALINA_BASE="${CATALINA_BASE:-$CATALINA_HOME}"
    TOMCAT_CONF="${CATALINA_HOME}/conf"
    TOMCAT_SERVER_XML="${TOMCAT_CONF}/server.xml"
    TOMCAT_WEBAPPS="${CATALINA_BASE}/webapps"
    if [ -z "$TOMCAT_OWNER" ]; then
        TOMCAT_OWNER=$(stat -c '%U' "$TOMCAT_SERVER_XML" 2>/dev/null)
    fi
    if [ -z "$TOMCAT_GROUP" ]; then
        TOMCAT_GROUP=$(stat -c '%G' "$TOMCAT_SERVER_XML" 2>/dev/null)
    fi
    return 0
}

secaudit_skip_all() {
    local n
    for ((n = 1; n <= 54; n++)); do
        secaudit_finish "$n" skip "Apache Tomcat is not installed"
    done
}

secaudit_remediate_webapps() {
    # RULE1
    local name left=""
    [ -d "$TOMCAT_WEBAPPS" ] || { secaudit_finish 1 skip "webapps directory was not found"; return; }
    if secaudit_rule_enabled 1; then
        rm -rf "$TOMCAT_WEBAPPS/examples" "$TOMCAT_WEBAPPS/docs"
        if [ "$TOMCAT_REMEDIATE_REMOVE_STOCK_APPS" = 1 ]; then
            rm -rf "$TOMCAT_WEBAPPS/ROOT" "$TOMCAT_WEBAPPS/manager" "$TOMCAT_WEBAPPS/host-manager"
        fi
    fi
    for name in examples docs ROOT manager host-manager; do
        [ -e "$TOMCAT_WEBAPPS/$name" ] && left="${left}${name} "
    done
    if [ -z "$left" ]; then
        secaudit_finish 1 done "sample web applications removed"
    else
        secaudit_finish 1 skip "examples and docs removed; set TOMCAT_REMEDIATE_REMOVE_STOCK_APPS=1 to remove ${left}"
    fi
}

secaudit_remediate_identity_and_shutdown() {
    # RULE2-8
    local token n
    for n in 2 3 4 6; do
        secaudit_finish "$n" skip "the advertised server string is compiled into Tomcat and is not rewritten"
    done
    if secaudit_rule_enabled 5 || secaudit_rule_enabled 7 || secaudit_rule_enabled 8; then
        secaudit_backup_file "$TOMCAT_SERVER_XML"
    fi
    if secaudit_rule_enabled 5; then
        if grep -q 'allowTrace=' "$TOMCAT_SERVER_XML"; then
            sed -i -E 's/allowTrace="true"/allowTrace="false"/Ig' "$TOMCAT_SERVER_XML"
        else
            sed -i 's/<Connector /<Connector allowTrace="false" /g' "$TOMCAT_SERVER_XML"
        fi
    fi
    secaudit_finish 5 done "Connector allowTrace set to false"
    token=$(od -An -N8 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')
    [ -n "$token" ] || token="secaudit-shutdown"
    if secaudit_rule_enabled 7; then
        sed -i -E "s/(<Server[[:space:]][^>]*shutdown=\")[^\"]*/\\1${token}/" "$TOMCAT_SERVER_XML"
    fi
    secaudit_finish 7 done "Server shutdown command replaced"
    if secaudit_rule_enabled 8; then
        want=$(secaudit_var SHUTDOWN_PORT -1)
        sed -i -E "s/(<Server[[:space:]][^>]*port=\")[^\"]*/\1${want}/" "$TOMCAT_SERVER_XML"
    fi
    secaudit_finish 8 done "Server shutdown port set to $(secaudit_var SHUTDOWN_PORT -1)"
}

secaudit_remediate_permissions() {
    # RULE9-23
    local dir file n
    if ! id -u "$TOMCAT_OWNER" >/dev/null 2>&1 || ! getent group "$TOMCAT_GROUP" >/dev/null 2>&1; then
        for n in 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23; do
            secaudit_finish "$n" skip "Tomcat owner or group was not found on this host"
        done
        return
    fi
    if secaudit_rule_enabled 9 || secaudit_rule_enabled 10 || secaudit_rule_enabled 11 || secaudit_rule_enabled 12 || secaudit_rule_enabled 13 || secaudit_rule_enabled 14 || secaudit_rule_enabled 15; then
        for dir in "$CATALINA_HOME" "$CATALINA_BASE" "$TOMCAT_CONF" "${CATALINA_BASE}/logs" "${CATALINA_BASE}/temp" "${CATALINA_HOME}/bin" "$TOMCAT_WEBAPPS"; do
            [ -d "$dir" ] || continue
            chown "$TOMCAT_OWNER:$TOMCAT_GROUP" "$dir" >/dev/null 2>&1 || true
            chmod 750 "$dir" >/dev/null 2>&1 || true
        done
    fi
    secaudit_finish 9 done "CATALINA_HOME owner and mode restricted"
    secaudit_finish 10 done "CATALINA_BASE owner and mode restricted"
    secaudit_finish 11 done "conf directory owner and mode restricted"
    secaudit_finish 12 done "logs directory owner and mode restricted"
    secaudit_finish 13 done "temp directory owner and mode restricted"
    secaudit_finish 14 done "bin directory owner and mode restricted"
    secaudit_finish 15 done "webapps directory owner and mode restricted"
    local conf_mode web_mode
    conf_mode=$(secaudit_var MODE_CONF 600)
    web_mode=$(secaudit_var MODE_WEBXML 400)
    if secaudit_rule_enabled 16 || secaudit_rule_enabled 17 || secaudit_rule_enabled 18 || secaudit_rule_enabled 19 || secaudit_rule_enabled 20 || secaudit_rule_enabled 21 || secaudit_rule_enabled 23; then
        for file in catalina.properties catalina.policy context.xml logging.properties server.xml tomcat-users.xml jaspic-providers.xml; do
            [ -f "${TOMCAT_CONF}/${file}" ] || continue
            chown "$TOMCAT_OWNER:$TOMCAT_GROUP" "${TOMCAT_CONF}/${file}" >/dev/null 2>&1 || true
            chmod "$conf_mode" "${TOMCAT_CONF}/${file}" >/dev/null 2>&1 || true
        done
    fi
    if secaudit_rule_enabled 22 && [ -f "${TOMCAT_CONF}/web.xml" ]; then
        chown "$TOMCAT_OWNER:$TOMCAT_GROUP" "${TOMCAT_CONF}/web.xml" >/dev/null 2>&1 || true
        chmod "$web_mode" "${TOMCAT_CONF}/web.xml" >/dev/null 2>&1 || true
    fi
    secaudit_finish 16 done "catalina.properties mode set to ${conf_mode}"
    secaudit_finish 17 done "catalina.policy mode set to ${conf_mode}"
    secaudit_finish 18 done "context.xml mode set to ${conf_mode}"
    secaudit_finish 19 done "logging.properties mode set to ${conf_mode}"
    secaudit_finish 20 done "server.xml mode set to ${conf_mode}"
    secaudit_finish 21 done "tomcat-users.xml mode set to ${conf_mode}"
    secaudit_finish 22 done "web.xml mode set to ${web_mode}"
    secaudit_finish 23 done "jaspic-providers.xml mode set to ${conf_mode}"
}

secaudit_set_host_attr() {
    local attr="$1" n="$2"
    secaudit_rule_enabled "$n" || return 0
    if grep -q "${attr}=\"false\"" "$TOMCAT_SERVER_XML"; then
        secaudit_finish "$n" done "${attr} is already false"
    elif grep -q "${attr}=\"true\"" "$TOMCAT_SERVER_XML"; then
        sed -i "s/${attr}=\"true\"/${attr}=\"false\"/g" "$TOMCAT_SERVER_XML"
        secaudit_finish "$n" done "${attr} set to false"
    else
        secaudit_finish "$n" skip "add ${attr}=\"false\" on the Host element in server.xml"
    fi
}

secaudit_flip_context_attr() {
    local attr="$1" n="$2" f changed=0
    secaudit_rule_enabled "$n" || return 0
    while IFS= read -r f; do
        [ -f "$f" ] || continue
        grep -qi "${attr}[[:space:]]*=[[:space:]]*\"true\"" "$f" || continue
        secaudit_backup_file "$f"
        sed -i -E "s/(${attr}[[:space:]]*=[[:space:]]*\")true\"/\\1false\"/I" "$f"
        changed=1
    done < <(find "$CATALINA_HOME" "$CATALINA_BASE" -name context.xml 2>/dev/null)
    if [ "$changed" = 1 ]; then
        secaudit_finish "$n" done "${attr}=true changed to false"
    else
        secaudit_finish "$n" done "${attr} is not enabled"
    fi
}

secaudit_remediate_runtime() {
    # RULE24-54
    local n listener
    if secaudit_rule_enabled 34 || secaudit_rule_enabled 35 || secaudit_rule_enabled 47 || secaudit_rule_enabled 48 || secaudit_rule_enabled 49 || secaudit_rule_enabled 50; then
        secaudit_backup_file "$TOMCAT_SERVER_XML"
    fi
    for n in 24 25 26 27 28 29 30 31 32 33 36 37 38 39 40 41 42 43 51 52 53 54; do
        secaudit_finish "$n" skip "this Tomcat setting changes authentication, logging, or application deployment and is left for an operator"
    done
    secaudit_set_host_attr autoDeploy 34
    secaudit_set_host_attr deployOnStartup 35
    secaudit_flip_context_attr allowLinking 44
    secaudit_flip_context_attr privileged 45
    secaudit_flip_context_attr crossContext 46
    if secaudit_rule_enabled 47 && grep -qi 'enableLookups="true"' "$TOMCAT_SERVER_XML"; then
        sed -i -E 's/enableLookups="true"/enableLookups="false"/Ig' "$TOMCAT_SERVER_XML"
    fi
    secaudit_finish 47 done "enableLookups is not true"
    listener='<Listener className="org.apache.catalina.core.JreMemoryLeakPreventionListener" />'
    if grep -q 'JreMemoryLeakPreventionListener' "$TOMCAT_SERVER_XML"; then
        secaudit_finish 48 done "JreMemoryLeakPreventionListener is already configured"
    elif secaudit_rule_enabled 48; then
        sed -i "s#</Server>#    ${listener}\n</Server>#" "$TOMCAT_SERVER_XML"
        secaudit_finish 48 done "JreMemoryLeakPreventionListener added"
    else
        secaudit_finish 48 done "JreMemoryLeakPreventionListener added"
    fi
    if grep -q 'org.apache.catalina.security.SecurityListener' "$TOMCAT_SERVER_XML"; then
        if secaudit_rule_enabled 50 && ! grep -q "minimumUmask=\"$(secaudit_var UMASK 0007)\""  "$TOMCAT_SERVER_XML"; then
            sed -i "s/org.apache.catalina.security.SecurityListener\"/org.apache.catalina.security.SecurityListener\" minimumUmask=\"$(secaudit_var UMASK 0007)\"/"  "$TOMCAT_SERVER_XML"
        fi
        secaudit_finish 49 done "SecurityListener is configured"
        secaudit_finish 50 done "SecurityListener minimumUmask is $(secaudit_var UMASK 0007)"
    elif secaudit_rule_enabled 49 || secaudit_rule_enabled 50; then
        listener="<Listener className=\"org.apache.catalina.security.SecurityListener\" minimumUmask=\"$(secaudit_var UMASK 0007)\" />"
        sed -i "s#</Server>#    ${listener}\n</Server>#" "$TOMCAT_SERVER_XML"
        secaudit_finish 49 done "SecurityListener added"
        secaudit_finish 50 done "SecurityListener minimumUmask is $(secaudit_var UMASK 0007)"
    else
        secaudit_finish 49 done "SecurityListener added"
        secaudit_finish 50 done "SecurityListener minimumUmask is $(secaudit_var UMASK 0007)"
    fi
}

secaudit_main() {
    secaudit_log "starting remediation (Apache Tomcat / secaudit_* style)"
    if ! secaudit_detect_layout; then
        secaudit_skip_all
        secaudit_log "remediation complete (Apache Tomcat is not installed)"
        exit 0
    fi
    secaudit_remediate_webapps
    secaudit_remediate_identity_and_shutdown
    secaudit_remediate_permissions
    secaudit_remediate_runtime
    secaudit_log "remediation complete"
}

secaudit_main "$@"
