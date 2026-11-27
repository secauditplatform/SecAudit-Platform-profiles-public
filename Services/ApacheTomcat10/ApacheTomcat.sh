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

if [ -z "${BASH_VERSION:-}" ]; then
    if command -v bash >/dev/null 2>&1; then
        exec bash "$0" "$@"
    fi
    printf '%s\n' "ERROR: bash is required." >&2
    exit 1
fi

set -o pipefail

export LC_ALL=C

CATALINA_HOME="${CATALINA_HOME:-}"
CATALINA_BASE="${CATALINA_BASE:-}"
_TOMCAT_OWNER_ENV="${TOMCAT_OWNER:-}"
_TOMCAT_GROUP_ENV="${TOMCAT_GROUP:-}"
TOMCAT_OWNER=""
TOMCAT_GROUP=""
TOMCAT_PROC_USER=""

TOMCAT_SERVER_XML=""
TOMCAT_WEBAPPS=""
TOMCAT_CONF=""
TOMCAT_BIN=""
TOMCAT_LOGS=""
TOMCAT_TEMP=""
TOMCAT_INFO_TMP=""

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

secaudit_trim() {
    local v="$1"
    v=${v#"${v%%[![:space:]]*}"}
    v=${v%"${v##*[![:space:]]}"}
    printf '%s' "$v"
}

secaudit_pass_if_empty() {
    local result="$1" pass_msg="$2" fail_msg="$3"
    result=$(secaudit_trim "$result")
    if [ -z "$result" ]; then
        echo "PASS: ${pass_msg}"
    else
        echo "FAIL: ${fail_msg} (${result})"
    fi
}

secaudit_pass_if_present() {
    local result="$1" pass_msg="$2" fail_msg="$3"
    result=$(secaudit_trim "$result")
    if [ -n "$result" ]; then
        echo "PASS: ${pass_msg}"
    else
        echo "FAIL: ${fail_msg}"
    fi
}

secaudit_perm_assessment() {
    local target="$1" extra="${2:-}" pass_msg="$3"
    local v
    v=$(secaudit_perm_violations "$target" "$extra")
    case "$v" in
        MISSING:*)
            echo "FAIL: ${pass_msg} (path missing: ${target})"
            ;;
        UNKNOWN_USER:*)
            echo "FAIL: ${pass_msg} (TOMCAT_OWNER '${TOMCAT_OWNER}' does not exist on host)"
            ;;
        UNKNOWN_GROUP:*)
            echo "FAIL: ${pass_msg} (TOMCAT_GROUP '${TOMCAT_GROUP}' does not exist on host)"
            ;;
        *)
            secaudit_pass_if_empty "$v" "$pass_msg" "Permission or ownership violations in ${target}"
            ;;
    esac
}

secaudit_conf_perm_assessment() {
    local file="$1" extra="${2:-g+rwx,u+x}" expected_mode="${3:-$(secaudit_var MODE_CONF 600)}"
    local path="${TOMCAT_CONF}/${file}" v mode actual
    v=$(secaudit_perm_violations "$path" "$extra")
    case "$v" in
        MISSING:*)
            echo "FAIL: Access to ${file} is restricted (path missing: ${path})"
            return
            ;;
        UNKNOWN_USER:*)
            echo "FAIL: Access to ${file} is restricted (TOMCAT_OWNER '${TOMCAT_OWNER}' does not exist on host)"
            return
            ;;
        UNKNOWN_GROUP:*)
            echo "FAIL: Access to ${file} is restricted (TOMCAT_GROUP '${TOMCAT_GROUP}' does not exist on host)"
            return
            ;;
    esac
    if [ -f "$path" ]; then
        actual=$(stat -c '%a' "$path" 2>/dev/null)
        if [ -n "$actual" ] && [ "$actual" != "$expected_mode" ]; then
            [ -n "$v" ] && v="${v}; "
            v="${v}mode=${actual} expected=${expected_mode}"
        fi
    fi
    secaudit_pass_if_empty "$v" \
        "Access to ${file} is restricted (${TOMCAT_OWNER}:${TOMCAT_GROUP}, mode ${expected_mode})" \
        "Permission or ownership violations in ${path}"
}

secaudit_detect_from_process() {
    local line home base user
    line=$(ps -eo user=,args= 2>/dev/null | awk '
        $0 ~ /org\.apache\.catalina\.startup\.Bootstrap/ && $0 !~ /awk/ { print; exit }
    ')
    [ -n "$line" ] || return 1
    user=${line%% *}
    line=${line#* }
    case "$line" in
        *-Dcatalina.home=*)
            home=${line#*-Dcatalina.home=}
            home=${home%% *}
            home=${home//\"/}
            ;;
    esac
    case "$line" in
        *-Dcatalina.base=*)
            base=${line#*-Dcatalina.base=}
            base=${base%% *}
            base=${base//\"/}
            ;;
    esac
    [ -n "$home" ] && CATALINA_HOME="${CATALINA_HOME:-$home}"
    [ -n "$base" ] && CATALINA_BASE="${CATALINA_BASE:-$base}"
    [ -n "$user" ] && TOMCAT_PROC_USER="$user"
}

secaudit_detect_layout() {
    local d g
    secaudit_detect_from_process
    if [ -z "$CATALINA_HOME" ]; then
        for d in /opt/tomcat /usr/share/tomcat /usr/local/tomcat /var/lib/tomcat; do
            [ -d "$d/conf" ] && CATALINA_HOME="$d" && break
        done
    fi
    CATALINA_HOME="${CATALINA_HOME:-/opt/tomcat}"
    CATALINA_BASE="${CATALINA_BASE:-$CATALINA_HOME}"
    TOMCAT_CONF="${CATALINA_HOME}/conf"
    TOMCAT_BIN="${CATALINA_HOME}/bin"
    TOMCAT_WEBAPPS="${CATALINA_BASE}/webapps"
    TOMCAT_LOGS="${CATALINA_BASE}/logs"
    TOMCAT_TEMP="${CATALINA_BASE}/temp"
    TOMCAT_SERVER_XML="${TOMCAT_CONF}/server.xml"
    d=""
    g=""
    if [ -f "$TOMCAT_SERVER_XML" ]; then
        d=$(stat -c '%U' "$TOMCAT_SERVER_XML" 2>/dev/null)
        g=$(stat -c '%G' "$TOMCAT_SERVER_XML" 2>/dev/null)
    fi
    if [ -n "$_TOMCAT_OWNER_ENV" ]; then
        TOMCAT_OWNER="$_TOMCAT_OWNER_ENV"
    elif [ -n "$TOMCAT_PROC_USER" ]; then
        TOMCAT_OWNER="$TOMCAT_PROC_USER"
    elif [ -n "$d" ] && [ "$d" != "UNKNOWN" ]; then
        TOMCAT_OWNER="$d"
    else
        TOMCAT_OWNER="secaudit_admin"
    fi
    if [ -n "$_TOMCAT_GROUP_ENV" ]; then
        TOMCAT_GROUP="$_TOMCAT_GROUP_ENV"
    elif [ -n "$g" ] && [ "$g" != "UNKNOWN" ]; then
        TOMCAT_GROUP="$g"
    else
        TOMCAT_GROUP="tomcat"
    fi
    if id -u "$TOMCAT_OWNER" >/dev/null 2>&1; then
        g=$(id -gn "$TOMCAT_OWNER" 2>/dev/null)
        if [ -z "$_TOMCAT_GROUP_ENV" ] && [ -n "$g" ]; then
            TOMCAT_GROUP="$g"
        fi
    fi
}

secaudit_xml_strip_comments() {
    awk '
        BEGIN { in_comment=0 }
        in_comment {
            if ($0 ~ /-->/) { sub(/^[^>]*>/, ""); in_comment=0 }
            else { next }
        }
        {
            while (match($0, /<!--/)) {
                if ($0 ~ /-->/) { sub(/<!--.*-->/, "") }
                else { $0 = substr($0, 1, RSTART - 1); in_comment = 1; break }
            }
            if (!in_comment && $0 !~ /^[[:space:]]*$/) print
        }
    '
}

secaudit_server_xml_active() {
    [ -f "$TOMCAT_SERVER_XML" ] || return 1
    secaudit_xml_strip_comments < "$TOMCAT_SERVER_XML"
}

secaudit_server_xml_grep() {
    local pattern="$1"
    secaudit_server_xml_active 2>/dev/null | grep -iE "$pattern"
}

secaudit_server_info_read() {
    local key="$1" catalina_jar prop val tmp
    catalina_jar=""
    for tmp in \
        "${CATALINA_HOME}/lib/catalina.jar" \
        "${CATALINA_HOME}/lib/catalina-"*.jar; do
        for catalina_jar in $tmp; do
            [ -f "$catalina_jar" ] && break 2
        done
    done
    [ -f "$catalina_jar" ] || return 1
    TOMCAT_INFO_TMP="${TOMCAT_INFO_TMP:-$(mktemp -d 2>/dev/null || mktemp -d -t tomcatinfo)}"
    prop="${TOMCAT_INFO_TMP}/org/apache/catalina/util/ServerInfo.properties"
    if [ ! -f "$prop" ]; then
        ( cd "$TOMCAT_INFO_TMP" && command jar xf "$catalina_jar" org/apache/catalina/util/ServerInfo.properties ) 2>/dev/null
    fi
    [ -f "$prop" ] || return 1
    val=$(grep -E "^[[:space:]]*${key}[[:space:]]*=" "$prop" 2>/dev/null | tail -1 | cut -d= -f2-)
    secaudit_trim "$val"
}

secaudit_perm_violations() {
    local target="$1" extra_perm="${2:-}" max="${3:-20}"
    local result=""
    [ -e "$target" ] || { echo "MISSING:$target"; return; }
    if ! id -u "$TOMCAT_OWNER" >/dev/null 2>&1; then
        echo "UNKNOWN_USER:$TOMCAT_OWNER"
        return
    fi
    if ! getent group "$TOMCAT_GROUP" >/dev/null 2>&1; then
        echo "UNKNOWN_GROUP:$TOMCAT_GROUP"
        return
    fi
    if [ -n "$extra_perm" ]; then
        result=$(find -L "$target" -maxdepth 0 \
            \( -perm /o+rwx,"$extra_perm" -o ! -user "$TOMCAT_OWNER" -o ! -group "$TOMCAT_GROUP" \) \
            -ls 2>/dev/null | head -"$max")
    else
        result=$(find -L "$target" -maxdepth 0 \
            \( -perm /o+rwx -o ! -user "$TOMCAT_OWNER" -o ! -group "$TOMCAT_GROUP" \) \
            -ls 2>/dev/null | head -"$max")
    fi
    if [ -n "$result" ]; then
        printf '%s' "$result" | tr '\n' '; '
    fi
}

secaudit_production_webapps() {
    local d
    [ -d "$TOMCAT_WEBAPPS" ] || return 1
    for d in "$TOMCAT_WEBAPPS"/*; do
        [ -d "$d" ] || continue
        case "$(basename "$d")" in
            ROOT|docs|examples|manager|host-manager) continue ;;
        esac
        echo "$d"
    done
}

secaudit_find_context_files() {
    find "$CATALINA_HOME" "$CATALINA_BASE" -name context.xml 2>/dev/null
}

secaudit_bootstrap_pid() {
    ps -eo pid=,args= 2>/dev/null | awk '
        $0 ~ /org\.apache\.catalina\.startup\.Bootstrap/ && $0 !~ /awk/ { print $1; exit }
    '
}

secaudit_jvm_props() {
    local pattern="$1"
    local f pid cmdline
    pid=$(secaudit_bootstrap_pid)
    if [ -n "$pid" ] && [ -r "/proc/${pid}/cmdline" ]; then
        cmdline=$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null)
        printf '%s\n' "$cmdline" | grep -iE "$pattern"
    fi
    for f in "${TOMCAT_BIN}/setenv.sh" "${TOMCAT_BIN}/catalina.sh"; do
        [ -f "$f" ] || continue
        grep -iE "$pattern" "$f" 2>/dev/null
    done
    if secaudit_have_bin systemctl; then
        systemctl cat tomcat tomcat10 2>/dev/null | grep -iE "$pattern"
    fi
    ps -eo args= 2>/dev/null | grep -iE 'org\.apache\.catalina\.startup\.Bootstrap' | grep -iE "$pattern"
}

secaudit_manager_present() {
    [ -d "${TOMCAT_WEBAPPS}/manager" ] || [ -f "${TOMCAT_CONF}/Catalina/localhost/manager.xml" ]
}

secaudit_access_log_sources() {
    find "$TOMCAT_WEBAPPS" -path '*/META-INF/context.xml' 2>/dev/null
    [ -f "$TOMCAT_SERVER_XML" ] && printf '%s\n' "$TOMCAT_SERVER_XML"
    find "${TOMCAT_CONF}/Catalina/localhost" -name '*.xml' 2>/dev/null
}

secaudit_connectors_active() {
    secaudit_server_xml_grep '<Connector'
}

secaudit_connector_attr_true() {
    local attr="$1"
    local line val
    while IFS= read -r line; do
        case "$line" in
            *"${attr}"=*)
                val=${line#*"${attr}"=}
                val=${val#\"}
                val=${val%%\"*}
                val=${val//\'/}
                val=$(printf '%s' "$val" | tr '[:upper:]' '[:lower:]')
                [ "$val" = "true" ] && echo "$line"
                ;;
        esac
    done < <(secaudit_connectors_active)
}

secaudit_extraneous_webapps_assessment() {
    local name found="" d
    [ -d "$TOMCAT_WEBAPPS" ] || { echo "FAIL: webapps directory ${TOMCAT_WEBAPPS} is missing"; return; }
    for name in examples docs ROOT host-manager manager; do
        d="${TOMCAT_WEBAPPS}/${name}"
        [ -e "$d" ] && found="${found}${name} "
    done
    found=$(secaudit_trim "$found")
    if [ -z "$found" ]; then
        echo "PASS: No extraneous sample web applications found under ${TOMCAT_WEBAPPS}"
    else
        echo "FAIL: Extraneous sample resources present (${found})"
    fi
}

secaudit_server_info_assessment() {
    local key="$1" label="$2"
    local val
    val=$(secaudit_server_info_read "$key")
    if [ -z "$val" ]; then
        echo "FAIL: Unable to read ${key} from ServerInfo.properties"
        return
    fi
    case "$key" in
        server.info)
            case "$val" in
                Apache\ Tomcat/*)
                    echo "FAIL: ${label} still uses default value (${val})"
                    ;;
                *)
                    echo "PASS: ${label} is customized (${val})"
                    ;;
            esac
            ;;
        server.number)
            if printf '%s' "$val" | grep -qE '^[0-9]+(\.[0-9]+){2,3}([^.].*)?$'; then
                echo "FAIL: ${label} still exposes Tomcat version (${val})"
            else
                echo "PASS: ${label} is customized (${val})"
            fi
            ;;
        server.built)
            if [ -z "$val" ]; then
                echo "PASS: ${label} is blank or customized"
            elif printf '%s' "$val" | grep -qiE 'jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec|[0-9]{4}'; then
                echo "FAIL: ${label} still exposes build date (${val})"
            else
                echo "PASS: ${label} is customized (${val})"
            fi
            ;;
    esac
}

secaudit_trace_assessment() {
    local bad="" line
    bad=$(secaudit_connector_attr_true 'allowTrace' | tr '\n' ' ')
    if [ -n "$bad" ]; then
        echo "FAIL: allowTrace=true on Connector (${bad})"
        return
    fi
    while IFS= read -r line; do
        [ -f "$line" ] || continue
        if grep -iE 'http-method[[:space:]]*>[[:space:]]*TRACE' "$line" 2>/dev/null | grep -vE '^[[:space:]]*<!--' | grep -q .; then
            bad="${bad}${line} "
        fi
    done < <(find "$TOMCAT_WEBAPPS" -path '*/WEB-INF/web.xml' 2>/dev/null)
    bad=$(secaudit_trim "$bad")
    if [ -n "$bad" ]; then
        echo "FAIL: TRACE not restricted in web.xml (${bad})"
    else
        echo "PASS: TRACE is disabled (allowTrace not true, no TRACE method exposure)"
    fi
}

secaudit_server_header_assessment() {
    local line server bad="" missing=0
    if ! secaudit_connectors_active | grep -q .; then
        echo "FAIL: No active Connector elements found in server.xml"
        return
    fi
    while IFS= read -r line; do
        case "$line" in
            *server=*)
                server=${line#*server=}
                server=${server#\"}
                server=${server%%\"*}
                server=${server//\'/}
                server=$(secaudit_trim "$server")
                case "$server" in
                    ""|*Apache*|*Tomcat*|*Catalina*|*Coyote*)
                        bad="${bad}revealing:${server} "
                        ;;
                esac
                ;;
            *)
                missing=$((missing + 1))
                ;;
        esac
    done < <(secaudit_connectors_active)
    bad=$(secaudit_trim "$bad")
    if [ "$missing" -gt 0 ]; then
        bad="${bad} connectors-without-server-attr:${missing} (default Apache-Coyote/1.1)"
        bad=$(secaudit_trim "$bad")
    fi
    if [ -n "$bad" ]; then
        echo "FAIL: Server header missing or reveals platform (${bad})"
    else
        echo "PASS: Server header is customized and does not reveal Tomcat/Apache"
    fi
}

secaudit_shutdown_command_assessment() {
    local line
    line=$(secaudit_shutdown_audit)
    if [ -n "$line" ]; then
        echo "FAIL: Shutdown command still uses default SHUTDOWN (${line})"
    else
        echo "PASS: Shutdown command is not the default SHUTDOWN value"
    fi
}

secaudit_shutdown_port_assessment() {
    local line
    line=$(secaudit_shutdown_port_disabled)
    if [ -n "$line" ]; then
        echo "PASS: Shutdown port is disabled (port=-1)"
    else
        echo "FAIL: Shutdown port is not disabled (expected port=\"-1\" on <Server>)"
    fi
}

secaudit_shutdown_audit() {
    local line
    line=$(secaudit_server_xml_active 2>/dev/null | grep -iE '^[[:space:]]*<Server\b' | head -1)
    [ -n "$line" ] || return
    case "$line" in
        *shutdown=\"SHUTDOWN\"*|*shutdown='SHUTDOWN'*)
            echo "$line"
            ;;
    esac
}

secaudit_shutdown_port_disabled() {
    local line want
    want=$(secaudit_var SHUTDOWN_PORT -1)
    line=$(secaudit_server_xml_active 2>/dev/null | grep -iE '^[[:space:]]*<Server\b' | head -1)
    case "$line" in
        *"port=\"${want}\""*|*"port='${want}'"*)
            echo "$line"
            ;;
    esac
}

secaudit_realm_assessment() {
    local realm="$1"
    local hits
    hits=$(secaudit_server_xml_grep 'Realm' | grep -iE "className=\"[^\"]*${realm}" | grep -vE '^[[:space:]]*<!--' | tr '\n' ' ')
    secaudit_pass_if_empty "$hits" "Tomcat is not using insecure ${realm}" "Insecure ${realm} is configured"
}

secaudit_lockout_realm_assessment() {
    local hits
    hits=$(secaudit_server_xml_grep 'LockOutRealm' | grep -vE '^[[:space:]]*<!--' | tr '\n' ' ')
    secaudit_pass_if_present "$hits" "LockOutRealm is configured" "LockOutRealm is not configured in server.xml"
}

secaudit_app_logging_assessment() {
    local apps missing="" app
    apps=$(secaudit_production_webapps)
    if [ -z "$apps" ]; then
        echo "PASS: No custom production web applications require per-app logging.properties"
        return
    fi
    while IFS= read -r app; do
        [ -n "$app" ] || continue
        [ -f "${app}/WEB-INF/classes/logging.properties" ] || missing="${missing}$(basename "$app") "
    done <<< "$apps"
    missing=$(secaudit_trim "$missing")
    if [ -z "$missing" ]; then
        echo "PASS: Application-specific logging.properties files are present for production apps"
    else
        echo "FAIL: Missing logging.properties for production apps (${missing})"
    fi
}

secaudit_logging_handlers_assessment() {
    local hits f bad=""
    hits=$(secaudit_app_logging_handlers | tr '\n' ' ')
    if printf '%s' "$hits" | grep -qiE 'FileHandler|AsyncFileHandler'; then
        echo "PASS: File logging handlers are configured (${hits})"
        return
    fi
    for f in \
        "${TOMCAT_CONF}/logging.properties" \
        $(find "$TOMCAT_WEBAPPS" -path '*/WEB-INF/classes/logging.properties' 2>/dev/null); do
        [ -f "$f" ] || continue
        if grep -iE '^[[:space:]]*handlers[[:space:]]*=' "$f" 2>/dev/null | grep -qiE 'FileHandler|AsyncFileHandler'; then
            echo "PASS: File logging handlers are configured in ${f}"
            return
        fi
        bad="${bad}${f}:no-file-handler "
    done
    echo "FAIL: No FileHandler/AsyncFileHandler configured in logging.properties (${bad:-global handlers missing})"
}

secaudit_app_logging_handlers() {
    find "$TOMCAT_WEBAPPS" -path '*/WEB-INF/classes/logging.properties' 2>/dev/null | while IFS= read -r f; do
        grep -iE '^[[:space:]]*handlers[[:space:]]*=' "$f" 2>/dev/null
    done
    if [ -f "${TOMCAT_CONF}/logging.properties" ]; then
        grep -iE '^[[:space:]]*handlers[[:space:]]*=' "${TOMCAT_CONF}/logging.properties" 2>/dev/null
    fi
}

secaudit_access_log_valve_hits() {
    local f
    while IFS= read -r f; do
        [ -f "$f" ] || continue
        grep -iE 'org\.apache\.catalina\.valves\.AccessLogValve' "$f" 2>/dev/null
    done < <(secaudit_access_log_sources)
}

secaudit_access_log_valve_assessment() {
    local apps missing="" app hits
    apps=$(secaudit_production_webapps)
    if [ -z "$apps" ]; then
        hits=$(secaudit_access_log_valve_hits | tr '\n' ' ')
        hits=$(secaudit_trim "$hits")
        if [ -n "$hits" ]; then
            echo "PASS: AccessLogValve is configured (context.xml, server.xml, or localhost descriptors)"
        else
            echo "FAIL: AccessLogValve is not configured in context.xml, server.xml, or conf/Catalina/localhost"
        fi
        return
    fi
    while IFS= read -r app; do
        [ -n "$app" ] || continue
        if ! grep -iE 'org\.apache\.catalina\.valves\.AccessLogValve' "${app}/META-INF/context.xml" 2>/dev/null | grep -q .; then
            missing="${missing}$(basename "$app") "
        fi
    done <<< "$apps"
    missing=$(secaudit_trim "$missing")
    if [ -z "$missing" ]; then
        echo "PASS: AccessLogValve is configured for production applications"
    else
        echo "FAIL: AccessLogValve missing for apps (${missing})"
    fi
}

secaudit_access_log_active_content() {
    local f="$1"
    [ -f "$f" ] || return 1
    if [ "$f" = "$TOMCAT_SERVER_XML" ]; then
        secaudit_server_xml_active
    else
        secaudit_xml_strip_comments < "$f"
    fi
}

secaudit_access_log_pattern_assessment() {
    local f pattern bad="" ok=0 req='%t %U %a %A %m %p %q %s'
    local active missing token
    while IFS= read -r f; do
        [ -f "$f" ] || continue
        active=$(secaudit_access_log_active_content "$f" 2>/dev/null)
        [ -n "$active" ] || continue
        pattern=$(printf '%s\n' "$active" | grep -iE 'pattern[[:space:]]*=' | tail -1)
        [ -n "$pattern" ] || continue
        missing=""
        for token in %t %U %a %A %m %p %q %s; do
            case "$pattern" in
                *"$token"*) ;;
                *) missing="${missing}${token} " ;;
            esac
        done
        missing=$(secaudit_trim "$missing")
        if [ -z "$missing" ]; then
            ok=1
        else
            bad="${bad}${f}:missing(${missing}) "
        fi
    done < <(secaudit_access_log_sources)
    bad=$(secaudit_trim "$bad")
    if [ "$ok" -eq 1 ] && [ -z "$bad" ]; then
        echo "PASS: Access log pattern includes required fields (${req})"
    elif [ -n "$bad" ]; then
        echo "FAIL: Access log pattern missing required fields (${bad})"
    else
        echo "FAIL: Access log pattern not configured with required fields (${req})"
    fi
}

secaudit_package_access_assessment() {
    local line val
    line=$(grep -E '^[[:space:]]*package\.access[[:space:]]*=' "${TOMCAT_CONF}/catalina.properties" 2>/dev/null | tail -1)
    if [ -z "$line" ]; then
        echo "FAIL: package.access is not configured in catalina.properties"
        return
    fi
    val=${line#*=}
    case "$val" in
        *sun.*|*org.apache.catalina.*|*org.apache.coyote.*|*org.apache.jasper.*|*org.apache.tomcat.*)
            echo "PASS: package.access restricts sensitive packages (${line})"
            ;;
        *)
            echo "FAIL: package.access does not restrict required packages (${line})"
            ;;
    esac
}

secaudit_host_deploy_attr_assessment() {
    local attr="$1"
    local line bad="" hosts=0
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        hosts=$((hosts + 1))
        case "$line" in
            *"${attr}"=\"false\"*|*"${attr}"='false'*)
                ;;
            *)
                bad="${bad}${line} "
                ;;
        esac
    done < <(secaudit_server_xml_grep '<Host\b')
    bad=$(secaudit_trim "$bad")
    if [ "$hosts" -eq 0 ]; then
        echo "FAIL: No active Host elements found in server.xml"
    elif [ -z "$bad" ]; then
        echo "PASS: ${attr} is disabled (false) on all Host elements"
    else
        echo "FAIL: ${attr} is enabled or defaults to true on Host (${bad})"
    fi
}

secaudit_admin_access_assessment() {
    local hits=""
    local f
    for f in \
        "${TOMCAT_CONF}/Catalina/localhost/host-manager.xml" \
        "${TOMCAT_WEBAPPS}/host-manager/META-INF/context.xml" \
        "$TOMCAT_SERVER_XML"; do
        [ -f "$f" ] || continue
        if grep -iE 'RemoteAddrValve' "$f" 2>/dev/null | grep -vE '^[[:space:]]*<!--' | grep -q .; then
            hits="${hits}${f} "
        fi
    done
    hits=$(secaudit_trim "$hits")
    secaudit_pass_if_present "$hits" "RemoteAddrValve restricts host-manager access (${hits})" \
        "RemoteAddrValve is not configured for host-manager administration"
}

secaudit_manager_ssl_assessment() {
    local hits
    if ! secaudit_manager_present; then
        echo "PASS: Manager application is not deployed (transport-guarantee check not applicable)"
        return
    fi
    hits=$(secaudit_manager_ssl_guarantee | tr '\n' ' ')
    secaudit_pass_if_present "$hits" "Manager application enforces CONFIDENTIAL transport" \
        "Manager WEB-INF/web.xml lacks transport-guarantee CONFIDENTIAL"
}

secaudit_manager_ssl_guarantee() {
    local f
    for f in \
        "${TOMCAT_WEBAPPS}/manager/WEB-INF/web.xml" \
        "${TOMCAT_CONF}/Catalina/localhost/manager.xml"; do
        [ -f "$f" ] || continue
        grep -iE 'transport-guarantee[[:space:]]*>[[:space:]]*CONFIDENTIAL' "$f" 2>/dev/null
    done
}

secaudit_manager_rename_assessment() {
    local found=""
    local f
    for f in \
        "${TOMCAT_CONF}/Catalina/localhost/manager.xml" \
        "${TOMCAT_WEBAPPS}/manager" \
        "${TOMCAT_WEBAPPS}/host-manager"; do
        [ -e "$f" ] && found="${found}${f} "
    done
    found=$(secaudit_trim "$found")
    if [ -z "$found" ]; then
        echo "PASS: Default manager/host-manager applications are not present at standard paths"
    else
        echo "FAIL: Default manager application paths still exist (${found})"
    fi
}

secaudit_jvm_flag_assessment() {
    local pattern="$1" pass_msg="$2" fail_msg="$3"
    local hits
    hits=$(secaudit_jvm_props "$pattern" | tr '\n' ' ')
    secaudit_pass_if_present "$hits" "$pass_msg (${hits})" "$fail_msg"
}

secaudit_path_delimiter_assessment() {
    local bad=""
    if secaudit_jvm_props 'ALLOW_BACKSLASH=true' | grep -q .; then
        bad="ALLOW_BACKSLASH=true "
    fi
    if secaudit_jvm_props 'ALLOW_ENCODED_SLASH=true' | grep -q .; then
        bad="${bad}ALLOW_ENCODED_SLASH=true"
    fi
    bad=$(secaudit_trim "$bad")
    if [ -z "$bad" ]; then
        echo "PASS: Additional path delimiters are disabled (ALLOW_BACKSLASH/ALLOW_ENCODED_SLASH not true)"
    else
        echo "FAIL: Additional path delimiters may be enabled (${bad})"
    fi
}

secaudit_connection_timeout_assessment() {
    local hits
    hits=$(secaudit_server_xml_grep 'connectionTimeout' | sort -u | tr '\n' ' ')
    hits=$(secaudit_trim "$hits")
    if [ -n "$hits" ]; then
        echo "PASS: connectionTimeout is configured (${hits})"
    elif secaudit_connectors_active | grep -q .; then
        echo "PASS: connectionTimeout uses Tomcat default (60000ms) on Connectors"
    else
        echo "FAIL: No Connector elements found in server.xml"
    fi
}

secaudit_transport_guarantee_assessment() {
    local hits
    hits=$(grep -iE 'transport-guarantee[[:space:]]*>[[:space:]]*CONFIDENTIAL' "${TOMCAT_CONF}/web.xml" 2>/dev/null | tr '\n' ' ')
    secaudit_pass_if_present "$hits" "Global transport-guarantee CONFIDENTIAL is set in conf/web.xml" \
        "conf/web.xml does not enforce transport-guarantee CONFIDENTIAL"
}

secaudit_context_attr_assessment() {
    local attr="$1" pass_msg="$2"
    local f line bad=""
    while IFS= read -r f; do
        [ -f "$f" ] || continue
        case "$f" in
            */manager/*|*/host-manager/*|*/Catalina/localhost/manager.xml|*/Catalina/localhost/host-manager.xml)
                [ "$attr" = "privileged" ] && continue
                ;;
        esac
        if grep -iE "${attr}[[:space:]]*=[[:space:]]*\"true\"" "$f" 2>/dev/null | grep -vE '^[[:space:]]*<!--' | grep -q .; then
            bad="${bad}${f}:${attr}=true "
        fi
    done < <(secaudit_find_context_files)
    bad=$(secaudit_trim "$bad")
    secaudit_pass_if_empty "$bad" "$pass_msg" "${attr}=true found"
}

secaudit_enable_lookups_assessment() {
    local bad=""
    local line val
    while IFS= read -r line; do
        case "$line" in
            *enableLookups=*)
                val=${line#*enableLookups=}
                val=${val#\"}
                val=${val%%\"*}
                val=${val//\'/}
                val=$(printf '%s' "$val" | tr '[:upper:]' '[:lower:]')
                [ "$val" = "true" ] && bad="${bad}${line} "
                ;;
        esac
    done < <(secaudit_connectors_active)
    bad=$(secaudit_trim "$bad")
    secaudit_pass_if_empty "$bad" "enableLookups is false or absent on all Connectors" \
        "enableLookups=true is enabled"
}

secaudit_memory_leak_listener_assessment() {
    local hits
    hits=$(secaudit_server_xml_grep 'JreMemoryLeakPreventionListener' | grep -vE '^[[:space:]]*<!--' | tr '\n' ' ')
    secaudit_pass_if_present "$hits" "JreMemoryLeakPreventionListener is enabled" \
        "JreMemoryLeakPreventionListener is missing from server.xml"
}

secaudit_security_listener_assessment() {
    local hits
    hits=$(secaudit_server_xml_grep 'SecurityLifecycleListener|org\.apache\.catalina\.security\.SecurityListener' | \
        grep -vE '^[[:space:]]*<!--' | tr '\n' ' ')
    secaudit_pass_if_present "$hits" "Security Lifecycle Listener is configured" \
        "Security Lifecycle Listener is not configured in server.xml"
}

secaudit_minimum_umask_assessment() {
    local hits
    hits=$(secaudit_server_xml_grep 'minimumUmask[[:space:]]*=[[:space:]]*"'"$(secaudit_var UMASK 0007)"'"' | grep -vE '^[[:space:]]*<!--' | tr '\n' ' ')
    secaudit_pass_if_present "$hits" "SecurityListener minimumUmask is $(secaudit_var UMASK 0007)" \
        "minimumUmask=\"$(secaudit_var UMASK 0007)\" is not configured on SecurityListener"
}

secaudit_metadata_complete_assessment() {
    local bad=""
    local app f
    while IFS= read -r app; do
        [ -n "$app" ] || continue
        f="${app}/WEB-INF/web.xml"
        [ -f "$f" ] || continue
        if grep -iE 'metadata-complete[[:space:]]*=[[:space:]]*"false"' "$f" 2>/dev/null | grep -vE '^[[:space:]]*<!--' | grep -q .; then
            bad="${bad}$(basename "$app"):metadata-complete=false "
        fi
    done < <(secaudit_production_webapps)
    bad=$(secaudit_trim "$bad")
    if [ -z "$(secaudit_production_webapps)" ]; then
        echo "PASS: No custom production web applications require metadata-complete review"
    elif [ -z "$bad" ]; then
        echo "PASS: metadata-complete is not false for production applications"
    else
        echo "FAIL: metadata-complete=false in production apps (${bad})"
    fi
}

secaudit_log_effective_webxml_assessment() {
    local bad=""
    local app f
    while IFS= read -r app; do
        [ -n "$app" ] || continue
        f="${app}/META-INF/context.xml"
        [ -f "$f" ] || continue
        if grep -iE 'logEffectiveWebXml[[:space:]]*=[[:space:]]*"false"' "$f" 2>/dev/null | grep -vE '^[[:space:]]*<!--' | grep -q .; then
            bad="${bad}$(basename "$app"):logEffectiveWebXml=false "
        fi
    done < <(secaudit_production_webapps)
    bad=$(secaudit_trim "$bad")
    if [ -z "$(secaudit_production_webapps)" ]; then
        echo "PASS: No custom production web applications require logEffectiveWebXml review"
    elif [ -z "$bad" ]; then
        echo "PASS: logEffectiveWebXml is not false for production applications"
    else
        echo "FAIL: logEffectiveWebXml=false in production apps (${bad})"
    fi
}

secaudit_manager_users_assessment() {
    local f="${TOMCAT_CONF}/tomcat-users.xml"
    local bad=""
    [ -f "$f" ] || { echo "FAIL: ${f} is missing"; return; }
    bad=$(secaudit_xml_strip_comments < "$f" | grep -iE '<user\b' | grep -iE 'manager-|must-be-changed|<password>|<password ' | tr '\n' ' ')
    bad=$(secaudit_trim "$bad")
    secaudit_pass_if_empty "$bad" "No default/plaintext manager users found in tomcat-users.xml" \
        "Default or plaintext manager credentials found"
}

secaudit_manager_digest_assessment() {
    local f="${TOMCAT_WEBAPPS}/manager/WEB-INF/web.xml"
    local hits
    if ! secaudit_manager_present; then
        echo "PASS: Manager application is not deployed (DIGEST auth check not applicable)"
        return
    fi
    [ -f "$f" ] || { echo "FAIL: Manager web.xml is missing (${f})"; return; }
    hits=$(grep -iE '<auth-method>[[:space:]]*DIGEST[[:space:]]*</auth-method>' "$f" 2>/dev/null | tr '\n' ' ')
    secaudit_pass_if_present "$hits" "Manager application uses DIGEST authentication" \
        "Manager WEB-INF/web.xml does not configure DIGEST auth-method"
}

secaudit_bootstrap() {
	secaudit_detect_layout


	if [ ! -f "$TOMCAT_SERVER_XML" ] && [ ! -f "${CATALINA_HOME}/bin/catalina.sh" ]; then
		secaudit_skip_all 54 "Apache Tomcat is not installed"
		return 1
	fi
	return 0
}

secaudit_run_remove_extraneous_resources() {
	# RULE1-1
	secaudit_emit 1 "$(secaudit_extraneous_webapps_assessment)"

}

secaudit_run_limit_server_platform_information_leaks() {
	# RULE2-6
	secaudit_emit 2 "$(secaudit_server_info_assessment server.info 'server.info')"
	secaudit_emit 3 "$(secaudit_server_info_assessment server.number 'server.number')"
	secaudit_emit 4 "$(secaudit_server_info_assessment server.built 'server.built')"
	secaudit_emit 5 "$(secaudit_trace_assessment)"
	secaudit_emit 6 "$(secaudit_server_header_assessment)"

}

secaudit_run_protect_shutdown_port() {
	# RULE7-8
	secaudit_emit 7 "$(secaudit_shutdown_command_assessment)"
	secaudit_emit 8 "$(secaudit_shutdown_port_assessment)"

}

secaudit_run_protect_tomcat_configurations() {
	# RULE9-23
	secaudit_emit 9 "$(secaudit_perm_assessment "$CATALINA_HOME" 'g=w' "Access to CATALINA_HOME is restricted")"
	secaudit_emit 10 "$(secaudit_perm_assessment "$CATALINA_BASE" 'g=w' "Access to CATALINA_BASE is restricted")"
	secaudit_emit 11 "$(secaudit_perm_assessment "$TOMCAT_CONF" 'g=w' "Access to Tomcat conf directory is restricted")"
	secaudit_emit 12 "$(secaudit_perm_assessment "$TOMCAT_LOGS" '' "Access to Tomcat logs directory is restricted")"
	secaudit_emit 13 "$(secaudit_perm_assessment "$TOMCAT_TEMP" '' "Access to Tomcat temp directory is restricted")"
	secaudit_emit 14 "$(secaudit_perm_assessment "$TOMCAT_BIN" 'g=w' "Access to Tomcat bin directory is restricted")"
	secaudit_emit 15 "$(secaudit_perm_assessment "$TOMCAT_WEBAPPS" 'g=w' "Access to Tomcat webapps directory is restricted")"
	secaudit_emit 16 "$(secaudit_conf_perm_assessment catalina.properties)"
	secaudit_emit 17 "$(secaudit_conf_perm_assessment catalina.policy)"
	secaudit_emit 18 "$(secaudit_conf_perm_assessment context.xml)"
	secaudit_emit 19 "$(secaudit_conf_perm_assessment logging.properties)"
	secaudit_emit 20 "$(secaudit_conf_perm_assessment server.xml)"
	secaudit_emit 21 "$(secaudit_conf_perm_assessment tomcat-users.xml)"
	secaudit_emit 22 "$(secaudit_conf_perm_assessment web.xml 'g+rwx,u+wx' "$(secaudit_var MODE_WEBXML 400)")"
	secaudit_emit 23 "$(secaudit_conf_perm_assessment jaspic-providers.xml)"

}

secaudit_run_configure_realms() {
	# RULE24-28
	secaudit_emit 24 "$(secaudit_realm_assessment MemoryRealm)"
	secaudit_emit 25 "$(secaudit_realm_assessment JDBCRealm)"
	secaudit_emit 26 "$(secaudit_realm_assessment UserDatabaseRealm)"
	secaudit_emit 27 "$(secaudit_realm_assessment JAASRealm)"
	secaudit_emit 28 "$(secaudit_lockout_realm_assessment)"

}

secaudit_run_establish_protect_logging_facilities() {
	# RULE29-32
	secaudit_emit 29 "$(secaudit_app_logging_assessment)"
	secaudit_emit 30 "$(secaudit_logging_handlers_assessment)"
	secaudit_emit 31 "$(secaudit_access_log_valve_assessment)"
	secaudit_emit 32 "$(secaudit_access_log_pattern_assessment)"

}

secaudit_run_configure_catalina_policy() {
	# RULE33-33
	secaudit_emit 33 "$(secaudit_package_access_assessment)"

}

secaudit_run_application_deployment() {
	# RULE34-35
	secaudit_emit 34 "$(secaudit_host_deploy_attr_assessment autoDeploy)"
	secaudit_emit 35 "$(secaudit_host_deploy_attr_assessment deployOnStartup)"

}

secaudit_run_miscellaneous_configuration_settings() {
	# RULE36-54
	secaudit_emit 36 "$(secaudit_admin_access_assessment)"
	secaudit_emit 37 "$(secaudit_manager_ssl_assessment)"
	secaudit_emit 38 "$(secaudit_manager_rename_assessment)"
	secaudit_emit 39 "$(secaudit_jvm_flag_assessment 'STRICT_SERVLET_COMPLIANCE=true' \
	    'STRICT_SERVLET_COMPLIANCE is enabled' 'STRICT_SERVLET_COMPLIANCE=true is not set')"
	secaudit_emit 40 "$(secaudit_jvm_flag_assessment 'RECYCLE_FACADES=true' \
	    'RECYCLE_FACADES is enabled' 'RECYCLE_FACADES=true is not set')"
	secaudit_emit 41 "$(secaudit_path_delimiter_assessment)"
	secaudit_emit 42 "$(secaudit_connection_timeout_assessment)"
	secaudit_emit 43 "$(secaudit_transport_guarantee_assessment)"
	secaudit_emit 44 "$(secaudit_context_attr_assessment allowLinking 'allowLinking is not enabled')"
	secaudit_emit 45 "$(secaudit_context_attr_assessment privileged 'privileged is not enabled for applications')"
	secaudit_emit 46 "$(secaudit_context_attr_assessment crossContext 'crossContext is not enabled')"
	secaudit_emit 47 "$(secaudit_enable_lookups_assessment)"
	secaudit_emit 48 "$(secaudit_memory_leak_listener_assessment)"
	secaudit_emit 49 "$(secaudit_security_listener_assessment)"
	secaudit_emit 50 "$(secaudit_minimum_umask_assessment)"
	secaudit_emit 51 "$(secaudit_metadata_complete_assessment)"
	secaudit_emit 52 "$(secaudit_log_effective_webxml_assessment)"
	secaudit_emit 53 "$(secaudit_manager_users_assessment)"
	secaudit_emit 54 "$(secaudit_manager_digest_assessment)"
}

secaudit_main() {
	secaudit_bootstrap || return 0
	secaudit_run_remove_extraneous_resources
	secaudit_run_limit_server_platform_information_leaks
	secaudit_run_protect_shutdown_port
	secaudit_run_protect_tomcat_configurations
	secaudit_run_configure_realms
	secaudit_run_establish_protect_logging_facilities
	secaudit_run_configure_catalina_policy
	secaudit_run_application_deployment
	secaudit_run_miscellaneous_configuration_settings
	if [ -n "$TOMCAT_INFO_TMP" ] && [ -d "$TOMCAT_INFO_TMP" ]; then
		rm -rf "$TOMCAT_INFO_TMP"
	fi
	exit 0
}

secaudit_main "$@"
