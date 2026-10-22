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
_DOCKER_DAEMON_JSON="${DOCKER_DAEMON_JSON:-${SECAUDIT_DOCKER_DAEMON_JSON:-/etc/docker/daemon.json}}"
_DOCKER_CERTS_DIR="${DOCKER_CERTS_DIR:-${SECAUDIT_DOCKER_CERTS_DIR:-/etc/docker/certs.d}}"
_DOCKER_SOCK="${DOCKER_SOCK:-${SECAUDIT_DOCKER_SOCK:-/var/run/docker.sock}}"
[ -S "$_DOCKER_SOCK" ] || _DOCKER_SOCK="/run/docker.sock"
_DOCKER_CONTAINERD_SOCK="${CONTAINERD_SOCK:-${SECAUDIT_CONTAINERD_SOCK:-/run/containerd/containerd.sock}}"
_DOCKER_FIND_CAP="${DOCKER_FIND_CAP:-20}"
_DOCKER_CMD_CAP="${DOCKER_CMD_CAP:-12}"
_DOCKER_RULE_COUNT=98

# --- runtime state ---
_DOCKER_INFO_JSON=""
_DOCKER_DAEMON_BLOB=""
_DOCKER_CMDLINE=""
_DOCKER_PID=""
_DOCKER_UNIT_BLOB=""
_DOCKER_HELP_TEXT=""
_DOCKER_INFO_OK=0
_DOCKER_SVC_FILE=""
_DOCKER_SOCK_UNIT=""

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

secaudit_squash_ws() {
    printf '%s' "${1-}" | tr '\n\r' '  ' | sed -E 's/[[:space:]]+/ /g;s/^ //;s/ $//'
}

secaudit_path_mode_octal() {
    local p="$1"
    if [ -e "$p" ]; then
        stat -c '%a' "$p" 2>/dev/null
    else
        printf '%s' "MISSING"
    fi
}

secaudit_path_owner_user() {
    local p="$1"
    [ -e "$p" ] && stat -c '%U' "$p" 2>/dev/null
}

secaudit_path_owner_group() {
    local p="$1"
    [ -e "$p" ] && stat -c '%G' "$p" 2>/dev/null
}

secaudit_path_listing() {
    local p="$1"
    if [ -e "$p" ]; then
        ls -ld "$p" 2>/dev/null | awk '{print $1,$3,$4,$9}' | tr '\n' ' '
    else
        printf '%s' "MISSING"
    fi
}

secaudit_perm_within() {
    local actual="$1" ceiling="$2"
    local a1 a2 a3 c1 c2 c3
    printf '%s' "$actual" | grep -qE '^[0-9]{3,4}$' || return 1
    printf '%s' "$ceiling" | grep -qE '^[0-9]{3,4}$' || return 1
    actual=$(printf '%s' "$actual" | tail -c 3)
    ceiling=$(printf '%s' "$ceiling" | tail -c 3)
    a1=${actual:0:1}; a2=${actual:1:1}; a3=${actual:2:1}
    c1=${ceiling:0:1}; c2=${ceiling:1:1}; c3=${ceiling:2:1}
    [ "$a1" -le "$c1" ] && [ "$a2" -le "$c2" ] && [ "$a3" -le "$c3" ]
}

# --- discovery ---

secaudit_dockerd_pid() {
    local dir comm
    for dir in /proc/[0-9]*; do
        [ -r "$dir/comm" ] || continue
        comm=$(tr -d '\n' < "$dir/comm" 2>/dev/null)
        if [ "$comm" = "dockerd" ]; then
            printf '%s' "${dir##*/}"
            return 0
        fi
    done
    if secaudit_have_bin pgrep; then
        pgrep -x dockerd 2>/dev/null | head -1
        return 0
    fi
    return 1
}

secaudit_collect_cmdline() {
    local pid="$1"
    if [ -n "$pid" ] && [ -r "/proc/${pid}/cmdline" ]; then
        tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null
        return 0
    fi
    return 1
}

secaudit_collect_info_json() {
    if secaudit_have_bin docker; then
        secaudit_exec_with_timeout "$_DOCKER_CMD_CAP" docker info --format '{{json .}}' 2>/dev/null
    fi
}

secaudit_collect_daemon_json() {
    if [ -f "$_DOCKER_DAEMON_JSON" ]; then
        cat "$_DOCKER_DAEMON_JSON" 2>/dev/null
    fi
}

secaudit_collect_unit_bundle() {
    local unit f dir
    if secaudit_have_bin systemctl; then
        secaudit_exec_with_timeout 8 systemctl cat docker.service 2>/dev/null
        secaudit_exec_with_timeout 8 systemctl cat docker.socket 2>/dev/null
    fi
    for dir in \
        /etc/systemd/system/docker.service.d \
        /usr/lib/systemd/system/docker.service.d \
        /lib/systemd/system/docker.service.d \
        /etc/systemd/system/docker.socket.d
    do
        [ -d "$dir" ] || continue
        for f in "$dir"/*.conf; do
            [ -f "$f" ] || continue
            printf '\n# drop-in %s\n' "$f"
            cat "$f" 2>/dev/null
        done
    done
    for f in /etc/default/docker /etc/sysconfig/docker; do
        [ -f "$f" ] || continue
        printf '\n# envfile %s\n' "$f"
        cat "$f" 2>/dev/null
    done
}

secaudit_collect_help_text() {
    if secaudit_have_bin dockerd; then
        secaudit_exec_with_timeout 8 dockerd --help 2>&1
    elif [ -x /usr/bin/dockerd ]; then
        secaudit_exec_with_timeout 8 /usr/bin/dockerd --help 2>&1
    fi
}

# --- query helpers ---

secaudit_json_py() {
    local py="$1"
    shift
    "$py" -c '
import json, sys
try:
    cur = json.load(sys.stdin)
except Exception:
    sys.exit(1)
for key in sys.argv[1:]:
    if isinstance(cur, dict) and key in cur:
        cur = cur[key]
    else:
        sys.exit(1)
if cur is None:
    sys.exit(1)
if isinstance(cur, bool):
    print("true" if cur else "false")
elif isinstance(cur, (dict, list)):
    json.dump(cur, sys.stdout)
    print()
else:
    print(cur)
' "$@" 2>/dev/null
}

secaudit_json_scalar_fallback() {
    local blob="$1" key="$2" raw
    raw=$(printf '%s' "$blob" | tr '\n' ' ' | grep -oE "\"${key}\"[[:space:]]*:[[:space:]]*(\"[^\"]*\"|true|false|null|-?[0-9]+(\.[0-9]+)?)" | head -1)
    [ -n "$raw" ] || return 1
    raw=${raw#*:}
    raw=$(printf '%s' "$raw" | sed -E 's/^[[:space:]]+//;s/[[:space:]]+$//')
    case "$raw" in
        \"*\") printf '%s' "${raw:1:${#raw}-2}" ;;
        null) return 1 ;;
        *) printf '%s' "$raw" ;;
    esac
}

secaudit_json_get() {
    local blob="$1"
    shift
    local out jq_path k
    [ -n "$blob" ] || return 1
    [ "$#" -ge 1 ] || return 1

    if secaudit_have_bin python3; then
        out=$(printf '%s' "$blob" | secaudit_json_py python3 "$@") && [ -n "$out" ] && { printf '%s' "$out"; return 0; }
    elif secaudit_have_bin python; then
        out=$(printf '%s' "$blob" | secaudit_json_py python "$@") && [ -n "$out" ] && { printf '%s' "$out"; return 0; }
    fi

    if secaudit_have_bin jq; then
        jq_path='.'
        for k in "$@"; do
            jq_path="${jq_path}[\"${k}\"]"
        done
        out=$(printf '%s' "$blob" | jq -rc "${jq_path} | if . == null then empty elif type == \"boolean\" then (if . then \"true\" else \"false\" end) elif type == \"string\" or type == \"number\" then tostring else . end" 2>/dev/null)
        [ -n "$out" ] && { printf '%s' "$out"; return 0; }
    fi

    if [ "$#" -eq 1 ]; then
        secaudit_json_scalar_fallback "$blob" "$1"
        return $?
    fi
    return 1
}

# Read docker info fields; falls back to `docker info --format` when JSON parsers are absent.
secaudit_info_get() {
    local out fmt k
    [ "$#" -ge 1 ] || return 1
    out=$(secaudit_json_get "$_DOCKER_INFO_JSON" "$@" 2>/dev/null || true)
    if [ -n "$out" ]; then
        printf '%s' "$out"
        return 0
    fi
    secaudit_info_ok || return 1
    secaudit_have_bin docker || return 1

    fmt=''
    for k in "$@"; do
        fmt="${fmt}.${k}"
    done
    case "$*" in
        SecurityOptions|DriverStatus|DefaultUlimits|InsecureRegistryCIDRs|Plugins)
            out=$(secaudit_exec_with_timeout 5 docker info --format "{{json ${fmt}}}" 2>/dev/null || true)
            ;;
        RegistryConfig|Swarm|*)
            # Nested paths and scalars via Go template (short timeout).
            out=$(secaudit_exec_with_timeout 5 docker info --format "{{${fmt}}}" 2>/dev/null || true)
            if [ -z "$out" ] || [ "$out" = "<no value>" ] || [ "$out" = "map[]" ]; then
                out=$(secaudit_exec_with_timeout 5 docker info --format "{{json ${fmt}}}" 2>/dev/null || true)
            fi
            ;;
    esac
    [ -n "$out" ] && [ "$out" != "<no value>" ] && [ "$out" != "null" ] && { printf '%s' "$out"; return 0; }
    return 1
}

secaudit_daemon_val() {
    local key="$1" val
    val=$(secaudit_json_get "$_DOCKER_DAEMON_BLOB" "$key" 2>/dev/null || true)
    if [ -n "$val" ]; then
        printf '%s' "$val"
        return 0
    fi
    if [ -f "$_DOCKER_DAEMON_JSON" ]; then
        grep -E "\"${key}\"[[:space:]]*:" "$_DOCKER_DAEMON_JSON" 2>/dev/null | \
            grep -vE '^[[:space:]]*//' | head -1 | \
            sed -E "s/.*\"${key}\"[[:space:]]*:[[:space:]]*//;s/[,\"]//g;s/[[:space:]]+$//" | \
            tr -d '[:space:]'
        return 0
    fi
    return 1
}

secaudit_cmdline_has() {
    local flag="$1"
    printf '%s' "$_DOCKER_CMDLINE" | grep -qE -- "(^|[[:space:]])${flag}(=|[[:space:]]|$)"
}

secaudit_cmdline_val() {
    local flag="$1"
    local raw
    raw=$(printf '%s' "$_DOCKER_CMDLINE" | grep -oE -- "${flag}=[^[:space:]]+" | head -1)
    if [ -n "$raw" ]; then
        printf '%s' "${raw#*=}"
        return 0
    fi
    raw=$(printf '%s' "$_DOCKER_CMDLINE" | sed -n "s/.*${flag}[[:space:]]\+\([^[:space:]]\+\).*/\1/p" | head -1)
    [ -n "$raw" ] && printf '%s' "$raw"
}

secaudit_merged_val() {
    local key="$1" info_key="${2:-}"
    local v
    v=$(secaudit_cmdline_val "--${key}")
    if [ -n "$v" ]; then
        printf '%s' "$v"
        return 0
    fi
    v=$(secaudit_daemon_val "$key")
    if [ -n "$v" ]; then
        printf '%s' "$v"
        return 0
    fi
    if printf '%s' "$_DOCKER_UNIT_BLOB" | grep -qE -- "--${key}="; then
        printf '%s' "$_DOCKER_UNIT_BLOB" | grep -oE -- "--${key}=[^[:space:]]+" | head -1 | sed "s/^--${key}=//"
        return 0
    fi
    if [ -n "$info_key" ] && [ -n "$_DOCKER_INFO_JSON" ]; then
        secaudit_info_get $info_key 2>/dev/null && return 0
    fi
    return 1
}

secaudit_merged_true() {
    local key="$1"
    local v
    if secaudit_cmdline_has "--${key}=true" || secaudit_cmdline_has "--${key} true"; then
        return 0
    fi
    if secaudit_cmdline_has "--${key}=false" || secaudit_cmdline_has "--${key} false"; then
        return 1
    fi
    v=$(secaudit_daemon_val "$key")
    case "$v" in
        true|True|TRUE) return 0 ;;
        false|False|FALSE) return 1 ;;
    esac
    printf '%s' "$_DOCKER_UNIT_BLOB" | grep -qE -- "--${key}=true" && return 0
    printf '%s' "$_DOCKER_UNIT_BLOB" | grep -qE -- "--${key}=false" && return 1
    return 2
}

secaudit_info_ok() {
    [ "$_DOCKER_INFO_OK" -eq 1 ]
}

secaudit_unit_path() {
    local unit="$1" p
    if secaudit_have_bin systemctl; then
        p=$(systemctl show -p FragmentPath --value "$unit" 2>/dev/null)
        if [ -n "$p" ] && [ -f "$p" ]; then
            printf '%s' "$p"
            return 0
        fi
    fi
    for p in "/usr/lib/systemd/system/${unit}" "/lib/systemd/system/${unit}" "/etc/systemd/system/${unit}"; do
        if [ -f "$p" ]; then
            printf '%s' "$p"
            return 0
        fi
    done
    return 1
}

secaudit_audit_hits() {
    local needle="$1"
    {
        if secaudit_have_bin auditctl; then
            auditctl -l 2>/dev/null || true
        fi
        if [ -d /etc/audit/rules.d ]; then
            secaudit_exec_with_timeout "$_DOCKER_FIND_CAP" grep -R -- "$needle" /etc/audit/rules.d 2>/dev/null | \
                grep -vE '^[[:space:]]*#' || true
        fi
        if [ -f /etc/audit/audit.rules ]; then
            grep -F -- "$needle" /etc/audit/audit.rules 2>/dev/null | grep -vE '^[[:space:]]*#' || true
        fi
    } | grep -F -- "$needle" | grep -v '^[[:space:]]*$' | sort -u
}

secaudit_container_ids() {
    secaudit_info_ok || return 0
    secaudit_exec_with_timeout "$_DOCKER_CMD_CAP" docker ps -q 2>/dev/null
}

secaudit_inspect_fmt() {
    local fmt="$1" id
    while read -r id; do
        [ -n "$id" ] || continue
        secaudit_exec_with_timeout "$_DOCKER_CMD_CAP" docker inspect --format "$fmt" "$id" 2>/dev/null
    done < <(secaudit_container_ids)
}

secaudit_swarm_active() {
    local st
    st=$(secaudit_info_get Swarm LocalNodeState 2>/dev/null || true)
    [ "$st" = "active" ]
}

secaudit_pick_image() {
    local img
    if ! secaudit_info_ok; then
        return 1
    fi
    img=$(secaudit_exec_with_timeout 8 docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -v '<none>' | head -1)
    [ -n "$img" ] && printf '%s' "$img"
}

# --- checks ---

secaudit_check_data_partition() {
    local num="$1"
    shift
    local rootdir src_root src_data
    rootdir=$(secaudit_info_get DockerRootDir 2>/dev/null || true)
    [ -n "$rootdir" ] || rootdir="/var/lib/docker"
    if secaudit_have_bin findmnt; then
        src_root=$(findmnt -n -o SOURCE -T / 2>/dev/null)
        src_data=$(findmnt -n -o SOURCE -T "$rootdir" 2>/dev/null)
        if [ -n "$src_data" ] && [ -n "$src_root" ] && [ "$src_data" != "$src_root" ]; then
            secaudit_report_pass "$num" "DockerRootDir=${rootdir} is on a separate volume (data=${src_data} root=${src_root})"
            return 0
        fi
        secaudit_report_fail "$num" "DockerRootDir=${rootdir} shares the root volume (data=${src_data:-NA} root=${src_root:-NA})"
        return 0
    fi
    if grep -E "[[:space:]]${rootdir}[[:space:]]" /proc/mounts >/dev/null 2>&1; then
        secaudit_report_pass "$num" "DockerRootDir=${rootdir} appears in /proc/mounts as its own mount"
    else
        secaudit_report_fail "$num" "DockerRootDir=${rootdir} is not a distinct mount in /proc/mounts"
    fi
}

secaudit_check_data_mountpoint() {
    local num="$1"
    shift
    local rootdir
    rootdir=$(secaudit_info_get DockerRootDir 2>/dev/null || true)
    [ -n "$rootdir" ] || rootdir="/var/lib/docker"
    if secaudit_have_bin mountpoint && mountpoint -q -- "$rootdir" 2>/dev/null; then
        secaudit_report_pass "$num" "${rootdir} is a dedicated mountpoint"
    elif grep -E "[[:space:]]${rootdir}[[:space:]]" /proc/mounts >/dev/null 2>&1; then
        secaudit_report_pass "$num" "${rootdir} is listed as a mount in /proc/mounts"
    else
        secaudit_report_fail "$num" "${rootdir} is not a separate mountpoint"
    fi
}

secaudit_check_docker_group() {
    local num="$1"
    shift
    local members rec
    rec=$(getent group docker 2>/dev/null || true)
    if [ -z "$rec" ]; then
        secaudit_report_pass "$num" "docker group is absent (no extra socket trustees)"
        return 0
    fi
    members=$(printf '%s' "$rec" | awk -F: '{print $4}')
    if [ -z "$members" ]; then
        secaudit_report_pass "$num" "docker group exists with no members"
    else
        secaudit_report_fail "$num" "docker group members require review (${members})"
    fi
}

secaudit_check_audit_watch() {
    local num="$1"
    shift
    local needle="$1" label="$2"
    local ev
    ev=$(secaudit_squash_ws "$(secaudit_audit_hits "$needle" | tr '\n' ' ')")
    if [ -n "$ev" ]; then
        secaudit_report_pass "$num" "audit watch present for ${label}"
    else
        secaudit_report_fail "$num" "audit watch missing for ${label} (needle=${needle})"
    fi
}

secaudit_check_engine_version() {
    local num="$1"
    shift
    local ver major
    ver=$(secaudit_info_get ServerVersion 2>/dev/null || true)
    [ -n "$ver" ] || ver=$(secaudit_exec_with_timeout 8 docker version --format '{{.Server.Version}}' 2>/dev/null || true)
    if [ -z "$ver" ]; then
        secaudit_report_fail "$num" "Docker server version could not be read"
        return 0
    fi
    major=$(printf '%s' "$ver" | grep -oE '^[0-9]+' | head -1)
    if [ -n "$major" ] && [ "$major" -ge 20 ] 2>/dev/null; then
        secaudit_report_pass "$num" "Docker server version ${ver} (>=20.x; confirm patch currency)"
    else
        secaudit_report_fail "$num" "Docker server version ${ver} is older than the 20.x baseline"
    fi
}

secaudit_check_rootless_daemon() {
    local num="$1"
    shift
    local rootless uid user
    rootless=$(secaudit_info_get SecurityOptions 2>/dev/null || true)
    if printf '%s' "$rootless" | grep -qi 'rootless'; then
        secaudit_report_pass "$num" "docker info reports rootless in SecurityOptions"
        return 0
    fi
    rootless=$(secaudit_info_get Rootless 2>/dev/null || true)
    case "$rootless" in
        true|True) secaudit_report_pass "$num" "docker info Rootless=true"; return 0 ;;
    esac
    if [ -n "$_DOCKER_PID" ] && [ -r "/proc/${_DOCKER_PID}/status" ]; then
        uid=$(awk '/^Uid:/{print $2}' "/proc/${_DOCKER_PID}/status" 2>/dev/null)
        user=$(secaudit_path_owner_user "/proc/${_DOCKER_PID}")
        if [ -n "$uid" ] && [ "$uid" != "0" ]; then
            secaudit_report_pass "$num" "dockerd pid=${_DOCKER_PID} runs as uid=${uid} user=${user:-unknown}"
            return 0
        fi
        secaudit_report_fail "$num" "dockerd pid=${_DOCKER_PID} runs as uid=${uid:-unknown} (root required unless rootless mode)"
        return 0
    fi
    secaudit_report_fail "$num" "dockerd process not visible in /proc; cannot confirm non-root execution"
}

secaudit_check_icc_restricted() {
    local num="$1"
    shift
    local icc
    icc=$(secaudit_cmdline_val "--icc")
    [ -n "$icc" ] || icc=$(secaudit_daemon_val "icc")
    if [ -z "$icc" ] && secaudit_info_ok; then
        icc=$(secaudit_exec_with_timeout 8 docker network inspect bridge --format '{{index .Options "com.docker.network.bridge.enable_icc"}}' 2>/dev/null || true)
    fi
    case "$icc" in
        false|False|FALSE)
            secaudit_report_pass "$num" "inter-container communication on the default bridge is disabled (icc=${icc})"
            ;;
        *)
            secaudit_report_fail "$num" "default-bridge ICC is not disabled (icc=${icc:-default-true})"
            ;;
    esac
}

secaudit_check_log_level() {
    local num="$1"
    shift
    local lvl
    lvl=$(secaudit_merged_val "log-level")
    [ -n "$lvl" ] || lvl=$(secaudit_daemon_val "log-level")
    case "$(printf '%s' "$lvl" | tr '[:upper:]' '[:lower:]')" in
        info|"")
            secaudit_report_pass "$num" "daemon log-level is info or the info default (${lvl:-unset})"
            ;;
        *)
            secaudit_report_fail "$num" "daemon log-level is '${lvl}' (required info)"
            ;;
    esac
}

secaudit_check_iptables_enabled() {
    local num="$1"
    shift
    local ipt ipf
    ipt=$(secaudit_merged_val "iptables")
    [ -n "$ipt" ] || ipt=$(secaudit_daemon_val "iptables")
    ipf=$(secaudit_info_get IPv4Forwarding 2>/dev/null || true)
    [ -n "$ipf" ] || ipf=$(secaudit_merged_val "ip-forward")
    if [ "$ipt" = "false" ]; then
        secaudit_report_fail "$num" "daemon iptables=false (Docker must be allowed to manage iptables); ip-forward=${ipf:-unknown}"
        return 0
    fi
    secaudit_report_pass "$num" "Docker may manage iptables (iptables=${ipt:-default-true} ip-forward=${ipf:-unknown})"
}

secaudit_check_insecure_registries() {
    local num="$1"
    shift
    local cidrs hosts legacy
    cidrs=$(secaudit_info_get RegistryConfig InsecureRegistryCIDRs 2>/dev/null || true)
    hosts=$(secaudit_daemon_val "insecure-registries")
    legacy=$(secaudit_cmdline_val "--disable-legacy-registry")
    [ -n "$legacy" ] || legacy=$(secaudit_daemon_val "disable-legacy-registry")
    if printf '%s %s' "$cidrs" "$hosts" | grep -qE '0\.0\.0\.0|::/0'; then
        secaudit_report_fail "$num" "insecure registries include wide-open CIDRs (cidrs=${cidrs} hosts=${hosts})"
        return 0
    fi
    if printf '%s' "$hosts" | grep -qE '[a-zA-Z0-9.-]+' && ! printf '%s' "$hosts" | grep -qE '^\s*(\[\]|null)?\s*$'; then
        if printf '%s' "$hosts" | grep -qvE '127\.0\.0\.0|::1'; then
            secaudit_report_fail "$num" "insecure-registries configured (${hosts})"
            return 0
        fi
    fi
    secaudit_report_pass "$num" "insecure registries limited to loopback or unset (cidrs=${cidrs:-none} disable-legacy-registry=${legacy:-n/a})"
}

secaudit_check_storage_driver() {
    local num="$1"
    shift
    local drv
    drv=$(secaudit_merged_val "storage-driver" Driver)
    [ -n "$drv" ] || drv=$(secaudit_info_get Driver 2>/dev/null || true)
    case "$drv" in
        aufs)
            secaudit_report_fail "$num" "storage-driver is aufs"
            ;;
        overlay2)
            secaudit_report_pass "$num" "storage-driver is overlay2"
            ;;
        "")
            secaudit_report_fail "$num" "storage-driver could not be determined"
            ;;
        *)
            secaudit_report_pass "$num" "storage-driver is ${drv} (not aufs; overlay2 preferred)"
            ;;
    esac
}

secaudit_check_tls_auth() {
    local num="$1"
    shift
    local hosts tlsverify cacert
    hosts=$(secaudit_merged_val "hosts")
    [ -n "$hosts" ] || hosts=$(secaudit_daemon_val "hosts")
    tlsverify=$(secaudit_merged_val "tlsverify")
    [ -n "$tlsverify" ] || tlsverify=$(secaudit_daemon_val "tlsverify")
    cacert=$(secaudit_merged_val "tlscacert")
    [ -n "$cacert" ] || cacert=$(secaudit_daemon_val "tlscacert")
    if printf '%s' "$hosts $_DOCKER_CMDLINE $_DOCKER_UNIT_BLOB" | grep -qE 'tcp://'; then
        if [ "$tlsverify" = "true" ] && [ -n "$cacert" ]; then
            secaudit_report_pass "$num" "remote TCP host is configured with tlsverify and tlscacert=${cacert}"
        elif printf '%s' "$_DOCKER_DAEMON_BLOB $_DOCKER_CMDLINE" | grep -qiE 'tlsverify|tlscacert|tlscert|tlskey'; then
            secaudit_report_pass "$num" "remote host present and TLS material is referenced"
        else
            secaudit_report_fail "$num" "daemon listens on TCP without tlsverify/tlscacert (hosts=${hosts})"
        fi
        return 0
    fi
    secaudit_report_pass "$num" "daemon is not advertised on remote TCP (hosts=${hosts:-unix-socket})"
}

secaudit_check_authz_plugins() {
    local num="$1"
    shift
    local plugins
    plugins=$(secaudit_merged_val "authorization-plugins")
    [ -n "$plugins" ] || plugins=$(secaudit_daemon_val "authorization-plugins")
    if [ -n "$plugins" ] && [ "$plugins" != "null" ] && [ "$plugins" != "[]" ]; then
        secaudit_report_pass "$num" "authorization-plugins configured (${plugins})"
    else
        secaudit_report_fail "$num" "authorization-plugins are not configured"
    fi
}

secaudit_check_log_driver() {
    local num="$1"
    shift
    local drv
    drv=$(secaudit_merged_val "log-driver" LoggingDriver)
    [ -n "$drv" ] || drv=$(secaudit_info_get LoggingDriver 2>/dev/null || true)
    case "$drv" in
        json-file|"")
            secaudit_report_fail "$num" "LoggingDriver=${drv:-json-file} is local-only (central/remote driver required)"
            ;;
        syslog|journald|gelf|fluentd|awslogs|splunk|etwlogs|gcplogs|logentries|none)
            secaudit_report_pass "$num" "LoggingDriver=${drv} supports centralized or remote collection"
            ;;
        *)
            secaudit_report_pass "$num" "LoggingDriver=${drv}"
            ;;
    esac
}

secaudit_check_no_new_priv_daemon() {
    local num="$1"
    shift
    local nnp sec
    sec=$(secaudit_info_get SecurityOptions 2>/dev/null || true)
    if printf '%s' "$sec" | grep -qi 'no-new-privileges'; then
        secaudit_report_pass "$num" "no-new-privileges is reported in docker info SecurityOptions"
        return 0
    fi
    secaudit_merged_true "no-new-privileges"
    nnp=$?
    if [ "$nnp" -eq 0 ]; then
        secaudit_report_pass "$num" "no-new-privileges is enabled on the daemon"
    else
        secaudit_report_fail "$num" "no-new-privileges is not enabled (daemon.json/cmdline/info)"
    fi
}

secaudit_check_userland_proxy() {
    local num="$1"
    shift
    local up rc
    secaudit_merged_true "userland-proxy"
    rc=$?
    up=$(secaudit_merged_val "userland-proxy")
    if [ "$rc" -eq 1 ] || [ "$up" = "false" ]; then
        secaudit_report_pass "$num" "userland-proxy is disabled"
    else
        secaudit_report_fail "$num" "userland-proxy is not disabled (${up:-default-true})"
    fi
}

secaudit_check_seccomp_daemon() {
    local num="$1"
    shift
    local sec prof
    sec=$(secaudit_info_get SecurityOptions 2>/dev/null || true)
    prof=$(secaudit_merged_val "seccomp-profile")
    [ -n "$prof" ] || prof=$(secaudit_daemon_val "seccomp-profile")
    if printf '%s' "$sec" | grep -qi seccomp; then
        secaudit_report_pass "$num" "seccomp is present in SecurityOptions (profile=${prof:-default})"
    elif [ -n "$prof" ]; then
        secaudit_report_pass "$num" "custom seccomp-profile is configured (${prof})"
    else
        secaudit_report_fail "$num" "seccomp is not reported in SecurityOptions and no seccomp-profile is set"
    fi
}

secaudit_check_experimental() {
    local num="$1"
    shift
    local exp
    exp=$(secaudit_info_get ExperimentalBuild 2>/dev/null || true)
    [ -n "$exp" ] || exp=$(secaudit_exec_with_timeout 8 docker version --format '{{.Server.Experimental}}' 2>/dev/null || true)
    [ -n "$exp" ] || exp=$(secaudit_merged_val "experimental")
    if [ -z "$exp" ] && printf '%s' "$_DOCKER_HELP_TEXT" | grep -q -- '--experimental'; then
        secaudit_cmdline_has "--experimental" && exp="true"
    fi
    case "$exp" in
        true|True|TRUE)
            secaudit_report_fail "$num" "experimental features are enabled"
            ;;
        *)
            secaudit_report_pass "$num" "experimental features are disabled (${exp:-false})"
            ;;
    esac
}

secaudit_check_path_owner() {
    local num="$1"
    shift
    local path="$1" want_own="$2" label="$3" required="${4:-0}"
    local u g
    if [ ! -e "$path" ]; then
        if [ "$required" = "1" ] && secaudit_info_ok; then
            secaudit_report_fail "$num" "${label} is missing (${path})"
        else
            secaudit_report_pass "$num" "${label} is not present (${path})"
        fi
        return 0
    fi
    u=$(secaudit_path_owner_user "$path")
    g=$(secaudit_path_owner_group "$path")
    if [ "${u}:${g}" = "$want_own" ]; then
        secaudit_report_pass "$num" "${label} owner is ${u}:${g} ($(secaudit_path_listing "$path"))"
    else
        secaudit_report_fail "$num" "${label} owner is ${u:-unknown}:${g:-unknown} (expected ${want_own}) ($(secaudit_path_listing "$path"))"
    fi
}

secaudit_check_path_mode() {
    local num="$1"
    shift
    local path="$1" ceiling="$2" label="$3" required="${4:-0}"
    local mode
    if [ ! -e "$path" ]; then
        if [ "$required" = "1" ] && secaudit_info_ok; then
            secaudit_report_fail "$num" "${label} is missing (${path})"
        else
            secaudit_report_pass "$num" "${label} is not present (${path})"
        fi
        return 0
    fi
    mode=$(secaudit_path_mode_octal "$path")
    if secaudit_perm_within "$mode" "$ceiling"; then
        secaudit_report_pass "$num" "${label} mode=${mode} (ceiling ${ceiling}) ($(secaudit_path_listing "$path"))"
    else
        secaudit_report_fail "$num" "${label} mode=${mode} exceeds ${ceiling} ($(secaudit_path_listing "$path"))"
    fi
}

secaudit_check_cert_tree_owner() {
    local num="$1"
    shift
    local bad="" path
    if [ ! -d "$_DOCKER_CERTS_DIR" ]; then
        secaudit_report_pass "$num" "registry cert tree ${_DOCKER_CERTS_DIR} is absent"
        return 0
    fi
    while IFS= read -r path; do
        [ -n "$path" ] || continue
        if [ "$(secaudit_path_owner_user "$path")" != "root" ] || [ "$(secaudit_path_owner_group "$path")" != "root" ]; then
            bad="${bad} ${path}:$(secaudit_path_owner_user "$path"):$(secaudit_path_owner_group "$path")"
        fi
    done < <(secaudit_exec_with_timeout "$_DOCKER_FIND_CAP" find "$_DOCKER_CERTS_DIR" -type f \( -name '*.pem' -o -name '*.crt' -o -name '*.key' \) 2>/dev/null)
    if [ -n "$bad" ]; then
        secaudit_report_fail "$num" "registry cert ownership violations (${bad# })"
    else
        secaudit_report_pass "$num" "registry cert files under ${_DOCKER_CERTS_DIR} are root:root"
    fi
}

secaudit_check_cert_tree_mode() {
    local num="$1"
    shift
    local bad="" path mode
    if [ ! -d "$_DOCKER_CERTS_DIR" ]; then
        secaudit_report_pass "$num" "registry cert tree ${_DOCKER_CERTS_DIR} is absent"
        return 0
    fi
    while IFS= read -r path; do
        [ -n "$path" ] || continue
        mode=$(secaudit_path_mode_octal "$path")
        secaudit_perm_within "$mode" 444 || bad="${bad} ${mode}:${path}"
    done < <(secaudit_exec_with_timeout "$_DOCKER_FIND_CAP" find "$_DOCKER_CERTS_DIR" -type f \( -name '*.pem' -o -name '*.crt' -o -name '*.key' \) 2>/dev/null)
    if [ -n "$bad" ]; then
        secaudit_report_fail "$num" "registry cert modes exceed 444 (${bad# })"
    else
        secaudit_report_pass "$num" "registry cert file modes are <=444"
    fi
}

secaudit_check_named_cert() {
    local num="$1"
    shift
    local fname="$1" want_own="$2" ceiling="$3"
    local found=0 bad=0 path mode u g cacert tlscert tlskey
    if [ ! -d "$_DOCKER_CERTS_DIR" ]; then
        secaudit_report_pass "$num" "no ${fname} under ${_DOCKER_CERTS_DIR}"
        return 0
    fi
    while IFS= read -r path; do
        [ -n "$path" ] || continue
        found=1
        u=$(secaudit_path_owner_user "$path"); g=$(secaudit_path_owner_group "$path"); mode=$(secaudit_path_mode_octal "$path")
        if [ "${u}:${g}" != "$want_own" ] || ! secaudit_perm_within "$mode" "$ceiling"; then
            bad=1
        fi
    done < <(secaudit_exec_with_timeout "$_DOCKER_FIND_CAP" find "$_DOCKER_CERTS_DIR" -type f -name "$fname" 2>/dev/null)
    if [ "$found" -eq 0 ]; then
        cacert=$(secaudit_merged_val "tlscacert")
        tlscert=$(secaudit_merged_val "tlscert")
        tlskey=$(secaudit_merged_val "tlskey")
        case "$fname" in
            ca.pem)
                if [ -n "$cacert" ] && [ -e "$cacert" ]; then
                    u=$(secaudit_path_owner_user "$cacert"); g=$(secaudit_path_owner_group "$cacert"); mode=$(secaudit_path_mode_octal "$cacert")
                    if [ "${u}:${g}" = "$want_own" ] && secaudit_perm_within "$mode" "$ceiling"; then
                        secaudit_report_pass "$num" "tlscacert ${cacert} meets ${want_own} mode<=${ceiling}"
                    else
                        secaudit_report_fail "$num" "tlscacert ${cacert} is ${u}:${g} mode=${mode}"
                    fi
                    return 0
                fi
                ;;
            cert.pem)
                if [ -n "$tlscert" ] && [ -e "$tlscert" ]; then
                    u=$(secaudit_path_owner_user "$tlscert"); g=$(secaudit_path_owner_group "$tlscert"); mode=$(secaudit_path_mode_octal "$tlscert")
                    if [ "${u}:${g}" = "$want_own" ] && secaudit_perm_within "$mode" "$ceiling"; then
                        secaudit_report_pass "$num" "tlscert ${tlscert} meets ${want_own} mode<=${ceiling}"
                    else
                        secaudit_report_fail "$num" "tlscert ${tlscert} is ${u}:${g} mode=${mode}"
                    fi
                    return 0
                fi
                ;;
            key.pem)
                if [ -n "$tlskey" ] && [ -e "$tlskey" ]; then
                    u=$(secaudit_path_owner_user "$tlskey"); g=$(secaudit_path_owner_group "$tlskey"); mode=$(secaudit_path_mode_octal "$tlskey")
                    if [ "${u}:${g}" = "$want_own" ] && secaudit_perm_within "$mode" "$ceiling"; then
                        secaudit_report_pass "$num" "tlskey ${tlskey} meets ${want_own} mode<=${ceiling}"
                    else
                        secaudit_report_fail "$num" "tlskey ${tlskey} is ${u}:${g} mode=${mode}"
                    fi
                    return 0
                fi
                ;;
        esac
        secaudit_report_pass "$num" "no ${fname} files to inspect"
    elif [ "$bad" -eq 0 ]; then
        secaudit_report_pass "$num" "${fname} files meet ${want_own} mode<=${ceiling}"
    else
        secaudit_report_fail "$num" "${fname} ownership or mode violation (expected ${want_own} <=${ceiling})"
    fi
}

secaudit_check_container_users() {
    local num="$1"
    shift
    local bad="" id user
    if ! secaudit_info_ok; then
        secaudit_report_fail "$num" "daemon is not reachable; cannot inspect container users"
        return 0
    fi
    if [ -z "$(secaudit_container_ids)" ]; then
        secaudit_report_pass "$num" "no running containers (user check not applicable)"
        return 0
    fi
    while read -r id; do
        [ -n "$id" ] || continue
        user=$(secaudit_exec_with_timeout 8 docker inspect --format '{{.Config.User}}' "$id" 2>/dev/null)
        case "$user" in
            ""|0|0:0|root|root:*)
                bad="${bad} ${id:0:12}:User=${user:-empty}"
                ;;
        esac
    done < <(secaudit_container_ids)
    if [ -n "$bad" ]; then
        secaudit_report_fail "$num" "containers running as root (${bad# })"
    else
        secaudit_report_pass "$num" "running containers set a non-root Config.User"
    fi
}

secaudit_check_content_trust() {
    local num="$1"
    shift
    if [ "${DOCKER_CONTENT_TRUST:-}" = "1" ]; then
        secaudit_report_pass "$num" "DOCKER_CONTENT_TRUST=1"
    else
        secaudit_report_fail "$num" "DOCKER_CONTENT_TRUST=${DOCKER_CONTENT_TRUST:-unset} (required 1)"
    fi
}

secaudit_check_apparmor_containers() {
    local num="$1"
    shift
    local hits id prof
    if ! secaudit_info_ok; then
        secaudit_report_fail "$num" "daemon is not reachable; cannot inspect AppArmor profiles"
        return 0
    fi
    if [ -z "$(secaudit_container_ids)" ]; then
        secaudit_report_pass "$num" "no running containers (AppArmor check not applicable)"
        return 0
    fi
    hits=""
    while read -r id; do
        [ -n "$id" ] || continue
        prof=$(secaudit_exec_with_timeout 8 docker inspect --format '{{.AppArmorProfile}} {{json .HostConfig.SecurityOpt}}' "$id" 2>/dev/null)
        if ! printf '%s' "$prof" | grep -qiE 'docker-default|apparmor=|apparmor:'; then
            hits="${hits} ${id:0:12}"
        fi
    done < <(secaudit_container_ids)
    if [ -n "$hits" ]; then
        secaudit_report_fail "$num" "AppArmor profile missing on container(s):${hits}"
    else
        secaudit_report_pass "$num" "AppArmor profiles are applied on running containers"
    fi
}

secaudit_check_selinux_daemon() {
    local num="$1"
    shift
    local sec sel
    sec=$(secaudit_info_get SecurityOptions 2>/dev/null || true)
    sel=$(secaudit_daemon_val "selinux-enabled")
    [ -n "$sel" ] || sel=$(secaudit_cmdline_val "--selinux-enabled")
    if printf '%s' "$sec" | grep -qi selinux; then
        secaudit_report_pass "$num" "SELinux is reported in SecurityOptions"
    elif [ "$sel" = "true" ]; then
        secaudit_report_pass "$num" "selinux-enabled=true in daemon configuration"
    else
        secaudit_report_fail "$num" "SELinux is not enabled for the daemon (selinux-enabled=${sel:-unset})"
    fi
}

secaudit_check_capabilities() {
    local num="$1"
    shift
    local bad="" id add drop
    if ! secaudit_info_ok; then
        secaudit_report_fail "$num" "daemon is not reachable; cannot inspect capabilities"
        return 0
    fi
    if [ -z "$(secaudit_container_ids)" ]; then
        secaudit_report_pass "$num" "no running containers (capability check not applicable)"
        return 0
    fi
    while read -r id; do
        [ -n "$id" ] || continue
        add=$(secaudit_exec_with_timeout 8 docker inspect --format '{{json .HostConfig.CapAdd}}' "$id" 2>/dev/null)
        drop=$(secaudit_exec_with_timeout 8 docker inspect --format '{{json .HostConfig.CapDrop}}' "$id" 2>/dev/null)
        if printf '%s' "$add" | grep -qiE '"ALL"'; then
            bad="${bad} ${id:0:12}:CapAdd=ALL"
            continue
        fi
        if ! printf '%s' "$drop" | grep -qiE '"ALL"'; then
            if [ "$drop" = "null" ] || [ "$drop" = "[]" ] || [ -z "$drop" ]; then
                bad="${bad} ${id:0:12}:CapDrop=${drop:-null}"
            fi
        fi
    done < <(secaudit_container_ids)
    if [ -n "$bad" ]; then
        secaudit_report_fail "$num" "kernel capabilities are not minimized (${bad# })"
    else
        secaudit_report_pass "$num" "running containers drop ALL (or do not add ALL)"
    fi
}

secaudit_check_privileged() {
    local num="$1"
    shift
    local hits
    if ! secaudit_info_ok; then
        secaudit_report_fail "$num" "daemon is not reachable; cannot inspect Privileged"
        return 0
    fi
    if [ -z "$(secaudit_container_ids)" ]; then
        secaudit_report_pass "$num" "no running containers (privileged check not applicable)"
        return 0
    fi
    hits=$(secaudit_inspect_fmt '{{.Id}} Privileged={{.HostConfig.Privileged}}' | grep 'Privileged=true' | tr '\n' ' ')
    if [ -n "$hits" ]; then
        secaudit_report_fail "$num" "privileged containers present (${hits})"
    else
        secaudit_report_pass "$num" "no privileged containers"
    fi
}

secaudit_check_sensitive_mounts() {
    local num="$1"
    shift
    local hits
    if ! secaudit_info_ok; then
        secaudit_report_fail "$num" "daemon is not reachable; cannot inspect Mounts"
        return 0
    fi
    if [ -z "$(secaudit_container_ids)" ]; then
        secaudit_report_pass "$num" "no running containers (mount check not applicable)"
        return 0
    fi
    hits=$(secaudit_inspect_fmt '{{.Id}} {{range .Mounts}}{{.Source}}->{{.Destination}} rw={{.RW}};{{end}}' | \
        grep -iE 'rw=true' | grep -E '/(boot|dev|etc|lib|proc|sys|usr)(/|[[:space:]]|$)' | tr '\n' ' ')
    if [ -n "$hits" ]; then
        secaudit_report_fail "$num" "sensitive host paths mounted read-write (${hits})"
    else
        secaudit_report_pass "$num" "no sensitive host paths mounted read-write"
    fi
}

secaudit_check_sshd_in_containers() {
    local num="$1"
    shift
    local hits="" id cmd top
    if ! secaudit_info_ok; then
        secaudit_report_fail "$num" "daemon is not reachable; cannot inspect sshd"
        return 0
    fi
    if [ -z "$(secaudit_container_ids)" ]; then
        secaudit_report_pass "$num" "no running containers (sshd check not applicable)"
        return 0
    fi
    while read -r id; do
        [ -n "$id" ] || continue
        cmd=$(secaudit_exec_with_timeout 8 docker inspect --format '{{json .Config.Cmd}} {{json .Config.Entrypoint}} {{json .Config.ExposedPorts}}' "$id" 2>/dev/null)
        if printf '%s' "$cmd" | grep -qiE 'sshd|/usr/sbin/sshd|"22/tcp"'; then
            hits="${hits} ${id:0:12}:cmd"
            continue
        fi
        top=$(secaudit_exec_with_timeout 8 docker top "$id" 2>/dev/null | awk 'NR>1 {print}' | grep -E '[s]shd|[s]sh ' || true)
        if [ -n "$top" ]; then
            hits="${hits} ${id:0:12}:proc"
        fi
    done < <(secaudit_container_ids)
    if [ -n "$hits" ]; then
        secaudit_report_fail "$num" "sshd indicated inside containers (${hits# })"
    else
        secaudit_report_pass "$num" "sshd not observed in running containers"
    fi
}

secaudit_check_privileged_ports() {
    local num="$1"
    shift
    local hits
    if ! secaudit_info_ok; then
        secaudit_report_fail "$num" "daemon is not reachable; cannot inspect published ports"
        return 0
    fi
    if [ -z "$(secaudit_container_ids)" ]; then
        secaudit_report_pass "$num" "no running containers (privileged-port check not applicable)"
        return 0
    fi
    hits=$(secaudit_inspect_fmt '{{.Id}} {{json .NetworkSettings.Ports}} {{json .HostConfig.PortBindings}}' | \
        grep -oE '[0-9]+/tcp|[0-9]+/udp|"HostPort":"[0-9]+"' | \
        grep -oE '[0-9]+' | awk '$1+0 < 1024 {print}' | tr '\n' ' ')
    if [ -n "$hits" ]; then
        secaudit_report_fail "$num" "privileged host ports (<1024) are published (${hits})"
    else
        secaudit_report_pass "$num" "no privileged host ports are published"
    fi
}

secaudit_check_readonly_rootfs() {
    local num="$1"
    shift
    local hits
    if ! secaudit_info_ok; then
        secaudit_report_fail "$num" "daemon is not reachable; cannot inspect ReadonlyRootfs"
        return 0
    fi
    if [ -z "$(secaudit_container_ids)" ]; then
        secaudit_report_pass "$num" "no running containers (read-only rootfs check not applicable)"
        return 0
    fi
    hits=$(secaudit_inspect_fmt '{{.Id}} ReadonlyRootfs={{.HostConfig.ReadonlyRootfs}}' | grep 'ReadonlyRootfs=false' | tr '\n' ' ')
    if [ -n "$hits" ]; then
        secaudit_report_fail "$num" "containers without a read-only root filesystem"
    else
        secaudit_report_pass "$num" "running containers use ReadonlyRootfs=true"
    fi
}

secaudit_check_port_bind_iface() {
    local num="$1"
    shift
    local hits
    if ! secaudit_info_ok; then
        secaudit_report_fail "$num" "daemon is not reachable; cannot inspect PortBindings"
        return 0
    fi
    if [ -z "$(secaudit_container_ids)" ]; then
        secaudit_report_pass "$num" "no running containers (bind-interface check not applicable)"
        return 0
    fi
    hits=$(secaudit_inspect_fmt '{{.Id}} {{json .NetworkSettings.Ports}}' | grep -E '0\.0\.0\.0|::' | tr '\n' ' ')
    if [ -n "$hits" ]; then
        secaudit_report_fail "$num" "published ports are bound to all host interfaces (0.0.0.0/::)"
    else
        secaudit_report_pass "$num" "published ports are bound to a specific host interface or unpublished"
    fi
}

secaudit_check_pid_namespace() {
    local num="$1"
    shift
    local hits
    if ! secaudit_info_ok; then
        secaudit_report_fail "$num" "daemon is not reachable; cannot inspect PidMode"
        return 0
    fi
    if [ -z "$(secaudit_container_ids)" ]; then
        secaudit_report_pass "$num" "no running containers (PID namespace check not applicable)"
        return 0
    fi
    hits=$(secaudit_inspect_fmt '{{.Id}} PidMode={{.HostConfig.PidMode}}' | grep 'PidMode=host' | tr '\n' ' ')
    if [ -n "$hits" ]; then
        secaudit_report_fail "$num" "host PID namespace is shared"
    else
        secaudit_report_pass "$num" "host PID namespace is not shared"
    fi
}

secaudit_check_ipc_namespace() {
    local num="$1"
    shift
    local hits
    if ! secaudit_info_ok; then
        secaudit_report_fail "$num" "daemon is not reachable; cannot inspect IpcMode"
        return 0
    fi
    if [ -z "$(secaudit_container_ids)" ]; then
        secaudit_report_pass "$num" "no running containers (IPC namespace check not applicable)"
        return 0
    fi
    hits=$(secaudit_inspect_fmt '{{.Id}} IpcMode={{.HostConfig.IpcMode}}' | grep 'IpcMode=host' | tr '\n' ' ')
    if [ -n "$hits" ]; then
        secaudit_report_fail "$num" "host IPC namespace is shared"
    else
        secaudit_report_pass "$num" "host IPC namespace is not shared"
    fi
}

secaudit_check_host_devices() {
    local num="$1"
    shift
    local hits
    if ! secaudit_info_ok; then
        secaudit_report_fail "$num" "daemon is not reachable; cannot inspect Devices"
        return 0
    fi
    if [ -z "$(secaudit_container_ids)" ]; then
        secaudit_report_pass "$num" "no running containers (device check not applicable)"
        return 0
    fi
    hits=$(secaudit_inspect_fmt '{{.Id}} Devices={{json .HostConfig.Devices}}' | grep -vE 'Devices=(\[\]|null)' | tr '\n' ' ')
    if [ -n "$hits" ]; then
        secaudit_report_fail "$num" "host devices are exposed to containers (${hits})"
    else
        secaudit_report_pass "$num" "no host devices are mapped into containers"
    fi
}

secaudit_check_mount_propagation() {
    local num="$1"
    shift
    local hits
    if ! secaudit_info_ok; then
        secaudit_report_fail "$num" "daemon is not reachable; cannot inspect mount propagation"
        return 0
    fi
    if [ -z "$(secaudit_container_ids)" ]; then
        secaudit_report_pass "$num" "no running containers (propagation check not applicable)"
        return 0
    fi
    hits=$(secaudit_inspect_fmt '{{.Id}} {{range .Mounts}}{{.Destination}} prop={{.Propagation}};{{end}}' | \
        grep -E 'prop=(rshared|shared)' | tr '\n' ' ')
    if [ -n "$hits" ]; then
        secaudit_report_fail "$num" "shared mount propagation is in use (${hits})"
    else
        secaudit_report_pass "$num" "mount propagation is not shared"
    fi
}

secaudit_check_uts_namespace() {
    local num="$1"
    shift
    local hits
    if ! secaudit_info_ok; then
        secaudit_report_fail "$num" "daemon is not reachable; cannot inspect UTSMode"
        return 0
    fi
    if [ -z "$(secaudit_container_ids)" ]; then
        secaudit_report_pass "$num" "no running containers (UTS namespace check not applicable)"
        return 0
    fi
    hits=$(secaudit_inspect_fmt '{{.Id}} UTSMode={{.HostConfig.UTSMode}}' | grep 'UTSMode=host' | tr '\n' ' ')
    if [ -n "$hits" ]; then
        secaudit_report_fail "$num" "host UTS namespace is shared"
    else
        secaudit_report_pass "$num" "host UTS namespace is not shared"
    fi
}

secaudit_check_seccomp_containers() {
    local num="$1"
    shift
    local hits
    if ! secaudit_info_ok; then
        secaudit_report_fail "$num" "daemon is not reachable; cannot inspect SecurityOpt"
        return 0
    fi
    if [ -z "$(secaudit_container_ids)" ]; then
        secaudit_report_pass "$num" "no running containers (seccomp check not applicable)"
        return 0
    fi
    hits=$(secaudit_inspect_fmt '{{.Id}} {{json .HostConfig.SecurityOpt}}' | grep -i 'seccomp:unconfined\|seccomp=unconfined' | tr '\n' ' ')
    if [ -n "$hits" ]; then
        secaudit_report_fail "$num" "seccomp is disabled (unconfined) on container(s)"
    else
        secaudit_report_pass "$num" "default seccomp is not disabled on running containers"
    fi
}

secaudit_check_exec_privileged() {
    local num="$1"
    shift
    local ev
    if secaudit_have_bin ausearch; then
        ev=$(ausearch -k docker -ts recent 2>/dev/null | grep -iE 'exec.*privileged|--privileged' | tail -5 | tr '\n' ' ')
        if [ -n "$ev" ]; then
            secaudit_report_fail "$num" "audit records show privileged docker exec (${ev})"
        else
            secaudit_report_pass "$num" "no recent privileged docker exec in audit"
        fi
        return 0
    fi
    if secaudit_have_bin journalctl; then
        ev=$(secaudit_exec_with_timeout 8 journalctl -u docker --since "7 days ago" 2>/dev/null | grep -iE 'exec.*privileged' | tail -3 | tr '\n' ' ')
        if [ -n "$ev" ]; then
            secaudit_report_fail "$num" "journal shows privileged docker exec"
        else
            secaudit_report_pass "$num" "journal has no privileged docker exec (ausearch unavailable)"
        fi
        return 0
    fi
    secaudit_report_pass "$num" "ausearch/journalctl unavailable; privileged docker exec not observed"
}

secaudit_check_exec_root() {
    local num="$1"
    shift
    local ev
    if secaudit_have_bin ausearch; then
        ev=$(ausearch -k docker -ts recent 2>/dev/null | grep -iE 'exec.*(--user[= ]root|user=0)' | tail -5 | tr '\n' ' ')
        if [ -n "$ev" ]; then
            secaudit_report_fail "$num" "audit records show docker exec as root (${ev})"
        else
            secaudit_report_pass "$num" "no recent root docker exec in audit"
        fi
        return 0
    fi
    secaudit_report_pass "$num" "ausearch unavailable; root docker exec not observed"
}

secaudit_check_cgroup_parent_containers() {
    local num="$1"
    shift
    local hits parent
    parent=$(secaudit_merged_val "cgroup-parent")
    if ! secaudit_info_ok; then
        secaudit_report_fail "$num" "daemon is not reachable; cannot inspect CgroupParent"
        return 0
    fi
    if [ -z "$(secaudit_container_ids)" ]; then
        secaudit_report_pass "$num" "no running containers (cgroup-parent check not applicable)"
        return 0
    fi
    hits=$(secaudit_inspect_fmt '{{.Id}} CgroupParent={{.HostConfig.CgroupParent}}' | grep -vE 'CgroupParent=$|CgroupParent=<no value>' | tr '\n' ' ')
    if [ -n "$hits" ]; then
        secaudit_report_fail "$num" "custom CgroupParent is set (${hits})"
    else
        secaudit_report_pass "$num" "containers use the default cgroup parent (daemon cgroup-parent=${parent:-empty})"
    fi
}

secaudit_check_nnp_containers() {
    local num="$1"
    shift
    local hits
    if ! secaudit_info_ok; then
        secaudit_report_fail "$num" "daemon is not reachable; cannot inspect no-new-privileges"
        return 0
    fi
    if [ -z "$(secaudit_container_ids)" ]; then
        secaudit_report_pass "$num" "no running containers (no-new-privileges check not applicable)"
        return 0
    fi
    hits=$(secaudit_inspect_fmt '{{.Id}} {{json .HostConfig.SecurityOpt}}' | grep -vi 'no-new-privileges' | tr '\n' ' ')
    if [ -n "$hits" ]; then
        secaudit_report_fail "$num" "containers without SecurityOpt no-new-privileges"
    else
        secaudit_report_pass "$num" "running containers set no-new-privileges"
    fi
}

secaudit_check_default_bridge() {
    local num="$1"
    shift
    local hits id mode nets
    if ! secaudit_info_ok; then
        secaudit_report_fail "$num" "daemon is not reachable; cannot inspect networks"
        return 0
    fi
    if [ -z "$(secaudit_container_ids)" ]; then
        secaudit_report_pass "$num" "no running containers (default-bridge check not applicable)"
        return 0
    fi
    hits=""
    while read -r id; do
        [ -n "$id" ] || continue
        mode=$(secaudit_exec_with_timeout 8 docker inspect --format '{{.HostConfig.NetworkMode}}' "$id" 2>/dev/null)
        nets=$(secaudit_exec_with_timeout 8 docker inspect --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$id" 2>/dev/null)
        if [ "$mode" = "bridge" ] || printf '%s' "$nets" | grep -qw bridge; then
            hits="${hits} ${id:0:12}"
        fi
    done < <(secaudit_container_ids)
    if [ -n "$hits" ]; then
        secaudit_report_fail "$num" "containers attached to the default docker0/bridge network (${hits# })"
    else
        secaudit_report_pass "$num" "running containers use user-defined networks (not docker0)"
    fi
}

secaudit_check_userns_mode() {
    local num="$1"
    shift
    local hits
    if ! secaudit_info_ok; then
        secaudit_report_fail "$num" "daemon is not reachable; cannot inspect UsernsMode"
        return 0
    fi
    if [ -z "$(secaudit_container_ids)" ]; then
        secaudit_report_pass "$num" "no running containers (userns check not applicable)"
        return 0
    fi
    hits=$(secaudit_inspect_fmt '{{.Id}} UsernsMode={{.HostConfig.UsernsMode}}' | grep 'UsernsMode=host' | tr '\n' ' ')
    if [ -n "$hits" ]; then
        secaudit_report_fail "$num" "host user namespace is shared"
    else
        secaudit_report_pass "$num" "host user namespace is not shared"
    fi
}

secaudit_check_sock_mount() {
    local num="$1"
    shift
    local hits
    if ! secaudit_info_ok; then
        secaudit_report_fail "$num" "daemon is not reachable; cannot inspect docker.sock mounts"
        return 0
    fi
    if [ -z "$(secaudit_container_ids)" ]; then
        secaudit_report_pass "$num" "no running containers (socket-mount check not applicable)"
        return 0
    fi
    hits=$(secaudit_inspect_fmt '{{.Id}} {{range .Mounts}}{{.Source}}->{{.Destination}};{{end}}' | grep -Fi 'docker.sock' | tr '\n' ' ')
    if [ -n "$hits" ]; then
        secaudit_report_fail "$num" "docker.sock is mounted into container(s)"
    else
        secaudit_report_pass "$num" "docker.sock is not mounted into containers"
    fi
}

secaudit_check_swarm_listen() {
    local num="$1"
    shift
    local hits
    if ! secaudit_swarm_active; then
        secaudit_report_pass "$num" "Swarm is inactive (listen-addr check not applicable)"
        return 0
    fi
    if secaudit_have_bin ss; then
        hits=$(ss -Htan 2>/dev/null | grep -E ':2377|:7946|:4789' | grep -vE '127\.0\.0\.1|\[::1\]' | tr '\n' ' ')
    elif secaudit_have_bin netstat; then
        hits=$(netstat -tan 2>/dev/null | grep -E ':2377|:7946|:4789' | grep -vE '127\.0\.0\.1|::1' | tr '\n' ' ')
    else
        hits=""
    fi
    if [ -n "$hits" ]; then
        secaudit_report_fail "$num" "Swarm control ports listen beyond localhost (${hits})"
    else
        secaudit_report_pass "$num" "Swarm ports are not broadly bound"
    fi
}

secaudit_check_overlay_crypto() {
    local num="$1"
    shift
    local nets enc
    if ! secaudit_swarm_active; then
        secaudit_report_pass "$num" "Swarm is inactive (overlay encryption check not applicable)"
        return 0
    fi
    nets=$(secaudit_exec_with_timeout 8 docker network ls --filter driver=overlay -q 2>/dev/null || true)
    if [ -z "$nets" ]; then
        secaudit_report_pass "$num" "no overlay networks"
        return 0
    fi
    enc=$(printf '%s' "$nets" | while read -r n; do
        [ -n "$n" ] || continue
        secaudit_exec_with_timeout 8 docker network inspect --format '{{.Name}} encrypted={{index .Options "encrypted"}}' "$n" 2>/dev/null
    done | tr '\n' ' ')
    if printf '%s' "$enc" | grep -qi 'encrypted=false\|encrypted=<no value>\|encrypted=$'; then
        secaudit_report_fail "$num" "unencrypted overlay networks (${enc})"
    else
        secaudit_report_pass "$num" "overlay networks request encryption (${enc})"
    fi
}

secaudit_check_swarm_secrets() {
    local num="$1"
    shift
    local n
    if ! secaudit_swarm_active; then
        secaudit_report_pass "$num" "Swarm is inactive (secrets check not applicable)"
        return 0
    fi
    n=$(secaudit_exec_with_timeout 8 docker secret ls -q 2>/dev/null | wc -l | tr -d ' ')
    if [ "${n:-0}" -gt 0 ] 2>/dev/null; then
        secaudit_report_pass "$num" "Docker secrets are in use (${n})"
    else
        secaudit_report_fail "$num" "no Docker secrets are defined in the swarm"
    fi
}

secaudit_check_autolock() {
    local num="$1"
    shift
    local al
    if ! secaudit_swarm_active; then
        secaudit_report_pass "$num" "Swarm is inactive (autolock check not applicable)"
        return 0
    fi
    al=$(secaudit_info_get Swarm Cluster Spec EncryptionConfig AutoLockManagers 2>/dev/null || true)
    if [ "$al" = "true" ]; then
        secaudit_report_pass "$num" "Swarm AutoLockManagers is enabled"
    else
        secaudit_report_fail "$num" "Swarm AutoLockManagers is ${al:-false}"
    fi
}

secaudit_check_autolock_rotate() {
    local num="$1"
    shift
    if ! secaudit_swarm_active; then
        secaudit_report_pass "$num" "Swarm is inactive (autolock rotation check not applicable)"
        return 0
    fi
    secaudit_report_pass "$num" "autolock key rotation is an operational control (unlock keys must be rotated out of band)"
}

secaudit_check_node_cert_expiry() {
    local num="$1"
    shift
    local exp
    if ! secaudit_swarm_active; then
        secaudit_report_pass "$num" "Swarm is inactive (node cert expiry check not applicable)"
        return 0
    fi
    exp=$(secaudit_info_get Swarm Cluster Spec CAConfig NodeCertExpiry 2>/dev/null || true)
    if [ -n "$exp" ] && [ "$exp" != "0" ] && [ "$exp" != "0s" ]; then
        secaudit_report_pass "$num" "node certificate expiry is configured (${exp})"
    else
        secaudit_report_fail "$num" "node certificate expiry is not reported"
    fi
}

secaudit_check_ca_rotate() {
    local num="$1"
    shift
    local crt birth change
    if ! secaudit_swarm_active; then
        secaudit_report_pass "$num" "Swarm is inactive (CA rotation check not applicable)"
        return 0
    fi
    crt="/var/lib/docker/swarm/certificates/swarm-root-ca.crt"
    if [ ! -f "$crt" ]; then
        secaudit_report_fail "$num" "swarm CA file ${crt} is missing"
        return 0
    fi
    birth=$(stat -c '%W' "$crt" 2>/dev/null || printf '%s' "0")
    change=$(stat -c '%Z' "$crt" 2>/dev/null || printf '%s' "0")
    if [ "$birth" != "0" ] && [ "$birth" != "-1" ] && [ "$birth" != "$change" ]; then
        secaudit_report_pass "$num" "swarm CA mtime differs from birth (possible rotation)"
    else
        secaudit_report_fail "$num" "swarm CA rotation not evident (birth=${birth} change=${change})"
    fi
}

secaudit_check_swarm_datapath() {
    local num="$1"
    shift
    local addr data
    if ! secaudit_swarm_active; then
        secaudit_report_pass "$num" "Swarm is inactive (data-path check not applicable)"
        return 0
    fi
    addr=$(secaudit_info_get Swarm NodeAddr 2>/dev/null || true)
    data=$(secaudit_exec_with_timeout 8 docker info --format '{{.Swarm.DataPathPort}} {{.Swarm.RemoteManagers}}' 2>/dev/null || true)
    if [ -n "$addr" ] || [ -n "$data" ]; then
        secaudit_report_pass "$num" "swarm addressing visible (NodeAddr=${addr:-n/a} ${data})"
    else
        secaudit_report_fail "$num" "cannot inspect swarm advertise/data-path addresses"
    fi
}

secaudit_check_host_hardening() {
    local num="$1"
    shift
    local ssh_ok=0 fw_ok=0 live ipf
    if grep -qiE '^[[:space:]]*PermitRootLogin[[:space:]]+no' /etc/ssh/sshd_config 2>/dev/null; then
        ssh_ok=1
    elif secaudit_have_bin sshd && sshd -T 2>/dev/null | awk 'tolower($1)=="permitrootlogin" {print $2}' | grep -qi '^no$'; then
        ssh_ok=1
    fi
    if secaudit_have_bin ufw && ufw status 2>/dev/null | grep -qi 'Status: active'; then
        fw_ok=1
    fi
    if secaudit_have_bin firewall-cmd && firewall-cmd --state 2>/dev/null | grep -qi running; then
        fw_ok=1
    fi
    if secaudit_have_bin nft && [ "$(nft list ruleset 2>/dev/null | wc -l | tr -d ' ')" -gt 3 ] 2>/dev/null; then
        fw_ok=1
    fi
    if secaudit_have_bin iptables && iptables -S 2>/dev/null | grep -qE '^-A'; then
        fw_ok=1
    fi
    live=$(secaudit_merged_val "live-restore")
    [ -n "$live" ] || live=$(secaudit_info_get LiveRestoreEnabled 2>/dev/null || true)
    ipf=$(secaudit_info_get IPv4Forwarding 2>/dev/null || true)
    if [ "$ssh_ok" -eq 1 ] && [ "$fw_ok" -eq 1 ]; then
        secaudit_report_pass "$num" "host hardening present (PermitRootLogin no, firewall active, live-restore=${live:-n/a} ip-forward=${ipf:-n/a})"
    else
        secaudit_report_fail "$num" "host hardening incomplete (ssh_root_denied=${ssh_ok} firewall=${fw_ok} live-restore=${live:-n/a})"
    fi
}

secaudit_check_default_ulimits() {
    local num="$1"
    shift
    local ul
    ul=$(secaudit_info_get DefaultUlimits 2>/dev/null || true)
    [ -n "$ul" ] || ul=$(secaudit_merged_val "default-ulimits")
    [ -n "$ul" ] || ul=$(secaudit_daemon_val "default-ulimits")
    if [ -n "$ul" ] && [ "$ul" != "null" ] && [ "$ul" != "[]" ]; then
        secaudit_report_pass "$num" "default-ulimits are configured (${ul})"
    else
        secaudit_report_fail "$num" "default-ulimits are not configured"
    fi
}

secaudit_check_userns_remap() {
    local num="$1"
    shift
    local sec remap subu subg
    sec=$(secaudit_info_get SecurityOptions 2>/dev/null || true)
    remap=$(secaudit_merged_val "userns-remap")
    [ -n "$remap" ] || remap=$(secaudit_daemon_val "userns-remap")
    subu=""; subg=""
    [ -s /etc/subuid ] && subu="subuid"
    [ -s /etc/subgid ] && subg="subgid"
    if printf '%s' "$sec" | grep -qi userns; then
        secaudit_report_pass "$num" "user namespace remapping is enabled (userns-remap=${remap:-info} ${subu} ${subg})"
    elif [ -n "$remap" ] && [ "$remap" != "null" ]; then
        secaudit_report_pass "$num" "userns-remap is set (${remap}) ${subu} ${subg}"
    else
        secaudit_report_fail "$num" "userns-remap is not enabled (need --userns-remap and /etc/subuid,/etc/subgid)"
    fi
}

secaudit_check_cgroup_driver() {
    local num="$1"
    shift
    local drv parent
    drv=$(secaudit_info_get CgroupDriver 2>/dev/null || true)
    parent=$(secaudit_merged_val "cgroup-parent")
    [ -n "$parent" ] || parent=$(secaudit_daemon_val "cgroup-parent")
    case "$drv" in
        systemd|cgroupfs)
            if [ -z "$parent" ] || [ "$parent" = "null" ]; then
                secaudit_report_pass "$num" "CgroupDriver=${drv} with default cgroup-parent"
            else
                secaudit_report_pass "$num" "CgroupDriver=${drv} cgroup-parent=${parent}"
            fi
            ;;
        *)
            secaudit_report_fail "$num" "CgroupDriver is unset or unexpected (${drv:-empty})"
            ;;
    esac
}

secaudit_check_basesize() {
    local num="$1"
    shift
    local st drv
    drv=$(secaudit_info_get Driver 2>/dev/null || true)
    st=$(secaudit_info_get DriverStatus 2>/dev/null || true)
    if printf '%s' "$_DOCKER_CMDLINE $_DOCKER_DAEMON_BLOB $_DOCKER_UNIT_BLOB" | grep -qi 'dm.basesize'; then
        secaudit_report_fail "$num" "dm.basesize is explicitly set (storage-opt)"
        return 0
    fi
    if printf '%s' "$st" | grep -qiE 'Base Device Size|dm.basesize'; then
        if printf '%s' "$st" | grep -qiE '10[[:space:]]*GB|10G'; then
            secaudit_report_pass "$num" "base device size remains at the 10GB default"
        else
            secaudit_report_fail "$num" "base device size appears customized (${st})"
        fi
        return 0
    fi
    secaudit_report_pass "$num" "dm.basesize not applied (driver=${drv:-unknown})"
}

secaudit_check_setuid_images() {
    local num="$1"
    shift
    local img cnt
    img=$(secaudit_pick_image || true)
    if [ -z "$img" ]; then
        secaudit_report_pass "$num" "no local images to scan for setuid/setgid"
        return 0
    fi
    cnt=$(secaudit_exec_with_timeout 60 docker run --rm --network none --read-only --tmpfs /tmp "$img" \
        sh -c 'find / -xdev -perm /6000 -type f 2>/dev/null | wc -l' 2>/dev/null | tr -d ' ')
    if [ "$cnt" = "0" ]; then
        secaudit_report_pass "$num" "no setuid/setgid files in sample image ${img}"
    elif [ -n "$cnt" ] && printf '%s' "$cnt" | grep -qE '^[0-9]+$'; then
        secaudit_report_fail "$num" "setuid/setgid files present in ${img} (count=${cnt})"
    else
        secaudit_report_fail "$num" "unable to scan setuid/setgid in ${img}"
    fi
}

secaudit_check_pkg_verify() {
    local num="$1"
    shift
    local img ok=0
    img=$(secaudit_pick_image || true)
    if [ -z "$img" ]; then
        secaudit_report_pass "$num" "no local images to verify package signatures"
        return 0
    fi
    if secaudit_exec_with_timeout 60 docker run --rm --network none "$img" sh -c \
        'command -v rpm >/dev/null && rpm -qa --qf "%{SIGPGP:pgpsig}\n" 2>/dev/null | grep -q "Key ID"' 2>/dev/null; then
        ok=1
    fi
    if [ "$ok" -eq 0 ] && secaudit_exec_with_timeout 60 docker run --rm --network none "$img" sh -c \
        'command -v apk >/dev/null && test -f /lib/apk/db/installed' 2>/dev/null; then
        ok=1
    fi
    if [ "$ok" -eq 0 ] && secaudit_exec_with_timeout 60 docker run --rm --network none "$img" sh -c \
        'command -v dpkg >/dev/null && dpkg -s dash >/dev/null 2>&1' 2>/dev/null; then
        ok=1
    fi
    if [ "$ok" -eq 1 ]; then
        secaudit_report_pass "$num" "package metadata is present on sample image ${img}"
    else
        secaudit_report_fail "$num" "unable to confirm signed/verified packages on ${img}"
    fi
}

secaudit_check_signed_images() {
    local num="$1"
    shift
    local img unsigned="" n=0
    if ! secaudit_info_ok; then
        secaudit_report_fail "$num" "daemon is not reachable; cannot inspect image trust"
        return 0
    fi
    while read -r img; do
        [ -n "$img" ] || continue
        n=$((n + 1))
        if secaudit_exec_with_timeout 12 docker trust inspect --pretty "$img" 2>/dev/null | grep -q 'Signed'; then
            continue
        fi
        unsigned="${unsigned} ${img}"
    done < <(secaudit_exec_with_timeout 8 docker ps --format '{{.Image}}' 2>/dev/null | sort -u)
    if [ "$n" -eq 0 ]; then
        secaudit_report_pass "$num" "no running containers; image signature check not applicable"
    elif [ -z "$unsigned" ]; then
        secaudit_report_pass "$num" "images used by running containers have trust metadata"
    else
        secaudit_report_fail "$num" "unsigned images in use (${unsigned# })"
    fi
}

secaudit_check_published_ports() {
    local num="$1"
    shift
    local hits
    if ! secaudit_info_ok; then
        secaudit_report_fail "$num" "daemon is not reachable; cannot inspect published ports"
        return 0
    fi
    hits=$(secaudit_exec_with_timeout 8 docker ps --format '{{.ID}} {{.Ports}}' 2>/dev/null | grep -E '0\.0\.0\.0:|:::' || true)
    if [ -n "$hits" ]; then
        secaudit_report_fail "$num" "unrestricted published ports detected ($(secaudit_squash_ws "$hits"))"
    else
        secaudit_report_pass "$num" "no 0.0.0.0/::: published ports on running containers"
    fi
}

# --- runners (RULE1-98 sequential) ---
secaudit_skip_all_rules() {
    local n=1
    while [ "$n" -le "$_DOCKER_RULE_COUNT" ]; do
        secaudit_report_skip "$n" "docker not present"
        n=$((n + 1))
    done
}

secaudit_run_host_layout() {
    # RULE1-3
    secaudit_check_data_partition 1
    secaudit_check_data_mountpoint 2
    secaudit_check_docker_group 3
}

secaudit_run_audit_watches() {
    # RULE4-19
    secaudit_check_audit_watch 4 dockerd "Docker daemon"
    secaudit_check_audit_watch 5 /run/containerd "/run/containerd"
    secaudit_check_audit_watch 6 /var/lib/docker "/var/lib/docker"
    secaudit_check_audit_watch 7 /etc/docker "/etc/docker"
    secaudit_check_audit_watch 8 docker.service "docker.service"
    secaudit_check_audit_watch 9 containerd.sock "containerd.sock"
    secaudit_check_audit_watch 10 docker.sock "docker.sock"
    secaudit_check_audit_watch 11 /etc/default/docker "/etc/default/docker"
    secaudit_check_audit_watch 12 /etc/docker/daemon.json "/etc/docker/daemon.json"
    secaudit_check_audit_watch 13 /etc/containerd/config.toml "/etc/containerd/config.toml"
    secaudit_check_audit_watch 14 /etc/sysconfig/docker "/etc/sysconfig/docker"
    secaudit_check_audit_watch 15 /usr/bin/containerd "/usr/bin/containerd"
    secaudit_check_audit_watch 16 /usr/bin/containerd-shim "/usr/bin/containerd-shim"
    secaudit_check_audit_watch 17 /usr/bin/containerd-shim-runc-v1 "/usr/bin/containerd-shim-runc-v1"
    secaudit_check_audit_watch 18 /usr/bin/containerd-shim-runc-v2 "/usr/bin/containerd-shim-runc-v2"
    secaudit_check_audit_watch 19 /usr/bin/runc "/usr/bin/runc"
}

secaudit_run_daemon_config() {
    # RULE20-33
    secaudit_check_engine_version 20
    secaudit_check_rootless_daemon 21
    secaudit_check_icc_restricted 22
    secaudit_check_log_level 23
    secaudit_check_iptables_enabled 24
    secaudit_check_insecure_registries 25
    secaudit_check_storage_driver 26
    secaudit_check_tls_auth 27
    secaudit_check_authz_plugins 28
    secaudit_check_log_driver 29
    secaudit_check_no_new_priv_daemon 30
    secaudit_check_userland_proxy 31
    secaudit_check_seccomp_daemon 32
    secaudit_check_experimental 33
}

secaudit_run_file_perms() {
    # RULE34-57
    local svc sock
    svc="${_DOCKER_SVC_FILE:-/usr/lib/systemd/system/docker.service}"
    sock="${_DOCKER_SOCK_UNIT:-/usr/lib/systemd/system/docker.socket}"
    secaudit_check_path_owner 34 "$svc" root:root "docker.service"
    secaudit_check_path_mode 35 "$svc" 644 "docker.service"
    secaudit_check_path_owner 36 "$sock" root:root "docker.socket"
    secaudit_check_path_mode 37 "$sock" 644 "docker.socket"
    secaudit_check_path_owner 38 /etc/docker root:root "/etc/docker" 1
    secaudit_check_path_mode 39 /etc/docker 755 "/etc/docker" 1
    secaudit_check_cert_tree_owner 40
    secaudit_check_cert_tree_mode 41
    secaudit_check_named_cert 42 ca.pem root:root 444
    secaudit_check_named_cert 43 ca.pem root:root 444
    secaudit_check_named_cert 44 cert.pem root:root 444
    secaudit_check_named_cert 45 cert.pem root:root 444
    secaudit_check_named_cert 46 key.pem root:root 400
    secaudit_check_named_cert 47 key.pem root:root 400
    secaudit_check_path_owner 48 "$_DOCKER_SOCK" root:docker "docker.sock" 1
    secaudit_check_path_mode 49 "$_DOCKER_SOCK" 660 "docker.sock" 1
    secaudit_check_path_owner 50 "$_DOCKER_DAEMON_JSON" root:root "daemon.json"
    secaudit_check_path_mode 51 "$_DOCKER_DAEMON_JSON" 644 "daemon.json"
    secaudit_check_path_owner 52 /etc/default/docker root:root "/etc/default/docker"
    secaudit_check_path_mode 53 /etc/default/docker 644 "/etc/default/docker"
    secaudit_check_path_mode 54 /etc/sysconfig/docker 644 "/etc/sysconfig/docker"
    secaudit_check_path_owner 55 /etc/sysconfig/docker root:root "/etc/sysconfig/docker"
    secaudit_check_path_owner 56 "$_DOCKER_CONTAINERD_SOCK" root:root "containerd.sock"
    secaudit_check_path_mode 57 "$_DOCKER_CONTAINERD_SOCK" 660 "containerd.sock"
}

secaudit_run_container_runtime() {
    # RULE58-81
    secaudit_check_container_users 58
    secaudit_check_content_trust 59
    secaudit_check_apparmor_containers 60
    secaudit_check_selinux_daemon 61
    secaudit_check_capabilities 62
    secaudit_check_privileged 63
    secaudit_check_sensitive_mounts 64
    secaudit_check_sshd_in_containers 65
    secaudit_check_privileged_ports 66
    secaudit_check_readonly_rootfs 67
    secaudit_check_port_bind_iface 68
    secaudit_check_pid_namespace 69
    secaudit_check_ipc_namespace 70
    secaudit_check_host_devices 71
    secaudit_check_mount_propagation 72
    secaudit_check_uts_namespace 73
    secaudit_check_seccomp_containers 74
    secaudit_check_exec_privileged 75
    secaudit_check_exec_root 76
    secaudit_check_cgroup_parent_containers 77
    secaudit_check_nnp_containers 78
    secaudit_check_default_bridge 79
    secaudit_check_userns_mode 80
    secaudit_check_sock_mount 81
}

secaudit_run_swarm_and_host() {
    # RULE82-98
    secaudit_check_swarm_listen 82
    secaudit_check_overlay_crypto 83
    secaudit_check_swarm_secrets 84
    secaudit_check_autolock 85
    secaudit_check_autolock_rotate 86
    secaudit_check_node_cert_expiry 87
    secaudit_check_ca_rotate 88
    secaudit_check_swarm_datapath 89
    secaudit_check_host_hardening 90
    secaudit_check_default_ulimits 91
    secaudit_check_userns_remap 92
    secaudit_check_cgroup_driver 93
    secaudit_check_basesize 94
    secaudit_check_setuid_images 95
    secaudit_check_pkg_verify 96
    secaudit_check_signed_images 97
    secaudit_check_published_ports 98
}

secaudit_bootstrap_docker() {
    if ! secaudit_have_bin docker; then
        secaudit_skip_all_rules
        return 1
    fi

    _DOCKER_INFO_JSON=$(secaudit_collect_info_json || true)
    if [ -n "$_DOCKER_INFO_JSON" ]; then
        _DOCKER_INFO_OK=1
    fi
    _DOCKER_DAEMON_BLOB=$(secaudit_collect_daemon_json || true)
    _DOCKER_PID=$(secaudit_dockerd_pid || true)
    _DOCKER_CMDLINE=$(secaudit_collect_cmdline "$_DOCKER_PID" || true)
    _DOCKER_UNIT_BLOB=$(secaudit_collect_unit_bundle || true)
    _DOCKER_HELP_TEXT=$(secaudit_collect_help_text || true)
    _DOCKER_SVC_FILE=$(secaudit_unit_path docker.service || true)
    _DOCKER_SOCK_UNIT=$(secaudit_unit_path docker.socket || true)
    return 0
}

secaudit_main() {
    if ! secaudit_bootstrap_docker; then
        exit 0
    fi
    secaudit_run_host_layout
    secaudit_run_audit_watches
    secaudit_run_daemon_config
    secaudit_run_file_perms
    secaudit_run_container_runtime
    secaudit_run_swarm_and_host
    exit 0
}

secaudit_main "$@"
