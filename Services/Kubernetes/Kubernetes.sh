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
_KUBE_MANIFEST_DIR="${KUBE_MANIFEST_DIR:-${SECAUDIT_KUBE_MANIFEST_DIR:-/etc/kubernetes/manifests}}"
_KUBE_PKI_DIR="${KUBE_PKI_DIR:-${SECAUDIT_KUBE_PKI_DIR:-/etc/kubernetes/pki}}"
_KUBE_KUBELET_CONF="${KUBE_KUBELET_CONF:-${SECAUDIT_KUBE_KUBELET_CONF:-/etc/kubernetes/kubelet.conf}}"
_KUBE_ADMIN_CONF="${KUBE_ADMIN_CONF:-${SECAUDIT_KUBE_ADMIN_CONF:-/etc/kubernetes/admin.conf}}"
_KUBE_SUPER_ADMIN_CONF="${KUBE_SUPER_ADMIN_CONF:-${SECAUDIT_KUBE_SUPER_ADMIN_CONF:-/etc/kubernetes/super-admin.conf}}"
_KUBE_SCHEDULER_CONF="${KUBE_SCHEDULER_CONF:-${SECAUDIT_KUBE_SCHEDULER_CONF:-/etc/kubernetes/scheduler.conf}}"
_KUBE_CM_CONF="${KUBE_CM_CONF:-${SECAUDIT_KUBE_CM_CONF:-/etc/kubernetes/controller-manager.conf}}"
_KUBE_CNI_DIR="${KUBE_CNI_DIR:-${SECAUDIT_KUBE_CNI_DIR:-/etc/cni/net.d}}"
_KUBE_ETCD_DATA_DEFAULT="${KUBE_ETCD_DATA_DIR:-${SECAUDIT_KUBE_ETCD_DATA_DIR:-/var/lib/etcd}}"
_KUBE_KUBELET_YAML_DEFAULT="/var/lib/kubelet/config.yaml"
_KUBE_KUBELET_YAML_ALT="/var/lib/kubelet/config.yml"
_KUBE_DROPIN_ETC="/etc/systemd/system/kubelet.service.d"
_KUBE_DROPIN_LIB="/usr/lib/systemd/system/kubelet.service.d"
_KUBE_DROPIN_LIB2="/lib/systemd/system/kubelet.service.d"
_KUBE_FIND_CAP="${KUBE_FIND_CAP:-25}"
_KUBE_CMD_CAP="${KUBE_CMD_CAP:-20}"
_KUBE_RULE_COUNT=130
_KUBE_STRONG_TLS="TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305 TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 TLS_RSA_WITH_AES_256_GCM_SHA384 TLS_RSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"

# --- runtime state ---
_KUBE_HOST="$(hostname 2>/dev/null || printf '%s' unknown)"
_KUBE_NODE_KIND="unknown"
_KUBE_KUBECTL=""
_KUBE_KUBECONFIG=""
_KUBE_API_OK=0
_KUBE_MANIFEST_APISERVER=""
_KUBE_MANIFEST_CONTROLLER=""
_KUBE_MANIFEST_SCHEDULER=""
_KUBE_MANIFEST_ETCD=""
_KUBE_KUBELET_YAML=""
_KUBE_KUBELET_DROPIN=""
_KUBE_PROXY_KUBECONFIG=""
_KUBE_PROXY_CONFIG=""
_KUBE_ETCD_DATA=""
_KUBE_CLIENT_CA=""
_KUBE_APISERVER_FLAGS=""
_KUBE_CONTROLLER_FLAGS=""
_KUBE_SCHEDULER_FLAGS=""
_KUBE_ETCD_FLAGS=""
_KUBE_KUBELET_CLI=""
_KUBE_KUBELET_DROPIN_TEXT=""
_KUBE_PROXY_FLAGS=""

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
    printf '%s' "${1-}" | tr '\n\r\t' '   ' | sed -E 's/[[:space:]]+/ /g;s/^ //;s/ $//'
}

secaudit_path_mode_octal() {
    local p="$1"
    if [ -e "$p" ]; then
        stat -c '%a' "$p" 2>/dev/null || stat -Lc '%a' "$p" 2>/dev/null || printf '%s' STAT_ERROR
    else
        printf '%s' MISSING
    fi
}

secaudit_path_owner_pair() {
    local p="$1"
    if [ -e "$p" ]; then
        stat -c '%U:%G' "$p" 2>/dev/null || stat -Lc '%U:%G' "$p" 2>/dev/null || printf '%s' STAT_ERROR
    else
        printf '%s' MISSING
    fi
}

secaudit_path_listing() {
    local p="$1"
    if [ -e "$p" ]; then
        ls -ld "$p" 2>/dev/null | awk '{print $1,$3,$4,$9}' | tr '\n' ' '
    else
        printf '%s' MISSING
    fi
}

secaudit_mode_bits_clear() {
    local mode="$1" mask="${2:-077}"
    [[ "$mode" =~ ^[0-7]+$ ]] || return 1
    (( (8#$mode & 8#$mask) == 0 ))
}

secaudit_as_uint() {
    local v
    v=$(printf '%s' "${1:-0}" | tr -d '[:space:]')
    [[ "$v" =~ ^[0-9]+$ ]] && printf '%s' "$v" || printf '0'
}

secaudit_first_existing() {
    local p
    for p in "$@"; do
        [ -e "$p" ] && { printf '%s' "$p"; return 0; }
    done
    return 1
}

secaudit_first_file() {
    local p
    for p in "$@"; do
        [ -f "$p" ] && { printf '%s' "$p"; return 0; }
    done
    return 1
}

secaudit_csv_has() {
    local csv="$1" needle="$2"
    printf '%s' ",${csv}," | grep -qE ",[[:space:]]*${needle}[[:space:]]*,"
}

secaudit_lower() {
    printf '%s' "${1-}" | tr '[:upper:]' '[:lower:]'
}

# --- discovery ---
secaudit_cluster_present() {
    local p
    for p in kubelet; do
        secaudit_have_bin "$p" && return 0
    done
    for p in /usr/bin/kubelet /usr/local/bin/kubelet; do
        [ -x "$p" ] && return 0
    done
    if secaudit_have_bin pgrep; then
        pgrep -x kubelet >/dev/null 2>&1 && return 0
        pgrep -f '[/]kubelet( |$)' >/dev/null 2>&1 && return 0
    fi
    [ -f "$_KUBE_KUBELET_CONF" ] && return 0
    [ -f "$_KUBE_KUBELET_YAML_DEFAULT" ] && return 0
    [ -f "$_KUBE_ADMIN_CONF" ] && return 0
    [ -d "$_KUBE_MANIFEST_DIR" ] && ls "$_KUBE_MANIFEST_DIR"/*apiserver* "$_KUBE_MANIFEST_DIR"/*etcd* 2>/dev/null | grep -q . && return 0
    if secaudit_have_bin systemctl; then
        systemctl list-unit-files kubelet.service 2>/dev/null | grep -q kubelet && return 0
    fi
    [ -d "$_KUBE_DROPIN_ETC" ] && ls "$_KUBE_DROPIN_ETC"/*.conf 2>/dev/null | grep -q . && return 0
    return 1
}

secaudit_locate_manifest() {
    local stem="$1"
    secaudit_first_file \
        "${_KUBE_MANIFEST_DIR}/${stem}.yaml" \
        "${_KUBE_MANIFEST_DIR}/${stem}.yml" \
        "${_KUBE_MANIFEST_DIR}/${stem}.manifest"
}

secaudit_node_label_blob() {
    local blob="" f
    blob=$(secaudit_live_proc_flags kubelet)
    for f in \
        "${_KUBE_DROPIN_ETC}"/*.conf \
        "${_KUBE_DROPIN_LIB}"/*.conf \
        "${_KUBE_DROPIN_LIB2}"/*.conf \
        /var/lib/kubelet/kubeadm-flags.env \
        /etc/default/kubelet; do
        [ -f "$f" ] && blob="${blob}
$(cat "$f" 2>/dev/null)"
    done
    printf '%s' "$blob"
}

secaudit_classify_node() {
    local labels manifests=0
    _KUBE_MANIFEST_APISERVER=$(secaudit_locate_manifest kube-apiserver || true)
    _KUBE_MANIFEST_CONTROLLER=$(secaudit_locate_manifest kube-controller-manager || true)
    _KUBE_MANIFEST_SCHEDULER=$(secaudit_locate_manifest kube-scheduler || true)
    _KUBE_MANIFEST_ETCD=$(secaudit_locate_manifest etcd || true)
    [ -n "$_KUBE_MANIFEST_APISERVER" ] && manifests=$((manifests + 1))
    [ -n "$_KUBE_MANIFEST_CONTROLLER" ] && manifests=$((manifests + 1))
    [ -n "$_KUBE_MANIFEST_ETCD" ] && manifests=$((manifests + 1))
    [ -n "$_KUBE_MANIFEST_SCHEDULER" ] && manifests=$((manifests + 1))

    labels=$(secaudit_node_label_blob)
    if [ "$manifests" -gt 0 ]; then
        _KUBE_NODE_KIND="control-plane"
    elif [ -f "$_KUBE_ADMIN_CONF" ] && [ -f "${_KUBE_PKI_DIR}/apiserver.crt" ]; then
        _KUBE_NODE_KIND="control-plane"
    elif printf '%s' "$labels" | grep -qiE 'node-role\.kubernetes\.io/(control-plane|master)'; then
        _KUBE_NODE_KIND="control-plane"
    elif [ -f "$_KUBE_KUBELET_CONF" ] || [ -f "$_KUBE_KUBELET_YAML_DEFAULT" ] || secaudit_have_bin kubelet; then
        _KUBE_NODE_KIND="worker"
    else
        _KUBE_NODE_KIND="unknown"
    fi
}

secaudit_on_control_plane() {
    [ "$_KUBE_NODE_KIND" = control-plane ]
}

secaudit_not_control_plane() {
    local num="$1" why="$2"
    if [ "$_KUBE_NODE_KIND" = worker ]; then
        secaudit_report_skip "$num" "${why} is control-plane-only; skipped on worker (host=${_KUBE_HOST})"
        return 0
    fi
    if [ "$_KUBE_NODE_KIND" != control-plane ]; then
        secaudit_report_skip "$num" "${why} is control-plane-only; skipped (role=${_KUBE_NODE_KIND} host=${_KUBE_HOST})"
        return 0
    fi
    return 1
}

# --- YAML / process flag parsers ---
secaudit_static_pod_flags() {
    local manifest="$1"
    [ -f "$manifest" ] || return 0
    awk '
        function dequote(s) {
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", s)
            gsub(/^["'\''"]|["'\''"]$/, "", s)
            return s
        }
        /^[[:space:]]*#/ { next }
        /^[[:space:]]+(command|args):[[:space:]]*\[/ {
            line=$0
            sub(/^[^[]*\[/, "", line)
            sub(/\][[:space:]]*$/, "", line)
            n=split(line, a, /,/)
            for (i=1; i<=n; i++) {
                v=dequote(a[i])
                if (v ~ /^--/) print v
            }
            next
        }
        /^[[:space:]]+(command|args):[[:space:]]*$/ { grab=1; next }
        grab && /^[[:space:]]+-[[:space:]]*/ {
            v=$0
            sub(/^[[:space:]]+-[[:space:]]*/, "", v)
            v=dequote(v)
            if (v ~ /^--/) print v
            next
        }
        grab && /^[[:space:]]+[A-Za-z]/ { grab=0 }
    ' "$manifest" 2>/dev/null
}

secaudit_live_proc_flags() {
    local proc="$1"
    local line
    line=$(ps -eo args= 2>/dev/null | grep -E "[/ ]${proc}( |$)" | grep -v grep | head -1)
    [ -n "$line" ] || return 0
    printf '%s\n' "$line" | awk '
        {
            for (i=1; i<=NF; i++) {
                if ($i ~ /^--/) {
                    f=$i
                    sub(/^--/, "", f)
                    if (f ~ /=/) print f
                    else if ((i+1)<=NF && $(i+1) !~ /^--/) { print f "=" $(i+1); i++ }
                    else print f "=true"
                }
            }
        }
    '
}

secaudit_normalize_flags() {
    sed -E 's/^--//;s/\r$//' | grep -E '^[A-Za-z0-9._-]+(|=.*)$' || true
}

secaudit_merge_component_flags() {
    local manifest="$1" proc="$2"
    local blob=""
    [ -n "$manifest" ] && [ -f "$manifest" ] && blob=$(secaudit_static_pod_flags "$manifest")
    blob="${blob}
$(secaudit_live_proc_flags "$proc")"
    printf '%s\n' "$blob" | secaudit_normalize_flags
}

secaudit_flag_val() {
    local blob="$1" key="$2"
    printf '%s\n' "$blob" | sed -n -E "s/^${key}=//p" | head -1
}

secaudit_flag_present() {
    local blob="$1" key="$2"
    printf '%s\n' "$blob" | grep -qE "^${key}(=|$)"
}

secaudit_plugin_state() {
    local blob="$1" plugin="$2"
    local enable disable
    enable=$(secaudit_flag_val "$blob" enable-admission-plugins)
    disable=$(secaudit_flag_val "$blob" disable-admission-plugins)
    if secaudit_csv_has "$disable" "$plugin"; then
        return 1
    fi
    if secaudit_csv_has "$enable" "$plugin"; then
        return 0
    fi
    return 2
}

secaudit_comp_blob() {
    case "$1" in
        apiserver) printf '%s' "$_KUBE_APISERVER_FLAGS" ;;
        controller) printf '%s' "$_KUBE_CONTROLLER_FLAGS" ;;
        scheduler) printf '%s' "$_KUBE_SCHEDULER_FLAGS" ;;
        etcd) printf '%s' "$_KUBE_ETCD_FLAGS" ;;
        *) return 1 ;;
    esac
}

secaudit_comp_name() {
    case "$1" in
        apiserver) printf '%s' "kube-apiserver" ;;
        controller) printf '%s' "kube-controller-manager" ;;
        scheduler) printf '%s' "kube-scheduler" ;;
        etcd) printf '%s' "etcd" ;;
        *) printf '%s' "$1" ;;
    esac
}

# --- kubelet config merge ---
secaudit_kubelet_dropin_paths() {
    local d
    for d in "$_KUBE_DROPIN_ETC" "$_KUBE_DROPIN_LIB" "$_KUBE_DROPIN_LIB2"; do
        [ -d "$d" ] || continue
        secaudit_exec_with_timeout "$_KUBE_FIND_CAP" find "$d" -maxdepth 1 -type f \( -name '*.conf' -o -name '*.cfg' \) 2>/dev/null
    done
}

secaudit_locate_kubelet_dropin() {
    local f
    for f in \
        "${_KUBE_DROPIN_ETC}/10-kubeadm.conf" \
        "${_KUBE_DROPIN_ETC}/99-default.conf" \
        "${_KUBE_DROPIN_LIB}/10-kubeadm.conf"; do
        [ -f "$f" ] && { printf '%s' "$f"; return 0; }
    done
    secaudit_kubelet_dropin_paths | sort | head -1
}

secaudit_locate_kubelet_yaml() {
    local from_cli from_dropin
    from_cli=$(secaudit_flag_val "$_KUBE_KUBELET_CLI" config)
    [ -n "$from_cli" ] && [ -f "$from_cli" ] && { printf '%s' "$from_cli"; return 0; }
    from_dropin=$(printf '%s' "$_KUBE_KUBELET_DROPIN_TEXT" | grep -oE -- '--config=[^[:space:]]+' | head -1 | sed 's/^--config=//')
    [ -n "$from_dropin" ] && [ -f "$from_dropin" ] && { printf '%s' "$from_dropin"; return 0; }
    from_dropin=$(printf '%s' "$_KUBE_KUBELET_DROPIN_TEXT" | grep -oE 'KUBELET_CONFIG(_FILE)?=[^[:space:]]+' | head -1 | sed 's/.*=//')
    [ -n "$from_dropin" ] && [ -f "$from_dropin" ] && { printf '%s' "$from_dropin"; return 0; }
    secaudit_first_file "$_KUBE_KUBELET_YAML_DEFAULT" "$_KUBE_KUBELET_YAML_ALT"
}

secaudit_yaml_top() {
    local file="$1" key="$2"
    [ -f "$file" ] || return 1
    awk -v key="$key" '
        $0 ~ "^[[:space:]]*" key ":" {
            line=$0
            sub("^[[:space:]]*" key ":[[:space:]]*", "", line)
            gsub(/["'\'']/, "", line)
            gsub(/[[:space:]]+#.*$/, "", line)
            print line
            exit
        }
    ' "$file" 2>/dev/null
}

secaudit_yaml_nested() {
    local file="$1"
    shift
    [ -f "$file" ] || return 1
    awk -v keys="$*" '
        BEGIN { n=split(keys, want, " ") }
        {
            indent=match($0, /[^ ]/)
            if (indent==0) indent=1
            gsub(/\r/, "")
            line=$0
            if (line ~ /^[[:space:]]*#/) next
            name=line
            sub(/^[[:space:]]+/, "", name)
            split(name, kv, ":")
            key=kv[1]
            depth=int((indent-1)/2)+1
            while (sp>=depth) { sp--; }
            sp++
            stack[sp]=key
            path=""
            for (i=1; i<=sp; i++) path=path (i==1?"":".") stack[i]
            wantpath=want[1]
            for (i=2; i<=n; i++) wantpath=wantpath "." want[i]
            if (path==wantpath) {
                val=line
                sub(/^[^:]*:[[:space:]]*/, "", val)
                gsub(/["'\'']/, "", val)
                gsub(/[[:space:]]+#.*$/, "", val)
                print val
                exit
            }
        }
    ' "$file" 2>/dev/null
}

secaudit_kubelet_val() {
    local cli_key="$1" yaml_key="$2"
    local val
    val=$(secaudit_flag_val "$_KUBE_KUBELET_CLI" "$cli_key")
    [ -n "$val" ] && { printf '%s' "$val"; return 0; }
    val=$(printf '%s' "$_KUBE_KUBELET_DROPIN_TEXT" | grep -oE -- "--${cli_key}=[^[:space:]]+" | head -1 | sed "s/^--${cli_key}=//")
    [ -n "$val" ] && { printf '%s' "$val"; return 0; }
    if [ -n "$_KUBE_KUBELET_YAML" ] && [ -f "$_KUBE_KUBELET_YAML" ]; then
        if printf '%s' "$yaml_key" | grep -q '\.'; then
            secaudit_yaml_nested "$_KUBE_KUBELET_YAML" ${yaml_key//./ }
        else
            secaudit_yaml_top "$_KUBE_KUBELET_YAML" "$yaml_key"
        fi
    fi
}

# --- kube-proxy / etcd / CA ---
secaudit_locate_proxy_kubeconfig() {
    local from_cli p
    from_cli=$(secaudit_flag_val "$_KUBE_PROXY_FLAGS" kubeconfig)
    [ -n "$from_cli" ] && [ -f "$from_cli" ] && { printf '%s' "$from_cli"; return 0; }
    for p in \
        /var/lib/kube-proxy/kubeconfig.conf \
        /var/lib/kube-proxy/kubeconfig \
        /etc/kubernetes/proxy.conf \
        /etc/kubernetes/kube-proxy.conf \
        /etc/kubernetes/kubelet-proxy.conf; do
        [ -f "$p" ] && { printf '%s' "$p"; return 0; }
    done
    return 1
}

secaudit_locate_proxy_config() {
    local from_cli p
    from_cli=$(secaudit_flag_val "$_KUBE_PROXY_FLAGS" config)
    [ -n "$from_cli" ] && [ -f "$from_cli" ] && { printf '%s' "$from_cli"; return 0; }
    for p in \
        /var/lib/kube-proxy/config.conf \
        /var/lib/kube-proxy/config.yaml \
        /etc/kubernetes/kube-proxy-config.yaml \
        /etc/kubernetes/kube-proxy.yaml; do
        [ -f "$p" ] && { printf '%s' "$p"; return 0; }
    done
    secaudit_first_file "${_KUBE_MANIFEST_DIR}/kube-proxy.yaml" "${_KUBE_MANIFEST_DIR}/kube-proxy.manifest"
}

secaudit_cilium_dataplane() {
    [ -e /etc/cni/net.d/05-cilium.conflist ] && return 0
    [ -e /etc/cni/net.d/05-cilium.conf ] && return 0
    [ -d /etc/cilium ] && return 0
    [ -S /var/run/cilium/cilium.sock ] && return 0
    secaudit_have_bin cilium && return 0
    return 1
}

secaudit_etcd_data_dir() {
    local d
    d=$(secaudit_flag_val "$_KUBE_ETCD_FLAGS" data-dir)
    [ -n "$d" ] && [ -e "$d" ] && { printf '%s' "$d"; return 0; }
    secaudit_first_existing "$_KUBE_ETCD_DATA_DEFAULT" /var/lib/etcd
}

secaudit_resolve_cni_dir() {
    if [ -d /etc/cni/net.d ]; then
        printf '%s' /etc/cni/net.d
    elif [ -d /etc/kubernetes/cni/net.d ]; then
        printf '%s' /etc/kubernetes/cni/net.d
    else
        printf '%s' "$_KUBE_CNI_DIR"
    fi
}

# --- openssl / PKI ---
secaudit_have_openssl() { secaudit_have_bin openssl; }

secaudit_cert_alive() {
    local f="$1"
    secaudit_have_openssl || return 2
    openssl x509 -in "$f" -noout -checkend 0 >/dev/null 2>&1
}

secaudit_cert_subject() {
    local f="$1"
    secaudit_have_openssl || return 1
    openssl x509 -in "$f" -noout -subject -issuer 2>/dev/null | secaudit_squash_ws
}

secaudit_cert_fingerprint() {
    local f="$1"
    secaudit_have_openssl || return 1
    openssl x509 -in "$f" -noout -fingerprint -sha256 2>/dev/null | sed 's/^.*=//'
}

secaudit_key_looks_private() {
    grep -qE 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|BEGIN PRIVATE KEY' "$1" 2>/dev/null
}

# --- kubectl ---
secaudit_locate_kubectl() {
    local p
    if secaudit_have_bin kubectl; then
        command -v kubectl
        return 0
    fi
    for p in /usr/bin/kubectl /usr/local/bin/kubectl /usr/local/sbin/kubectl; do
        [ -x "$p" ] && { printf '%s' "$p"; return 0; }
    done
    return 1
}

secaudit_locate_kubeconfig() {
    local p
    [ -n "${KUBECONFIG:-}" ] && [ -f "${KUBECONFIG}" ] && { printf '%s' "$KUBECONFIG"; return 0; }
    for p in \
        "$_KUBE_ADMIN_CONF" \
        "$_KUBE_SUPER_ADMIN_CONF" \
        /root/.kube/config \
        /etc/kubernetes/admin.conf \
        "${HOME}/.kube/config"; do
        [ -f "$p" ] && { printf '%s' "$p"; return 0; }
    done
    return 1
}

secaudit_api_ok() { [ "$_KUBE_API_OK" = 1 ]; }

secaudit_have_python() { secaudit_have_bin python3; }

secaudit_no_api() {
    local num="$1" why="$2"
    if ! secaudit_api_ok; then
        secaudit_report_skip "$num" "${why} needs kubectl+kubeconfig (kubectl=${_KUBE_KUBECTL:-none} kubeconfig=${_KUBE_KUBECONFIG:-none} role=${_KUBE_NODE_KIND})"
        return 0
    fi
    return 1
}

secaudit_no_python() {
    local num="$1" why="$2"
    if ! secaudit_have_python; then
        secaudit_report_skip "$num" "${why} needs python3 to parse kubectl JSON"
        return 0
    fi
    return 1
}

secaudit_kubectl() {
    [ -n "$_KUBE_KUBECTL" ] && [ -n "$_KUBE_KUBECONFIG" ] || return 1
    secaudit_exec_with_timeout "$_KUBE_CMD_CAP" env KUBECONFIG="$_KUBE_KUBECONFIG" "$_KUBE_KUBECTL" "$@"
}

secaudit_probe_api() {
    _KUBE_KUBECTL=$(secaudit_locate_kubectl || true)
    _KUBE_KUBECONFIG=$(secaudit_locate_kubeconfig || true)
    _KUBE_API_OK=0
    [ -n "$_KUBE_KUBECTL" ] || return 1
    [ -n "$_KUBE_KUBECONFIG" ] || return 1
    if secaudit_kubectl get --raw=/readyz >/dev/null 2>&1 \
        || secaudit_kubectl cluster-info >/dev/null 2>&1 \
        || secaudit_kubectl get ns >/dev/null 2>&1; then
        _KUBE_API_OK=1
        return 0
    fi
    return 1
}

# --- generic file / flag checks ---
secaudit_check_path_mode() {
    local num="$1" path="$2" desc="$3" mask="${4:-077}"
    local mode own
    mode=$(secaudit_path_mode_octal "$path")
    own=$(secaudit_path_owner_pair "$path")
    if [ "$mode" = MISSING ]; then
        secaudit_report_fail "$num" "${desc}: ${path} is missing"
        return 0
    fi
    if [ "$mode" = STAT_ERROR ]; then
        secaudit_report_fail "$num" "${desc}: cannot stat ${path}"
        return 0
    fi
    if secaudit_mode_bits_clear "$mode" "$mask"; then
        secaudit_report_pass "$num" "${desc}: ${path} mode=${mode} owner=${own} $(secaudit_path_listing "$path")"
    else
        secaudit_report_fail "$num" "${desc}: ${path} mode=${mode} owner=${own}, expected no group/other bits (mask ${mask})"
    fi
}

secaudit_check_path_owner() {
    local num="$1" path="$2" want="$3" desc="$4"
    local own
    own=$(secaudit_path_owner_pair "$path")
    if [ "$own" = MISSING ]; then
        secaudit_report_fail "$num" "${desc}: ${path} is missing"
        return 0
    fi
    if [ "$own" = "$want" ]; then
        secaudit_report_pass "$num" "${desc}: ${path} owner=${own}"
    else
        secaudit_report_fail "$num" "${desc}: ${path} owner=${own}, expected ${want}"
    fi
}

secaudit_check_plane_mode() {
    local num="$1" path="$2" desc="$3"
    secaudit_not_control_plane "$num" "$desc" && return 0
    secaudit_check_path_mode "$num" "$path" "$desc" 077
}

secaudit_check_plane_owner() {
    local num="$1" path="$2" want="$3" desc="$4"
    secaudit_not_control_plane "$num" "$desc" && return 0
    secaudit_check_path_owner "$num" "$path" "$want" "$desc"
}

secaudit_check_static_pod_mode() {
    local num="$1" path="$2" component="$3"
    local mode own flags
    secaudit_not_control_plane "$num" "${component} static pod permissions" && return 0
    if [ -z "$path" ] || [ ! -f "$path" ]; then
        secaudit_report_fail "$num" "${component} static pod manifest is missing under ${_KUBE_MANIFEST_DIR}"
        return 0
    fi
    mode=$(secaudit_path_mode_octal "$path")
    own=$(secaudit_path_owner_pair "$path")
    flags=$(secaudit_static_pod_flags "$path" | wc -l | tr -d ' ')
    if ! secaudit_mode_bits_clear "$mode" 077; then
        secaudit_report_fail "$num" "${component} manifest ${path} mode=${mode} owner=${own}, expected 600 or more restrictive"
        return 0
    fi
    if grep -qE "kind:[[:space:]]*Pod" "$path" 2>/dev/null && [ "$(secaudit_as_uint "$flags")" -gt 0 ]; then
        secaudit_report_pass "$num" "${component} manifest ${path} mode=${mode} owner=${own} kind=Pod flags=${flags}"
    elif grep -qE "kind:[[:space:]]*Pod" "$path" 2>/dev/null; then
        secaudit_report_pass "$num" "${component} manifest ${path} mode=${mode} owner=${own} kind=Pod (flags via args/process)"
    else
        secaudit_report_fail "$num" "${component} manifest ${path} mode=${mode} but YAML is not a Pod spec"
    fi
}

secaudit_check_static_pod_owner() {
    local num="$1" path="$2" component="$3"
    secaudit_not_control_plane "$num" "${component} static pod ownership" && return 0
    if [ -z "$path" ] || [ ! -f "$path" ]; then
        secaudit_report_fail "$num" "${component} static pod manifest is missing under ${_KUBE_MANIFEST_DIR}"
        return 0
    fi
    secaudit_check_path_owner "$num" "$path" "root:root" "${component} static pod manifest"
}

secaudit_check_dir_files_mode() {
    local num="$1" dir="$2" desc="$3"
    local f mode bad="" count=0
    secaudit_not_control_plane "$num" "$desc" && return 0
    if [ ! -d "$dir" ]; then
        secaudit_report_fail "$num" "${desc}: directory ${dir} is missing"
        return 0
    fi
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        count=$((count + 1))
        mode=$(secaudit_path_mode_octal "$f")
        secaudit_mode_bits_clear "$mode" 077 || bad="${bad}${f}(mode=${mode}) "
    done < <(secaudit_exec_with_timeout "$_KUBE_FIND_CAP" find "$dir" -type f 2>/dev/null)
    if [ "$count" -eq 0 ]; then
        secaudit_report_fail "$num" "${desc}: no files under ${dir}"
        return 0
    fi
    if [ -z "$bad" ]; then
        secaudit_report_pass "$num" "${desc}: ${count} files under ${dir} have mode 600 or more restrictive"
    else
        secaudit_report_fail "$num" "${desc}: loose permissions: $(secaudit_squash_ws "$bad")"
    fi
}

secaudit_check_dir_files_owner() {
    local num="$1" dir="$2" want="$3" desc="$4"
    local f own bad="" count=0
    secaudit_not_control_plane "$num" "$desc" && return 0
    if [ ! -d "$dir" ]; then
        secaudit_report_fail "$num" "${desc}: directory ${dir} is missing"
        return 0
    fi
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        count=$((count + 1))
        own=$(secaudit_path_owner_pair "$f")
        [ "$own" = "$want" ] || bad="${bad}${f}(${own}) "
    done < <(secaudit_exec_with_timeout "$_KUBE_FIND_CAP" find "$dir" -type f 2>/dev/null)
    if [ "$count" -eq 0 ]; then
        secaudit_report_fail "$num" "${desc}: no files under ${dir}"
        return 0
    fi
    if [ -z "$bad" ]; then
        secaudit_report_pass "$num" "${desc}: ${count} files under ${dir} owned by ${want}"
    else
        secaudit_report_fail "$num" "${desc}: unexpected owners: $(secaudit_squash_ws "$bad")"
    fi
}

secaudit_check_comp_eq() {
    local num="$1" comp="$2" key="$3" expected="$4" desc="$5"
    local blob val
    secaudit_not_control_plane "$num" "$desc" && return 0
    blob=$(secaudit_comp_blob "$comp")
    if [ -z "$blob" ]; then
        secaudit_report_fail "$num" "${desc}: $(secaudit_comp_name "$comp") flags not found in static pod or process"
        return 0
    fi
    val=$(secaudit_flag_val "$blob" "$key")
    if [ "$val" = "$expected" ]; then
        secaudit_report_pass "$num" "${desc}: --${key}=${val}"
    else
        secaudit_report_fail "$num" "${desc}: --${key}=${val:-unset}, expected ${expected}"
    fi
}

secaudit_check_comp_absent() {
    local num="$1" comp="$2" key="$3" desc="$4"
    local blob val
    secaudit_not_control_plane "$num" "$desc" && return 0
    blob=$(secaudit_comp_blob "$comp")
    if [ -z "$blob" ]; then
        secaudit_report_fail "$num" "${desc}: $(secaudit_comp_name "$comp") flags not found in static pod or process"
        return 0
    fi
    if secaudit_flag_present "$blob" "$key"; then
        val=$(secaudit_flag_val "$blob" "$key")
        secaudit_report_fail "$num" "${desc}: forbidden --${key}=${val} is set"
    else
        secaudit_report_pass "$num" "${desc}: --${key} is not set"
    fi
}

secaudit_check_comp_not_true() {
    local num="$1" comp="$2" key="$3" desc="$4"
    local blob val
    secaudit_not_control_plane "$num" "$desc" && return 0
    blob=$(secaudit_comp_blob "$comp")
    if [ -z "$blob" ]; then
        secaudit_report_fail "$num" "${desc}: $(secaudit_comp_name "$comp") flags not found in static pod or process"
        return 0
    fi
    val=$(secaudit_lower "$(secaudit_flag_val "$blob" "$key")")
    if [ "$val" = true ]; then
        secaudit_report_fail "$num" "${desc}: --${key}=true (must not be enabled)"
    else
        secaudit_report_pass "$num" "${desc}: --${key}=${val:-unset/false}"
    fi
}

secaudit_check_admission_on() {
    local num="$1" plugin="$2" desc="$3" default_on="${4:-0}"
    local st enable disable
    secaudit_not_control_plane "$num" "$desc" && return 0
    if [ -z "$_KUBE_APISERVER_FLAGS" ]; then
        secaudit_report_fail "$num" "${desc}: kube-apiserver flags not found"
        return 0
    fi
    enable=$(secaudit_flag_val "$_KUBE_APISERVER_FLAGS" enable-admission-plugins)
    disable=$(secaudit_flag_val "$_KUBE_APISERVER_FLAGS" disable-admission-plugins)
    secaudit_plugin_state "$_KUBE_APISERVER_FLAGS" "$plugin"
    st=$?
    if [ "$st" -eq 0 ]; then
        secaudit_report_pass "$num" "${desc}: ${plugin} is enabled (enable=${enable:-none})"
    elif [ "$st" -eq 1 ]; then
        secaudit_report_fail "$num" "${desc}: ${plugin} is in --disable-admission-plugins (${disable})"
    elif [ "$default_on" = 1 ]; then
        secaudit_report_pass "$num" "${desc}: ${plugin} is a default plugin and is not disabled"
    else
        secaudit_report_fail "$num" "${desc}: ${plugin} is not in --enable-admission-plugins (${enable:-unset})"
    fi
}

secaudit_check_admission_off() {
    local num="$1" plugin="$2" desc="$3"
    local enable
    secaudit_not_control_plane "$num" "$desc" && return 0
    if [ -z "$_KUBE_APISERVER_FLAGS" ]; then
        secaudit_report_fail "$num" "${desc}: kube-apiserver flags not found"
        return 0
    fi
    enable=$(secaudit_flag_val "$_KUBE_APISERVER_FLAGS" enable-admission-plugins)
    if secaudit_csv_has "$enable" "$plugin"; then
        secaudit_report_fail "$num" "${desc}: ${plugin} is enabled (${enable})"
    else
        secaudit_report_pass "$num" "${desc}: ${plugin} is not enabled"
    fi
}

secaudit_authz_modes() {
    secaudit_flag_val "$_KUBE_APISERVER_FLAGS" authorization-mode
}

secaudit_admin_kubeconfig_paths() {
    local p
    for p in "$_KUBE_ADMIN_CONF" "$_KUBE_SUPER_ADMIN_CONF" /root/.kube/config; do
        [ -f "$p" ] && printf '%s\n' "$p"
    done
}

secaudit_weak_ciphers() {
    local suites="$1" s bad=""
    suites=$(printf '%s' "$suites" | tr -d '[]"')
    IFS=', ' read -ra _ciphers <<< "$suites"
    for s in "${_ciphers[@]}"; do
        s=$(secaudit_trim_ws "$s")
        [ -n "$s" ] || continue
        printf '%s' " ${_KUBE_STRONG_TLS} " | grep -q " $s " || bad="${bad}${s} "
    done
    printf '%s' "$bad"
}

# --- control-plane files (RULE1-21) ---
secaudit_check_etcd_datadir_mode() {
    local num="$1" path mode own
    secaudit_not_control_plane "$num" "etcd data directory permissions" && return 0
    path="${_KUBE_ETCD_DATA:-$_KUBE_ETCD_DATA_DEFAULT}"
    mode=$(secaudit_path_mode_octal "$path")
    own=$(secaudit_path_owner_pair "$path")
    if [ "$mode" = MISSING ]; then
        secaudit_report_fail "$num" "etcd data dir ${path} is missing (data-dir flag=$(secaudit_flag_val "$_KUBE_ETCD_FLAGS" data-dir))"
        return 0
    fi
    if secaudit_mode_bits_clear "$mode" 077; then
        secaudit_report_pass "$num" "etcd data dir ${path} mode=${mode} owner=${own} (700 or more restrictive)"
    else
        secaudit_report_fail "$num" "etcd data dir ${path} mode=${mode} owner=${own}, expected 700 or more restrictive"
    fi
}

secaudit_check_etcd_datadir_owner() {
    local num="$1" path own
    secaudit_not_control_plane "$num" "etcd data directory ownership" && return 0
    path="${_KUBE_ETCD_DATA:-$_KUBE_ETCD_DATA_DEFAULT}"
    own=$(secaudit_path_owner_pair "$path")
    if [ "$own" = MISSING ]; then
        secaudit_report_fail "$num" "etcd data dir ${path} is missing"
        return 0
    fi
    if [ "$own" = "etcd:etcd" ]; then
        secaudit_report_pass "$num" "etcd data dir ${path} owner=${own}"
    else
        secaudit_report_fail "$num" "etcd data dir ${path} owner=${own}, expected etcd:etcd"
    fi
}

secaudit_check_admin_kubeconfig_mode() {
    local num="$1" p mode worst="" files="" kube_ok=0
    secaudit_not_control_plane "$num" "admin kubeconfig permissions" && return 0
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        files="${files}${p} "
        mode=$(secaudit_path_mode_octal "$p")
        [ "$mode" = MISSING ] && continue
        if [ -z "$worst" ] || [ "$(secaudit_as_uint "$mode")" -gt "$(secaudit_as_uint "$worst")" ]; then
            worst="$mode"
        fi
        grep -qE 'kind:[[:space:]]*Config|apiVersion:[[:space:]]*v1' "$p" 2>/dev/null && kube_ok=1
    done < <(secaudit_admin_kubeconfig_paths)
    if [ -z "$worst" ]; then
        secaudit_report_fail "$num" "admin kubeconfig not found (${_KUBE_ADMIN_CONF})"
        return 0
    fi
    if secaudit_mode_bits_clear "$worst" 077 && [ "$kube_ok" = 1 ]; then
        secaudit_report_pass "$num" "admin kubeconfig files (${files}) worst-mode=${worst} valid-kubeconfig=yes"
    elif secaudit_mode_bits_clear "$worst" 077; then
        secaudit_report_fail "$num" "admin kubeconfig mode=${worst} but file does not look like a kubeconfig"
    else
        secaudit_report_fail "$num" "admin kubeconfig worst-mode=${worst} files=${files}, expected 600"
    fi
}

secaudit_check_admin_kubeconfig_owner() {
    local num="$1" p
    secaudit_not_control_plane "$num" "admin kubeconfig ownership" && return 0
    p=$(secaudit_admin_kubeconfig_paths | head -1)
    secaudit_check_path_owner "$num" "${p:-$_KUBE_ADMIN_CONF}" "root:root" "admin kubeconfig"
}

secaudit_check_pki_tree_owner() {
    local num="$1" f own bad="" count=0
    secaudit_not_control_plane "$num" "Kubernetes PKI ownership" && return 0
    if [ ! -d "$_KUBE_PKI_DIR" ]; then
        secaudit_report_fail "$num" "PKI directory ${_KUBE_PKI_DIR} is missing"
        return 0
    fi
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        count=$((count + 1))
        own=$(secaudit_path_owner_pair "$f")
        [ "$own" = "root:root" ] || bad="${bad}${f}(${own}) "
    done < <(secaudit_exec_with_timeout "$_KUBE_FIND_CAP" find "$_KUBE_PKI_DIR" -mindepth 1 2>/dev/null)
    if [ "$count" -eq 0 ]; then
        secaudit_report_fail "$num" "PKI tree ${_KUBE_PKI_DIR} is empty"
        return 0
    fi
    if [ -z "$bad" ]; then
        secaudit_report_pass "$num" "PKI tree ${_KUBE_PKI_DIR} (${count} entries) owned by root:root"
    else
        secaudit_report_fail "$num" "non-root PKI owners: $(secaudit_squash_ws "$bad")"
    fi
}

secaudit_check_pki_cert_modes() {
    local num="$1" f mode bad="" expired="" count=0
    secaudit_not_control_plane "$num" "Kubernetes PKI certificate permissions" && return 0
    for f in "${_KUBE_PKI_DIR}"/*.crt "${_KUBE_PKI_DIR}"/etcd/*.crt; do
        [ -f "$f" ] || continue
        count=$((count + 1))
        mode=$(secaudit_path_mode_octal "$f")
        secaudit_mode_bits_clear "$mode" 077 || bad="${bad}${f}(mode=${mode}) "
        if secaudit_have_openssl; then
            if ! secaudit_cert_alive "$f"; then
                expired="${expired}${f} "
            fi
        fi
    done
    if [ "$count" -eq 0 ]; then
        secaudit_report_fail "$num" "no PKI certificates under ${_KUBE_PKI_DIR}"
        return 0
    fi
    if [ -n "$bad" ]; then
        secaudit_report_fail "$num" "PKI certs with loose mode: $(secaudit_squash_ws "$bad")"
        return 0
    fi
    if [ -n "$expired" ]; then
        secaudit_report_fail "$num" "PKI certs expired or unreadable: $(secaudit_squash_ws "$expired")"
        return 0
    fi
    if secaudit_have_openssl; then
        secaudit_report_pass "$num" "${count} PKI certificates are mode 600+ and unexpired (openssl)"
    else
        secaudit_report_pass "$num" "${count} PKI certificates are mode 600+ (openssl not available for expiry)"
    fi
}

secaudit_check_pki_key_modes() {
    local num="$1" f mode bad="" world="" notkey="" count=0
    secaudit_not_control_plane "$num" "Kubernetes PKI key permissions" && return 0
    for f in "${_KUBE_PKI_DIR}"/*.key "${_KUBE_PKI_DIR}"/etcd/*.key; do
        [ -f "$f" ] || continue
        count=$((count + 1))
        mode=$(secaudit_path_mode_octal "$f")
        secaudit_mode_bits_clear "$mode" 077 || bad="${bad}${f}(mode=${mode}) "
        if [[ "$mode" =~ ^[0-7]+$ ]] && (( 8#$mode & 8#004 )); then
            world="${world}${f} "
        fi
        if [ -r "$f" ] && ! secaudit_key_looks_private "$f"; then
            notkey="${notkey}${f} "
        fi
    done
    if [ "$count" -eq 0 ]; then
        secaudit_report_fail "$num" "no PKI keys under ${_KUBE_PKI_DIR}"
        return 0
    fi
    if [ -n "$world" ]; then
        secaudit_report_fail "$num" "world-readable PKI keys: $(secaudit_squash_ws "$world")"
        return 0
    fi
    if [ -n "$bad" ]; then
        secaudit_report_fail "$num" "PKI keys with loose mode: $(secaudit_squash_ws "$bad")"
        return 0
    fi
    if [ -n "$notkey" ]; then
        secaudit_report_fail "$num" "PKI .key files without PRIVATE KEY header: $(secaudit_squash_ws "$notkey")"
        return 0
    fi
    secaudit_report_pass "$num" "${count} PKI keys are mode 600 and not world-readable"
}

# --- apiserver auth / admission (RULE22-35) ---
secaudit_check_kubelet_client_certs() {
    local num="$1" cert key
    secaudit_not_control_plane "$num" "apiserver kubelet client certificate" && return 0
    cert=$(secaudit_flag_val "$_KUBE_APISERVER_FLAGS" kubelet-client-certificate)
    key=$(secaudit_flag_val "$_KUBE_APISERVER_FLAGS" kubelet-client-key)
    if [ -n "$cert" ] && [ -n "$key" ] && [ -f "$cert" ] && [ -f "$key" ]; then
        if secaudit_mode_bits_clear "$(secaudit_path_mode_octal "$key")" 077; then
            secaudit_report_pass "$num" "kubelet client cert=${cert} key=${key} key-mode=$(secaudit_path_mode_octal "$key")"
        else
            secaudit_report_fail "$num" "kubelet client key ${key} mode=$(secaudit_path_mode_octal "$key") is too open"
        fi
    elif [ -n "$cert" ] && [ -n "$key" ]; then
        secaudit_report_fail "$num" "kubelet-client-certificate=${cert} kubelet-client-key=${key} but files are missing"
    else
        secaudit_report_fail "$num" "kubelet-client-certificate/key not set on kube-apiserver"
    fi
}

secaudit_check_kubelet_client_ca() {
    local num="$1" ca
    secaudit_not_control_plane "$num" "apiserver kubelet certificate authority" && return 0
    ca=$(secaudit_flag_val "$_KUBE_APISERVER_FLAGS" kubelet-certificate-authority)
    if [ -z "$ca" ]; then
        secaudit_report_fail "$num" "kubelet-certificate-authority is not set on kube-apiserver"
        return 0
    fi
    if [ ! -f "$ca" ]; then
        secaudit_report_fail "$num" "kubelet-certificate-authority=${ca} is missing"
        return 0
    fi
    if secaudit_have_openssl && ! secaudit_cert_alive "$ca"; then
        secaudit_report_fail "$num" "kubelet-certificate-authority=${ca} is expired"
        return 0
    fi
    secaudit_report_pass "$num" "kubelet-certificate-authority=${ca} $(secaudit_cert_subject "$ca")"
}

secaudit_check_authz_not_alwaysallow() {
    local num="$1" modes
    secaudit_not_control_plane "$num" "apiserver authorization-mode AlwaysAllow" && return 0
    modes=$(secaudit_authz_modes)
    if [ -z "$modes" ]; then
        secaudit_report_fail "$num" "authorization-mode is not set on kube-apiserver"
        return 0
    fi
    if secaudit_csv_has "$modes" AlwaysAllow; then
        secaudit_report_fail "$num" "authorization-mode includes AlwaysAllow (${modes})"
    else
        secaudit_report_pass "$num" "authorization-mode=${modes} (AlwaysAllow absent)"
    fi
}

secaudit_check_authz_includes() {
    local num="$1" want="$2" desc="$3"
    local modes
    secaudit_not_control_plane "$num" "$desc" && return 0
    modes=$(secaudit_authz_modes)
    if secaudit_csv_has "$modes" "$want"; then
        secaudit_report_pass "$num" "authorization-mode includes ${want} (${modes})"
    else
        secaudit_report_fail "$num" "authorization-mode=${modes:-unset} does not include ${want}"
    fi
}

# --- apiserver audit / tls (RULE36-50) ---
secaudit_check_audit_log_path() {
    local num="$1" path
    secaudit_not_control_plane "$num" "apiserver audit-log-path" && return 0
    path=$(secaudit_flag_val "$_KUBE_APISERVER_FLAGS" audit-log-path)
    if [ -z "$path" ]; then
        secaudit_report_fail "$num" "audit-log-path is not set on kube-apiserver"
    else
        secaudit_report_pass "$num" "audit-log-path=${path}"
    fi
}

secaudit_check_audit_log_min() {
    local num="$1" key="$2" min="$3" desc="$4"
    local val
    secaudit_not_control_plane "$num" "$desc" && return 0
    val=$(secaudit_flag_val "$_KUBE_APISERVER_FLAGS" "$key")
    if [ -z "$val" ]; then
        secaudit_report_fail "$num" "${key} is not set"
        return 0
    fi
    if [ "$(secaudit_as_uint "$val")" -ge "$min" ]; then
        secaudit_report_pass "$num" "${key}=${val} (>=${min})"
    else
        secaudit_report_fail "$num" "${key}=${val}, expected ${min} or greater"
    fi
}

secaudit_check_request_timeout() {
    local num="$1" val
    secaudit_not_control_plane "$num" "apiserver request-timeout" && return 0
    val=$(secaudit_flag_val "$_KUBE_APISERVER_FLAGS" request-timeout)
    if [ -z "$val" ]; then
        secaudit_report_pass "$num" "request-timeout is unset (kube-apiserver default 1m0s is acceptable)"
        return 0
    fi
    if printf '%s' "$val" | grep -qE '^-' || [ "$val" = 0 ] || [ "$val" = 0s ]; then
        secaudit_report_fail "$num" "request-timeout=${val} is not an appropriate positive timeout"
        return 0
    fi
    secaudit_report_pass "$num" "request-timeout=${val}"
}

secaudit_check_sa_lookup() {
    local num="$1" val
    secaudit_not_control_plane "$num" "apiserver service-account-lookup" && return 0
    val=$(secaudit_lower "$(secaudit_flag_val "$_KUBE_APISERVER_FLAGS" service-account-lookup)")
    if [ -z "$val" ] || [ "$val" = true ]; then
        secaudit_report_pass "$num" "service-account-lookup=${val:-default-true}"
    else
        secaudit_report_fail "$num" "service-account-lookup=${val}, expected true"
    fi
}

secaudit_check_existing_flag_file() {
    local num="$1" comp="$2" key="$3" desc="$4"
    local blob path
    secaudit_not_control_plane "$num" "$desc" && return 0
    blob=$(secaudit_comp_blob "$comp")
    path=$(secaudit_flag_val "$blob" "$key")
    if [ -z "$path" ]; then
        secaudit_report_fail "$num" "${key} is not set"
        return 0
    fi
    if [ -f "$path" ]; then
        secaudit_report_pass "$num" "${key}=${path} mode=$(secaudit_path_mode_octal "$path")"
    else
        secaudit_report_fail "$num" "${key}=${path} is missing"
    fi
}

secaudit_check_tls_pair() {
    local num="$1" desc="$2" cert_key="$3" key_key="$4" blob="$5" check_expiry="${6:-0}" check_key_mode="${7:-1}"
    local cert key
    secaudit_not_control_plane "$num" "$desc" && return 0
    cert=$(secaudit_flag_val "$blob" "$cert_key")
    key=$(secaudit_flag_val "$blob" "$key_key")
    if [ -z "$cert" ] || [ -z "$key" ] || [ ! -f "$cert" ] || [ ! -f "$key" ]; then
        secaudit_report_fail "$num" "${cert_key}=${cert:-unset} ${key_key}=${key:-unset} (files must exist)"
        return 0
    fi
    if [ "$check_key_mode" = 1 ] && ! secaudit_mode_bits_clear "$(secaudit_path_mode_octal "$key")" 077; then
        secaudit_report_fail "$num" "${key_key} ${key} mode=$(secaudit_path_mode_octal "$key") is too open"
        return 0
    fi
    if [ "$check_expiry" = 1 ] && secaudit_have_openssl && ! secaudit_cert_alive "$cert"; then
        secaudit_report_fail "$num" "${cert_key} ${cert} is expired"
        return 0
    fi
    secaudit_report_pass "$num" "${cert_key}=${cert} ${key_key}=${key} key-mode=$(secaudit_path_mode_octal "$key") $(secaudit_cert_subject "$cert")"
}

secaudit_check_ca_file_flag() {
    local num="$1" key="$2" desc="$3"
    local ca
    secaudit_not_control_plane "$num" "$desc" && return 0
    ca=$(secaudit_flag_val "$_KUBE_APISERVER_FLAGS" "$key")
    if [ -z "$ca" ] || [ ! -f "$ca" ]; then
        secaudit_report_fail "$num" "${key}=${ca:-unset} is missing"
        return 0
    fi
    if secaudit_have_openssl && ! secaudit_cert_alive "$ca"; then
        secaudit_report_fail "$num" "${key}=${ca} is expired"
        return 0
    fi
    secaudit_report_pass "$num" "${key}=${ca} $(secaudit_cert_subject "$ca")"
}

secaudit_check_encryption_providers() {
    local num="$1" path body
    secaudit_not_control_plane "$num" "etcd encryption providers" && return 0
    path=$(secaudit_flag_val "$_KUBE_APISERVER_FLAGS" encryption-provider-config)
    if [ -z "$path" ] || [ ! -f "$path" ]; then
        secaudit_report_fail "$num" "encryption providers: config file missing (${path:-unset})"
        return 0
    fi
    body=$(cat "$path" 2>/dev/null)
    if ! printf '%s' "$body" | grep -qiE 'resources:|[[:space:]]secrets'; then
        secaudit_report_fail "$num" "encryption config ${path} does not mention secrets"
        return 0
    fi
    if printf '%s' "$body" | grep -qiE 'aescbc:|aesgcm:|secretbox:|kms:|kmsv2:'; then
        if printf '%s' "$body" | awk '
            /providers:[[:space:]]*$/ { p=1; next }
            p && /identity:[[:space:]]*(\{\})?[[:space:]]*$/ { id=1; exit }
            p && /(aescbc|aesgcm|secretbox|kms):/ { strong=1; exit }
            p && /^[^[:space:]]/ { p=0 }
            END { exit (strong?0:1) }
        '; then
            secaudit_report_pass "$num" "encryption providers in ${path} include aescbc/aesgcm/secretbox/kms before identity"
        else
            secaudit_report_fail "$num" "encryption config ${path} lists identity first or lacks a strong provider"
        fi
    else
        secaudit_report_fail "$num" "encryption config ${path} has no aescbc/aesgcm/secretbox/kms provider"
    fi
}

secaudit_check_apiserver_ciphers() {
    local num="$1" suites bad
    secaudit_not_control_plane "$num" "apiserver tls-cipher-suites" && return 0
    suites=$(secaudit_flag_val "$_KUBE_APISERVER_FLAGS" tls-cipher-suites)
    if [ -z "$suites" ]; then
        secaudit_report_fail "$num" "tls-cipher-suites is not set on kube-apiserver"
        return 0
    fi
    bad=$(secaudit_weak_ciphers "$suites")
    if [ -n "$bad" ]; then
        secaudit_report_fail "$num" "apiserver cipher suites include weak/unknown entries: $(secaudit_squash_ws "$bad")"
    else
        secaudit_report_pass "$num" "apiserver tls-cipher-suites uses strong suites only"
    fi
}

# --- controller / scheduler (RULE51-59) ---
secaudit_check_terminated_pod_gc() {
    local num="$1" val
    secaudit_not_control_plane "$num" "controller-manager terminated-pod-gc-threshold" && return 0
    val=$(secaudit_flag_val "$_KUBE_CONTROLLER_FLAGS" terminated-pod-gc-threshold)
    if [ -z "$val" ]; then
        secaudit_report_fail "$num" "terminated-pod-gc-threshold is not set"
        return 0
    fi
    if [ "$(secaudit_as_uint "$val")" -gt 0 ]; then
        secaudit_report_pass "$num" "terminated-pod-gc-threshold=${val}"
    else
        secaudit_report_fail "$num" "terminated-pod-gc-threshold=${val} is not a positive integer"
    fi
}

secaudit_check_cm_sa_key() {
    local num="$1" path
    secaudit_not_control_plane "$num" "controller-manager service-account-private-key-file" && return 0
    path=$(secaudit_flag_val "$_KUBE_CONTROLLER_FLAGS" service-account-private-key-file)
    if [ -n "$path" ] && [ -f "$path" ]; then
        if secaudit_mode_bits_clear "$(secaudit_path_mode_octal "$path")" 077; then
            secaudit_report_pass "$num" "service-account-private-key-file=${path} mode=$(secaudit_path_mode_octal "$path")"
        else
            secaudit_report_fail "$num" "service-account-private-key-file ${path} mode=$(secaudit_path_mode_octal "$path") is too open"
        fi
    else
        secaudit_report_fail "$num" "service-account-private-key-file=${path:-unset} is missing"
    fi
}

secaudit_check_cm_root_ca() {
    local num="$1" path
    secaudit_not_control_plane "$num" "controller-manager root-ca-file" && return 0
    path=$(secaudit_flag_val "$_KUBE_CONTROLLER_FLAGS" root-ca-file)
    if [ -n "$path" ] && [ -f "$path" ]; then
        secaudit_report_pass "$num" "root-ca-file=${path} $(secaudit_cert_subject "$path")"
    else
        secaudit_report_fail "$num" "root-ca-file=${path:-unset} is missing"
    fi
}

secaudit_check_cm_rotate_kubelet_cert() {
    local num="$1" feat
    secaudit_not_control_plane "$num" "controller-manager RotateKubeletServerCertificate" && return 0
    feat=$(secaudit_flag_val "$_KUBE_CONTROLLER_FLAGS" feature-gates)
    if printf '%s' "$feat" | grep -qE 'RotateKubeletServerCertificate=true'; then
        secaudit_report_pass "$num" "feature-gates includes RotateKubeletServerCertificate=true"
    elif printf '%s' "$_KUBE_CONTROLLER_FLAGS" | grep -qE 'RotateKubeletServerCertificate=true'; then
        secaudit_report_pass "$num" "RotateKubeletServerCertificate=true is set"
    else
        secaudit_report_fail "$num" "RotateKubeletServerCertificate=true is not set on kube-controller-manager"
    fi
}

# --- etcd (RULE60-66) ---
secaudit_check_etcd_tls_pair() {
    local num="$1" desc="$2" cert_key="$3" key_key="$4" check_expiry="${5:-0}"
    local cert key
    secaudit_not_control_plane "$num" "$desc" && return 0
    cert=$(secaudit_flag_val "$_KUBE_ETCD_FLAGS" "$cert_key")
    key=$(secaudit_flag_val "$_KUBE_ETCD_FLAGS" "$key_key")
    if [ -n "$cert" ] && [ -n "$key" ] && [ -f "$cert" ] && [ -f "$key" ]; then
        if [ "$check_expiry" = 1 ] && secaudit_have_openssl && ! secaudit_cert_alive "$cert"; then
            secaudit_report_fail "$num" "etcd ${cert_key} ${cert} is expired"
            return 0
        fi
        secaudit_report_pass "$num" "etcd ${cert_key}=${cert} ${key_key}=${key} key-mode=$(secaudit_path_mode_octal "$key")"
    else
        secaudit_report_fail "$num" "etcd ${cert_key}=${cert:-unset} ${key_key}=${key:-unset}"
    fi
}

secaudit_check_etcd_unique_ca() {
    local num="$1" etcd_ca k8s_ca fp1 fp2
    secaudit_not_control_plane "$num" "etcd unique Certificate Authority" && return 0
    etcd_ca=$(secaudit_flag_val "$_KUBE_ETCD_FLAGS" trusted-ca-file)
    [ -z "$etcd_ca" ] && etcd_ca=$(secaudit_flag_val "$_KUBE_ETCD_FLAGS" client-ca-file)
    [ -z "$etcd_ca" ] && etcd_ca=$(secaudit_first_file "${_KUBE_PKI_DIR}/etcd/ca.crt")
    k8s_ca=$(secaudit_flag_val "$_KUBE_APISERVER_FLAGS" client-ca-file)
    [ -z "$k8s_ca" ] && k8s_ca=$(secaudit_first_file "${_KUBE_PKI_DIR}/ca.crt")
    if [ -z "$etcd_ca" ] || [ ! -f "$etcd_ca" ]; then
        secaudit_report_fail "$num" "etcd CA file not found (trusted-ca-file/client-ca-file/pki/etcd/ca.crt)"
        return 0
    fi
    if [ -n "$k8s_ca" ] && [ -f "$k8s_ca" ] && secaudit_have_openssl; then
        fp1=$(secaudit_cert_fingerprint "$etcd_ca")
        fp2=$(secaudit_cert_fingerprint "$k8s_ca")
        if [ -n "$fp1" ] && [ "$fp1" = "$fp2" ]; then
            secaudit_report_fail "$num" "etcd CA ${etcd_ca} matches Kubernetes CA ${k8s_ca} (not unique)"
            return 0
        fi
        secaudit_report_pass "$num" "etcd CA ${etcd_ca} is distinct from Kubernetes CA ${k8s_ca}"
        return 0
    fi
    if [ -f "${_KUBE_PKI_DIR}/etcd/ca.crt" ]; then
        secaudit_report_pass "$num" "etcd unique CA present at ${etcd_ca}"
    else
        secaudit_report_fail "$num" "etcd unique CA not verified"
    fi
}

# --- auth policy (RULE67-71) ---
secaudit_check_user_client_certs() {
    local num="$1" hits
    secaudit_no_api "$num" "user client-certificate authentication" && return 0
    hits=$(secaudit_kubectl config view --raw 2>/dev/null | grep -cE 'client-certificate-data:|client-key-data:' || true)
    if [ "$(secaudit_as_uint "$hits")" -gt 0 ]; then
        secaudit_report_fail "$num" "kubeconfig contains client-certificate-data (count=${hits}); user client certs are not revocable"
    else
        secaudit_report_pass "$num" "default kubeconfig has no client-certificate-data for users"
    fi
}

secaudit_check_user_sa_tokens() {
    local num="$1" n
    secaudit_no_api "$num" "service account token auth for users" && return 0
    n=$(secaudit_kubectl get clusterrolebindings -o json 2>/dev/null | grep -cE '"kind": "ServiceAccount"|system:serviceaccount:' || true)
    if [ "$(secaudit_as_uint "$n")" -gt 20 ]; then
        secaudit_report_fail "$num" "clusterrolebindings reference many ServiceAccounts (count=${n}); review user SA-token auth"
    else
        secaudit_report_pass "$num" "ServiceAccount clusterrolebindings count=${n} (review remaining user token use)"
    fi
}

secaudit_check_bootstrap_tokens() {
    local num="$1"
    secaudit_no_api "$num" "bootstrap token user authentication" && return 0
    if secaudit_kubectl get secrets -n kube-system 2>/dev/null | grep -q bootstrap-token; then
        secaudit_report_fail "$num" "bootstrap-token secrets still present in kube-system"
    elif secaudit_kubectl get secrets -n kube-system -o json 2>/dev/null | grep -q 'bootstrap.kubernetes.io/token'; then
        secaudit_report_fail "$num" "bootstrap token annotations present in kube-system secrets"
    else
        secaudit_report_pass "$num" "no bootstrap tokens found in kube-system"
    fi
}

secaudit_check_audit_policy_file() {
    local num="$1" path
    secaudit_not_control_plane "$num" "apiserver audit-policy-file" && return 0
    path=$(secaudit_flag_val "$_KUBE_APISERVER_FLAGS" audit-policy-file)
    if [ -n "$path" ] && [ -f "$path" ]; then
        secaudit_report_pass "$num" "audit-policy-file=${path} mode=$(secaudit_path_mode_octal "$path")"
    else
        secaudit_report_fail "$num" "audit-policy-file=${path:-unset} is missing"
    fi
}

secaudit_check_audit_policy_coverage() {
    local num="$1" path body miss=""
    secaudit_not_control_plane "$num" "audit policy security coverage" && return 0
    path=$(secaudit_flag_val "$_KUBE_APISERVER_FLAGS" audit-policy-file)
    if [ -z "$path" ] || [ ! -f "$path" ]; then
        secaudit_report_fail "$num" "audit policy file missing"
        return 0
    fi
    body=$(cat "$path" 2>/dev/null)
    printf '%s' "$body" | grep -qiE 'kind:[[:space:]]*Policy' || miss="${miss}kind=Policy "
    printf '%s' "$body" | grep -qiE 'level:[[:space:]]*(Metadata|RequestResponse|Request)' || miss="${miss}level "
    printf '%s' "$body" | grep -qiE 'secrets' || miss="${miss}secrets "
    printf '%s' "$body" | grep -qiE 'configmaps' || miss="${miss}configmaps "
    printf '%s' "$body" | grep -qiE 'pods/exec|pods/portforward|pods/proxy' || miss="${miss}pods-subresources "
    if [ -z "$miss" ]; then
        secaudit_report_pass "$num" "audit policy ${path} covers secrets, configmaps, and pod subresources"
    else
        secaudit_report_fail "$num" "audit policy ${path} missing coverage: $(secaudit_squash_ws "$miss")"
    fi
}

# --- kubelet files (RULE72-81) ---
secaudit_kubelet_unit_path() {
    local path="${_KUBE_KUBELET_DROPIN}"
    if [ -z "$path" ] || [ ! -f "$path" ]; then
        path=$(secaudit_first_file /etc/systemd/system/kubelet.service /usr/lib/systemd/system/kubelet.service /lib/systemd/system/kubelet.service)
    fi
    printf '%s' "$path"
}

secaudit_check_kubelet_unit_mode() {
    local num="$1" path
    path=$(secaudit_kubelet_unit_path)
    if [ -z "$path" ]; then
        secaudit_report_fail "$num" "kubelet systemd unit/drop-in not found"
        return 0
    fi
    secaudit_check_path_mode "$num" "$path" "kubelet systemd unit ${path}" 077
}

secaudit_check_kubelet_unit_owner() {
    local num="$1" path
    path=$(secaudit_kubelet_unit_path)
    if [ -z "$path" ]; then
        secaudit_report_fail "$num" "kubelet systemd unit/drop-in not found"
        return 0
    fi
    secaudit_check_path_owner "$num" "$path" "root:root" "kubelet systemd unit"
}

secaudit_check_proxy_kubeconfig_mode() {
    local num="$1"
    if secaudit_cilium_dataplane && [ -z "$_KUBE_PROXY_KUBECONFIG" ]; then
        secaudit_report_skip "$num" "kube-proxy kubeconfig unused (Cilium/eBPF dataplane on this node)"
        return 0
    fi
    if [ -z "$_KUBE_PROXY_KUBECONFIG" ]; then
        secaudit_report_skip "$num" "kube-proxy kubeconfig file is not used on this node (DaemonSet/ConfigMap or no kube-proxy)"
        return 0
    fi
    secaudit_check_path_mode "$num" "$_KUBE_PROXY_KUBECONFIG" "kube-proxy kubeconfig" 077
}

secaudit_check_proxy_kubeconfig_owner() {
    local num="$1"
    if secaudit_cilium_dataplane && [ -z "$_KUBE_PROXY_KUBECONFIG" ]; then
        secaudit_report_skip "$num" "kube-proxy kubeconfig unused (Cilium/eBPF dataplane on this node)"
        return 0
    fi
    if [ -z "$_KUBE_PROXY_KUBECONFIG" ]; then
        secaudit_report_skip "$num" "kube-proxy kubeconfig file is not used on this node"
        return 0
    fi
    secaudit_check_path_owner "$num" "$_KUBE_PROXY_KUBECONFIG" "root:root" "kube-proxy kubeconfig"
}

secaudit_resolve_client_ca() {
    local ca
    ca=$(secaudit_kubelet_val client-ca-file authentication.x509.clientCAFile)
    [ -z "$ca" ] && ca="${_KUBE_CLIENT_CA}"
    [ -z "$ca" ] && ca=$(secaudit_first_file "${_KUBE_PKI_DIR}/ca.crt")
    printf '%s' "$ca"
}

secaudit_check_client_ca_mode() {
    local num="$1" ca
    ca=$(secaudit_resolve_client_ca)
    if [ -z "$ca" ] || [ ! -f "$ca" ]; then
        secaudit_report_fail "$num" "kubelet client CA file not found"
        return 0
    fi
    _KUBE_CLIENT_CA="$ca"
    secaudit_check_path_mode "$num" "$ca" "kubelet client CA" 077
}

secaudit_check_client_ca_owner() {
    local num="$1" ca
    ca="${_KUBE_CLIENT_CA}"
    [ -z "$ca" ] && ca=$(secaudit_resolve_client_ca)
    if [ -z "$ca" ] || [ ! -f "$ca" ]; then
        secaudit_report_fail "$num" "kubelet client CA file not found"
        return 0
    fi
    secaudit_check_path_owner "$num" "$ca" "root:root" "kubelet client CA"
}

secaudit_check_kubelet_yaml_mode() {
    local num="$1"
    if [ -z "$_KUBE_KUBELET_YAML" ] || [ ! -f "$_KUBE_KUBELET_YAML" ]; then
        secaudit_report_skip "$num" "kubelet --config YAML is not in use on this node"
        return 0
    fi
    secaudit_check_path_mode "$num" "$_KUBE_KUBELET_YAML" "kubelet config.yaml" 077
}

secaudit_check_kubelet_yaml_owner() {
    local num="$1"
    if [ -z "$_KUBE_KUBELET_YAML" ] || [ ! -f "$_KUBE_KUBELET_YAML" ]; then
        secaudit_report_skip "$num" "kubelet --config YAML is not in use on this node"
        return 0
    fi
    secaudit_check_path_owner "$num" "$_KUBE_KUBELET_YAML" "root:root" "kubelet config.yaml"
}

# --- kubelet runtime (RULE82-95) ---
secaudit_check_kubelet_anonymous() {
    local num="$1" val
    val=$(secaudit_lower "$(secaudit_kubelet_val anonymous-auth authentication.anonymous.enabled)")
    if [ "$val" = false ]; then
        secaudit_report_pass "$num" "kubelet anonymous auth is false (cli/config.yaml)"
    elif [ -z "$val" ]; then
        secaudit_report_fail "$num" "kubelet anonymous-auth / authentication.anonymous.enabled is not set to false"
    else
        secaudit_report_fail "$num" "kubelet anonymous auth=${val}, expected false"
    fi
}

secaudit_check_kubelet_authz_mode() {
    local num="$1" val
    val=$(secaudit_kubelet_val authorization-mode authorization.mode)
    if [ -z "$val" ]; then
        val=$(secaudit_yaml_nested "${_KUBE_KUBELET_YAML}" authorization mode 2>/dev/null || true)
    fi
    if printf '%s' "$val" | grep -qi AlwaysAllow; then
        secaudit_report_fail "$num" "kubelet authorization-mode=${val} (AlwaysAllow is forbidden)"
    elif printf '%s' "$val" | grep -qi Webhook; then
        secaudit_report_pass "$num" "kubelet authorization-mode=${val}"
    else
        secaudit_report_fail "$num" "kubelet authorization-mode=${val:-unset}, expected Webhook (not AlwaysAllow)"
    fi
}

secaudit_check_kubelet_client_ca_flag() {
    local num="$1" ca
    ca=$(secaudit_kubelet_val client-ca-file authentication.x509.clientCAFile)
    if [ -n "$ca" ] && [ -f "$ca" ]; then
        secaudit_report_pass "$num" "kubelet clientCAFile=${ca}"
    else
        secaudit_report_fail "$num" "kubelet client-ca-file / authentication.x509.clientCAFile is not set to an existing file (${ca:-unset})"
    fi
}

secaudit_check_kubelet_readonly_port() {
    local num="$1" val
    val=$(secaudit_kubelet_val read-only-port readOnlyPort)
    if [ "$val" = 0 ]; then
        secaudit_report_pass "$num" "kubelet readOnlyPort=0"
    elif [ -z "$val" ]; then
        secaudit_report_pass "$num" "kubelet readOnlyPort unset (default 0 on kubelet 1.18+)"
    else
        secaudit_report_fail "$num" "kubelet readOnlyPort=${val}, expected 0"
    fi
}

secaudit_check_kubelet_streaming_timeout() {
    local num="$1" val
    val=$(secaudit_kubelet_val streaming-connection-idle-timeout streamingConnectionIdleTimeout)
    if [ "$val" = 0 ] || [ "$val" = 0s ]; then
        secaudit_report_fail "$num" "kubelet streamingConnectionIdleTimeout=${val} disables the timeout"
    elif [ -n "$val" ]; then
        secaudit_report_pass "$num" "kubelet streamingConnectionIdleTimeout=${val}"
    else
        secaudit_report_pass "$num" "kubelet streamingConnectionIdleTimeout unset (default 4h)"
    fi
}

secaudit_check_kubelet_iptables() {
    local num="$1" val
    val=$(secaudit_lower "$(secaudit_kubelet_val make-iptables-util-chains makeIPTablesUtilChains)")
    if [ "$val" = false ]; then
        secaudit_report_fail "$num" "kubelet makeIPTablesUtilChains=false"
    else
        secaudit_report_pass "$num" "kubelet makeIPTablesUtilChains=${val:-default-true}"
    fi
}

secaudit_check_kubelet_hostname_override() {
    local num="$1"
    if secaudit_flag_present "$_KUBE_KUBELET_CLI" hostname-override \
        || printf '%s' "$_KUBE_KUBELET_DROPIN_TEXT" | grep -qE -- '--hostname-override'; then
        secaudit_report_fail "$num" "kubelet --hostname-override is set"
    else
        secaudit_report_pass "$num" "kubelet --hostname-override is not set"
    fi
}

secaudit_check_kubelet_event_qps() {
    local num="$1" val
    val=$(secaudit_kubelet_val event-qps eventRecordQPS)
    if [ -n "$val" ]; then
        secaudit_report_pass "$num" "kubelet eventRecordQPS=${val}"
    else
        secaudit_report_fail "$num" "kubelet eventRecordQPS / --event-qps is not set"
    fi
}

secaudit_check_kubelet_tls_files() {
    local num="$1" cert key bootstrap
    cert=$(secaudit_kubelet_val tls-cert-file tlsCertFile)
    key=$(secaudit_kubelet_val tls-private-key-file tlsPrivateKeyFile)
    bootstrap=$(secaudit_lower "$(secaudit_kubelet_val rotate-server-certificates serverTLSBootstrap)")
    if [ -n "$cert" ] && [ -n "$key" ] && [ -f "$cert" ] && [ -f "$key" ]; then
        secaudit_report_pass "$num" "kubelet tlsCertFile=${cert} tlsPrivateKeyFile=${key}"
    elif [ "$bootstrap" = true ]; then
        secaudit_report_pass "$num" "kubelet serverTLSBootstrap=true (serving certs via CSR, tlsCertFile optional)"
    else
        secaudit_report_fail "$num" "kubelet tlsCertFile/tlsPrivateKeyFile unset and serverTLSBootstrap is not true"
    fi
}

secaudit_check_kubelet_rotate_client() {
    local num="$1" val
    val=$(secaudit_lower "$(secaudit_kubelet_val rotate-certificates rotateCertificates)")
    if [ "$val" = false ]; then
        secaudit_report_fail "$num" "kubelet rotateCertificates=false"
    else
        secaudit_report_pass "$num" "kubelet rotateCertificates=${val:-default-true}"
    fi
}

secaudit_check_kubelet_rotate_server() {
    local num="$1" val feat
    val=$(secaudit_lower "$(secaudit_kubelet_val rotate-server-certificates serverTLSBootstrap)")
    feat=$(secaudit_flag_val "$_KUBE_KUBELET_CLI" feature-gates)
    if [ "$val" = true ] || printf '%s' "$feat" | grep -qE 'RotateKubeletServerCertificate=true'; then
        secaudit_report_pass "$num" "kubelet server TLS rotation enabled (serverTLSBootstrap=${val:-n/a})"
    else
        secaudit_report_fail "$num" "kubelet RotateKubeletServerCertificate/serverTLSBootstrap is not true"
    fi
}

secaudit_check_kubelet_ciphers() {
    local num="$1" suites bad
    suites=$(secaudit_kubelet_val tls-cipher-suites tlsCipherSuites)
    if [ -z "$suites" ]; then
        secaudit_report_fail "$num" "kubelet tlsCipherSuites / --tls-cipher-suites is not set"
        return 0
    fi
    bad=$(secaudit_weak_ciphers "$suites")
    if [ -n "$bad" ]; then
        secaudit_report_fail "$num" "kubelet cipher suites include weak/unknown entries: $(secaudit_squash_ws "$bad")"
    else
        secaudit_report_pass "$num" "kubelet tlsCipherSuites uses strong suites only"
    fi
}

secaudit_check_kubelet_pod_pids() {
    local num="$1" val
    val=$(secaudit_kubelet_val pod-max-pids podPidsLimit)
    if [ -z "$val" ] || [ "$val" = "-1" ] || [ "$val" = 0 ]; then
        secaudit_report_fail "$num" "kubelet podPidsLimit=${val:-unset} (no PID limit)"
    else
        secaudit_report_pass "$num" "kubelet podPidsLimit=${val}"
    fi
}

secaudit_check_kube_proxy_metrics() {
    local num="$1" addr
    if secaudit_cilium_dataplane && [ -z "$_KUBE_PROXY_FLAGS" ] && [ -z "$_KUBE_PROXY_CONFIG" ]; then
        secaudit_report_skip "$num" "kube-proxy metrics bind skipped (Cilium replaces kube-proxy on this node)"
        return 0
    fi
    addr=$(secaudit_flag_val "$_KUBE_PROXY_FLAGS" metrics-bind-address)
    [ -z "$addr" ] && [ -n "$_KUBE_PROXY_CONFIG" ] && [ -f "$_KUBE_PROXY_CONFIG" ] && addr=$(secaudit_yaml_top "$_KUBE_PROXY_CONFIG" metricsBindAddress)
    [ -z "$addr" ] && [ -n "$_KUBE_PROXY_CONFIG" ] && [ -f "$_KUBE_PROXY_CONFIG" ] && addr=$(grep -E 'metricsBindAddress|metrics-bind-address|bindAddress' "$_KUBE_PROXY_CONFIG" 2>/dev/null | head -1)
    if [ -z "$addr" ]; then
        secaudit_report_skip "$num" "kube-proxy process/config not found on this node"
        return 0
    fi
    if printf '%s' "$addr" | grep -qE '127\.0\.0\.1|localhost|::1'; then
        secaudit_report_pass "$num" "kube-proxy metrics bound to localhost (${addr})"
    else
        secaudit_report_fail "$num" "kube-proxy metrics not bound to localhost (${addr})"
    fi
}

# --- RBAC (RULE96-108) ---
secaudit_rbac_hits() {
    local resource="$1" verbs="$2"
    secaudit_have_python || { printf '0'; return 1; }
    secaudit_kubectl get clusterroles,roles --all-namespaces -o json 2>/dev/null | python3 -c '
import json,sys
resource=sys.argv[1]
want=set(sys.argv[2].split(","))
try:
    data=json.load(sys.stdin)
except Exception:
    print(0); sys.exit(0)
n=0
for item in data.get("items") or []:
    name=item.get("metadata",{}).get("name","")
    if str(name).startswith("system:"):
        continue
    for rule in item.get("rules") or []:
        res=set(rule.get("resources") or [])
        verbs=set(rule.get("verbs") or [])
        if (resource in res or "*" in res) and (verbs.intersection(want) or "*" in verbs):
            n+=1
            break
print(n)
' "$resource" "$verbs" 2>/dev/null || printf 0
}

secaudit_check_cluster_admin_bindings() {
    local num="$1" extra
    secaudit_no_api "$num" "cluster-admin role usage" && return 0
    secaudit_no_python "$num" "cluster-admin role usage" && return 0
    extra=$(secaudit_kubectl get clusterrolebindings -o json 2>/dev/null | python3 -c '
import json,sys
try:
    data=json.load(sys.stdin)
except Exception:
    sys.exit(0)
names=[]
for item in data.get("items") or []:
    ref=(item.get("roleRef") or {}).get("name","")
    if ref!="cluster-admin":
        continue
    for s in item.get("subjects") or []:
        n=s.get("name","")
        k=s.get("kind","")
        if n in ("system:masters","system:anonymous"):
            names.append("%s:%s"%(k,n))
        elif not str(n).startswith("system:"):
            names.append("%s:%s"%(k,n))
print(" ".join(names[:12]))
' 2>/dev/null || true)
    extra=$(secaudit_trim_ws "$extra")
    if printf '%s' "$extra" | grep -q 'system:masters'; then
        secaudit_report_fail "$num" "cluster-admin bound to system:masters and extra subjects (${extra})"
    elif [ -n "$extra" ]; then
        secaudit_report_fail "$num" "cluster-admin bound to non-system subjects (${extra}); minimize usage"
    else
        secaudit_report_pass "$num" "cluster-admin bindings limited to expected system subjects"
    fi
}

secaudit_check_secrets_rbac() {
    local num="$1" n
    secaudit_no_api "$num" "RBAC access to secrets" && return 0
    secaudit_no_python "$num" "RBAC access to secrets" && return 0
    n=$(secaudit_kubectl get clusterroles,roles --all-namespaces -o json 2>/dev/null | python3 -c '
import json,sys
try:
    data=json.load(sys.stdin)
except Exception:
    print(0); sys.exit(0)
n=0
for item in data.get("items") or []:
    name=item.get("metadata",{}).get("name","")
    if str(name).startswith("system:"):
        continue
    for rule in item.get("rules") or []:
        res=set(rule.get("resources") or [])
        verbs=set(rule.get("verbs") or [])
        if ("secrets" in res or "*" in res) and verbs.intersection({"get","list","watch","*"}):
            n+=1
            break
print(n)
' 2>/dev/null || printf 0)
    if [ "$(secaudit_as_uint "$n")" -gt 5 ]; then
        secaudit_report_fail "$num" "non-system Roles/ClusterRoles grant secrets get/list/watch (count=${n})"
    else
        secaudit_report_pass "$num" "non-system secrets RBAC roles count=${n}"
    fi
}

secaudit_check_wildcard_rbac() {
    local num="$1" n
    secaudit_no_api "$num" "wildcard RBAC rules" && return 0
    secaudit_no_python "$num" "wildcard RBAC rules" && return 0
    n=$(secaudit_kubectl get clusterroles,roles --all-namespaces -o json 2>/dev/null | python3 -c '
import json,sys
try:
    data=json.load(sys.stdin)
except Exception:
    print(0); sys.exit(0)
n=0
for item in data.get("items") or []:
    name=item.get("metadata",{}).get("name","")
    if str(name).startswith("system:") or name in ("cluster-admin","admin","edit"):
        continue
    for rule in item.get("rules") or []:
        if "*" in (rule.get("verbs") or []) or "*" in (rule.get("resources") or []) or "*" in (rule.get("apiGroups") or []):
            n+=1
            break
print(n)
' 2>/dev/null || printf 0)
    if [ "$(secaudit_as_uint "$n")" -gt 3 ]; then
        secaudit_report_fail "$num" "custom Roles/ClusterRoles use wildcards (count=${n})"
    else
        secaudit_report_pass "$num" "custom wildcard RBAC roles count=${n}"
    fi
}

secaudit_check_pod_create_rbac() {
    local num="$1" n
    secaudit_no_api "$num" "RBAC permission to create pods" && return 0
    secaudit_no_python "$num" "RBAC permission to create pods" && return 0
    n=$(secaudit_kubectl get clusterroles,roles --all-namespaces -o json 2>/dev/null | python3 -c '
import json,sys
try:
    data=json.load(sys.stdin)
except Exception:
    print(0); sys.exit(0)
n=0
for item in data.get("items") or []:
    name=item.get("metadata",{}).get("name","")
    if str(name).startswith("system:"):
        continue
    for rule in item.get("rules") or []:
        res=set(rule.get("resources") or [])
        verbs=set(rule.get("verbs") or [])
        if ("pods" in res or "*" in res) and verbs.intersection({"create","*"}):
            n+=1
            break
print(n)
' 2>/dev/null || printf 0)
    if [ "$(secaudit_as_uint "$n")" -gt 3 ]; then
        secaudit_report_fail "$num" "non-system roles allow pod create (count=${n})"
    else
        secaudit_report_pass "$num" "non-system pod-create roles count=${n}"
    fi
}

secaudit_check_default_sa_automount() {
    local num="$1" bad
    secaudit_no_api "$num" "default service account automount" && return 0
    secaudit_no_python "$num" "default service account automount" && return 0
    bad=$(secaudit_kubectl get serviceaccounts --all-namespaces -o json 2>/dev/null | python3 -c '
import json,sys
try:
    data=json.load(sys.stdin)
except Exception:
    sys.exit(0)
bad=[]
for item in data.get("items") or []:
    if item.get("metadata",{}).get("name")!="default":
        continue
    auto=item.get("automountServiceAccountToken")
    if auto is True or auto is None:
        ns=item.get("metadata",{}).get("namespace","")
        bad.append("%s:%s"%(ns,auto))
print(" ".join(bad[:15]))
' 2>/dev/null || true)
    bad=$(secaudit_trim_ws "$bad")
    if [ -n "$bad" ]; then
        secaudit_report_fail "$num" "default ServiceAccounts leave automount enabled (${bad})"
    else
        secaudit_report_pass "$num" "default ServiceAccounts set automountServiceAccountToken=false"
    fi
}

secaudit_check_sa_token_mounts() {
    local num="$1" n
    secaudit_no_api "$num" "service account token mounts on pods" && return 0
    secaudit_no_python "$num" "service account token mounts on pods" && return 0
    n=$(secaudit_kubectl get pods --all-namespaces -o json 2>/dev/null | python3 -c '
import json,sys
try:
    data=json.load(sys.stdin)
except Exception:
    print(0); sys.exit(0)
n=0
for item in data.get("items") or []:
    spec=item.get("spec") or {}
    sa=spec.get("serviceAccountName") or spec.get("serviceAccount") or "default"
    auto=spec.get("automountServiceAccountToken")
    ns=item.get("metadata",{}).get("namespace","")
    if ns in ("kube-system","kube-public","kube-node-lease","cilium","calico-system","kube-flannel"):
        continue
    if sa=="default" and auto is not False:
        n+=1
print(n)
' 2>/dev/null || printf 0)
    if [ "$(secaudit_as_uint "$n")" -gt 0 ]; then
        secaudit_report_fail "$num" "workload pods (non-system ns) mount default SA tokens (count=${n})"
    else
        secaudit_report_pass "$num" "no non-system pods mounting the default SA token"
    fi
}

secaudit_check_system_masters() {
    local num="$1"
    secaudit_no_api "$num" "system:masters group usage" && return 0
    if secaudit_kubectl get clusterrolebindings -o json 2>/dev/null | grep -q '"name": "system:masters"'; then
        secaudit_report_fail "$num" "system:masters appears in clusterrolebindings"
    else
        secaudit_report_pass "$num" "system:masters is not used in clusterrolebindings"
    fi
}

secaudit_check_bind_impersonate_escalate() {
    local num="$1" n
    secaudit_no_api "$num" "bind/impersonate/escalate RBAC" && return 0
    secaudit_no_python "$num" "bind/impersonate/escalate RBAC" && return 0
    n=$(secaudit_kubectl get clusterroles,roles --all-namespaces -o json 2>/dev/null | python3 -c '
import json,sys
try:
    data=json.load(sys.stdin)
except Exception:
    print(0); sys.exit(0)
n=0
want={"bind","impersonate","escalate"}
for item in data.get("items") or []:
    name=item.get("metadata",{}).get("name","")
    if str(name).startswith("system:"):
        continue
    for rule in item.get("rules") or []:
        verbs=set(rule.get("verbs") or [])
        if verbs.intersection(want) or "*" in verbs:
            n+=1
            break
print(n)
' 2>/dev/null || printf 0)
    if [ "$(secaudit_as_uint "$n")" -gt 2 ]; then
        secaudit_report_fail "$num" "custom roles grant bind/impersonate/escalate or * verbs (count=${n})"
    else
        secaudit_report_pass "$num" "custom bind/impersonate/escalate roles count=${n}"
    fi
}

secaudit_check_rbac_resource() {
    local num="$1" why="$2" resource="$3" verbs="$4" max="$5" fail_msg="$6" pass_msg="$7"
    local n
    secaudit_no_api "$num" "$why" && return 0
    secaudit_no_python "$num" "$why" && return 0
    n=$(secaudit_rbac_hits "$resource" "$verbs")
    if [ "$(secaudit_as_uint "$n")" -gt "$max" ]; then
        secaudit_report_fail "$num" "$(printf "$fail_msg" "$n")"
    else
        secaudit_report_pass "$num" "$(printf "$pass_msg" "$n")"
    fi
}

secaudit_check_webhook_config_rbac() {
    local num="$1" n1 n2
    secaudit_no_api "$num" "admission webhook configuration RBAC" && return 0
    secaudit_no_python "$num" "admission webhook configuration RBAC" && return 0
    n1=$(secaudit_rbac_hits validatingwebhookconfigurations "create,update,patch,delete")
    n2=$(secaudit_rbac_hits mutatingwebhookconfigurations "create,update,patch,delete")
    if [ "$(secaudit_as_uint "$n1")" -gt 1 ] || [ "$(secaudit_as_uint "$n2")" -gt 1 ]; then
        secaudit_report_fail "$num" "custom roles can mutate webhook configurations (validating=${n1} mutating=${n2})"
    else
        secaudit_report_pass "$num" "custom webhook-config roles validating=${n1} mutating=${n2}"
    fi
}

# --- workloads / policy (RULE109-130) ---
secaudit_check_policy_mechanism() {
    local num="$1" wh psa
    if secaudit_api_ok; then
        wh=$(secaudit_as_uint "$(secaudit_kubectl get validatingwebhookconfigurations,mutatingwebhookconfigurations --no-headers 2>/dev/null | wc -l)")
        psa=$(secaudit_as_uint "$(secaudit_kubectl get ns -o json 2>/dev/null | grep -c 'pod-security.kubernetes.io' || true)")
        if [ "$wh" -gt 0 ] || [ "$psa" -gt 0 ]; then
            secaudit_report_pass "$num" "policy mechanism present (webhooks=${wh} psa-labels=${psa})"
            return 0
        fi
    fi
    if secaudit_on_control_plane && secaudit_csv_has "$(secaudit_flag_val "$_KUBE_APISERVER_FLAGS" enable-admission-plugins)" PodSecurity; then
        secaudit_report_pass "$num" "PodSecurity admission plugin is enabled on kube-apiserver"
        return 0
    fi
    if ! secaudit_api_ok; then
        secaudit_report_skip "$num" "cluster policy control mechanism needs kubectl+kubeconfig (kubectl=${_KUBE_KUBECTL:-none} kubeconfig=${_KUBE_KUBECONFIG:-none} role=${_KUBE_NODE_KIND})"
        return 0
    fi
    secaudit_report_fail "$num" "no webhook, PodSecurity labels, or PodSecurity admission plugin detected"
}

secaudit_pod_jsonpath_hits() {
    local path="$1" pattern="$2"
    secaudit_kubectl get pods --all-namespaces -o jsonpath="$path" 2>/dev/null | grep -E "$pattern" | head -15 || true
}

secaudit_check_pod_jsonpath() {
    local num="$1" why="$2" jpath="$3" pattern="$4" fail_pfx="$5" ok_msg="$6"
    local bad
    secaudit_no_api "$num" "$why" && return 0
    bad=$(secaudit_pod_jsonpath_hits "$jpath" "$pattern")
    if [ -n "$bad" ]; then
        secaudit_report_fail "$num" "${fail_pfx} $(secaudit_squash_ws "$bad")"
    else
        secaudit_report_pass "$num" "$ok_msg"
    fi
}

secaudit_check_pod_grep() {
    local num="$1" why="$2" jpath="$3" pattern="$4" invert="${5:-0}" fail_pfx="$6" ok_msg="$7"
    local bad
    secaudit_no_api "$num" "$why" && return 0
    if [ "$invert" = 1 ]; then
        bad=$(secaudit_kubectl get pods --all-namespaces -o jsonpath="$jpath" 2>/dev/null | grep -vE "$pattern" | head -10 || true)
    else
        bad=$(secaudit_kubectl get pods --all-namespaces -o jsonpath="$jpath" 2>/dev/null | grep -E "$pattern" | head -10 || true)
    fi
    if [ -n "$bad" ]; then
        secaudit_report_fail "$num" "${fail_pfx} $(secaudit_squash_ws "$bad")"
    else
        secaudit_report_pass "$num" "$ok_msg"
    fi
}

secaudit_check_assigned_capabilities() {
    local num="$1" drop
    secaudit_no_api "$num" "capability drop ALL" && return 0
    drop=$(secaudit_kubectl get pods --all-namespaces -o json 2>/dev/null | grep -c 'ALL' || true)
    if [ "$(secaudit_as_uint "$drop")" -gt 0 ]; then
        secaudit_report_pass "$num" "some pods drop ALL capabilities (matches=${drop})"
    else
        secaudit_report_fail "$num" "no pods drop ALL capabilities"
    fi
}

secaudit_check_windows_hostprocess() {
    local num="$1"
    secaudit_no_api "$num" "Windows HostProcess containers" && return 0
    if secaudit_kubectl get pods --all-namespaces -o json 2>/dev/null | grep -qi hostprocess; then
        secaudit_report_fail "$num" "Windows HostProcess containers detected"
    else
        secaudit_report_pass "$num" "no HostProcess containers"
    fi
}

secaudit_check_cni_networkpolicy_support() {
    local num="$1" files=""
    files=$(ls /etc/cni/net.d /etc/kubernetes/cni/net.d 2>/dev/null | tr '\n' ' ')
    if printf '%s' "$files" | grep -qiE 'cilium|calico|weave|canal|antrea'; then
        secaudit_report_pass "$num" "CNI configs support NetworkPolicy (${files})"
        return 0
    fi
    if secaudit_cilium_dataplane; then
        secaudit_report_pass "$num" "Cilium dataplane present (NetworkPolicy supported)"
        return 0
    fi
    if secaudit_api_ok; then
        if secaudit_kubectl get crds 2>/dev/null | grep -qiE 'networkpolicies.crd.projectcalico.org|ciliumnetworkpolicies'; then
            secaudit_report_pass "$num" "NetworkPolicy CRDs present (Calico/Cilium)"
            return 0
        fi
        if secaudit_kubectl api-resources 2>/dev/null | grep -q networkpolicies; then
            secaudit_report_pass "$num" "networkpolicies API resource is available"
            return 0
        fi
    fi
    if [ -z "$files" ]; then
        secaudit_report_skip "$num" "CNI config directory is empty and API is unavailable to verify NetworkPolicy support"
    else
        secaudit_report_fail "$num" "CNI NetworkPolicy support not verified (cni=${files})"
    fi
}

secaudit_check_networkpolicies_per_ns() {
    local num="$1" np ns
    secaudit_no_api "$num" "NetworkPolicy per namespace" && return 0
    np=$(secaudit_as_uint "$(secaudit_kubectl get networkpolicies --all-namespaces --no-headers 2>/dev/null | wc -l)")
    ns=$(secaudit_as_uint "$(secaudit_kubectl get ns --no-headers 2>/dev/null | wc -l)")
    if [ "$np" -eq 0 ]; then
        secaudit_report_fail "$num" "no NetworkPolicies defined (namespaces=${ns})"
    else
        secaudit_report_pass "$num" "NetworkPolicies present (count=${np} namespaces=${ns})"
    fi
}

secaudit_check_secrets_as_env() {
    local num="$1" n
    secaudit_no_api "$num" "secrets as environment variables" && return 0
    n=$(secaudit_as_uint "$(secaudit_kubectl get pods --all-namespaces -o json 2>/dev/null | grep -c 'secretKeyRef' || true)")
    if [ "$n" -gt 0 ]; then
        secaudit_report_fail "$num" "pods use secrets as env vars via secretKeyRef (count=${n})"
    else
        secaudit_report_pass "$num" "no secretKeyRef env usage detected"
    fi
}

secaudit_check_external_secret_store() {
    local num="$1"
    secaudit_no_api "$num" "external secret storage" && return 0
    if secaudit_kubectl get crds 2>/dev/null | grep -qiE 'externalsecrets|vaultsecrets|sealedsecrets'; then
        secaudit_report_pass "$num" "external secret CRDs are present"
    elif secaudit_kubectl get ns 2>/dev/null | grep -qiE 'external-secrets|vault'; then
        secaudit_report_pass "$num" "external-secrets/vault namespace is present"
    elif secaudit_have_bin vault; then
        secaudit_report_pass "$num" "vault CLI is present on the node"
    else
        secaudit_report_fail "$num" "no external secret store (CRD/namespace/vault CLI) detected"
    fi
}

secaudit_check_imagepolicy_webhook() {
    local num="$1"
    secaudit_not_control_plane "$num" "ImagePolicyWebhook admission" && return 0
    if secaudit_csv_has "$(secaudit_flag_val "$_KUBE_APISERVER_FLAGS" enable-admission-plugins)" ImagePolicyWebhook; then
        secaudit_report_pass "$num" "ImagePolicyWebhook is enabled on kube-apiserver"
        return 0
    fi
    if secaudit_api_ok && secaudit_kubectl get validatingwebhookconfigurations 2>/dev/null | grep -qiE 'image|trivy|kyverno|gatekeeper'; then
        secaudit_report_pass "$num" "image-policy validating webhooks are present (policy engine)"
        return 0
    fi
    secaudit_report_fail "$num" "ImagePolicyWebhook is not enabled and no image-policy webhook was found"
}

secaudit_check_namespace_boundaries() {
    local num="$1" n
    secaudit_no_api "$num" "namespace administrative boundaries" && return 0
    n=$(secaudit_as_uint "$(secaudit_kubectl get namespaces --no-headers 2>/dev/null | wc -l)")
    if [ "$n" -gt 4 ]; then
        secaudit_report_pass "$num" "namespaces in use (count=${n})"
    else
        secaudit_report_fail "$num" "insufficient namespace separation (count=${n})"
    fi
}

secaudit_check_seccomp_profile() {
    local num="$1"
    secaudit_no_api "$num" "seccomp profiles on pods" && return 0
    if secaudit_kubectl get pods --all-namespaces -o json 2>/dev/null | grep -qE 'seccompProfile|RuntimeDefault|seccomp.security.alpha.kubernetes.io'; then
        secaudit_report_pass "$num" "seccomp profiles referenced in pod specs"
    else
        secaudit_report_fail "$num" "no seccomp profiles found in pod definitions"
    fi
}

secaudit_check_security_context() {
    local num="$1"
    secaudit_no_api "$num" "pod securityContext" && return 0
    if secaudit_kubectl get pods --all-namespaces -o json 2>/dev/null | grep -q 'securityContext'; then
        secaudit_report_pass "$num" "securityContext is used in pod definitions"
    else
        secaudit_report_fail "$num" "no securityContext in pod definitions"
    fi
}

secaudit_check_default_namespace_empty() {
    local num="$1" wl
    secaudit_no_api "$num" "default namespace workloads" && return 0
    wl=$(secaudit_kubectl get all --ignore-not-found -n default 2>/dev/null | grep -vE '^NAME|service/kubernetes|^$' | head -8 || true)
    if [ -n "$wl" ]; then
        secaudit_report_fail "$num" "workloads in default namespace: $(secaudit_squash_ws "$wl")"
    else
        secaudit_report_pass "$num" "default namespace has no extra workloads"
    fi
}

# --- runners (RULE1-130 sequential) ---
secaudit_run_control_plane_files() {
    # RULE1-21
    secaudit_check_static_pod_mode 1 "$_KUBE_MANIFEST_APISERVER" kube-apiserver
    secaudit_check_static_pod_owner 2 "$_KUBE_MANIFEST_APISERVER" kube-apiserver
    secaudit_check_static_pod_mode 3 "$_KUBE_MANIFEST_CONTROLLER" kube-controller-manager
    secaudit_check_static_pod_owner 4 "$_KUBE_MANIFEST_CONTROLLER" kube-controller-manager
    secaudit_check_static_pod_mode 5 "$_KUBE_MANIFEST_SCHEDULER" kube-scheduler
    secaudit_check_static_pod_owner 6 "$_KUBE_MANIFEST_SCHEDULER" kube-scheduler
    secaudit_check_static_pod_mode 7 "$_KUBE_MANIFEST_ETCD" etcd
    secaudit_check_static_pod_owner 8 "$_KUBE_MANIFEST_ETCD" etcd
    secaudit_check_dir_files_mode 9 "$_KUBE_CNI_DIR" "CNI configs"
    secaudit_check_dir_files_owner 10 "$_KUBE_CNI_DIR" "root:root" "CNI configs"
    secaudit_check_etcd_datadir_mode 11
    secaudit_check_etcd_datadir_owner 12
    secaudit_check_admin_kubeconfig_mode 13
    secaudit_check_admin_kubeconfig_owner 14
    secaudit_check_plane_mode 15 "$_KUBE_SCHEDULER_CONF" "scheduler.conf permissions"
    secaudit_check_plane_owner 16 "$_KUBE_SCHEDULER_CONF" "root:root" "scheduler.conf ownership"
    secaudit_check_plane_mode 17 "$_KUBE_CM_CONF" "controller-manager.conf permissions"
    secaudit_check_plane_owner 18 "$_KUBE_CM_CONF" "root:root" "controller-manager.conf ownership"
    secaudit_check_pki_tree_owner 19
    secaudit_check_pki_cert_modes 20
    secaudit_check_pki_key_modes 21
}

secaudit_run_apiserver_auth() {
    # RULE22-35
    secaudit_check_comp_eq 22 apiserver anonymous-auth false "kube-apiserver anonymous-auth"
    secaudit_check_comp_absent 23 apiserver token-auth-file "kube-apiserver token-auth-file"
    secaudit_check_admission_on 24 DenyServiceExternalIPs "DenyServiceExternalIPs admission" 0
    secaudit_check_kubelet_client_certs 25
    secaudit_check_kubelet_client_ca 26
    secaudit_check_authz_not_alwaysallow 27
    secaudit_check_authz_includes 28 Node "apiserver authorization-mode Node"
    secaudit_check_authz_includes 29 RBAC "apiserver authorization-mode RBAC"
    secaudit_check_admission_on 30 EventRateLimit "EventRateLimit admission" 0
    secaudit_check_admission_off 31 AlwaysAdmit "AlwaysAdmit admission"
    secaudit_check_admission_on 32 AlwaysPullImages "AlwaysPullImages admission" 0
    secaudit_check_admission_on 33 ServiceAccount "ServiceAccount admission" 1
    secaudit_check_admission_on 34 NamespaceLifecycle "NamespaceLifecycle admission" 1
    secaudit_check_admission_on 35 NodeRestriction "NodeRestriction admission" 0
}

secaudit_run_apiserver_audit_tls() {
    # RULE36-50
    secaudit_check_comp_eq 36 apiserver profiling false "kube-apiserver profiling"
    secaudit_check_audit_log_path 37
    secaudit_check_audit_log_min 38 audit-log-maxage 30 "apiserver audit-log-maxage"
    secaudit_check_audit_log_min 39 audit-log-maxbackup 10 "apiserver audit-log-maxbackup"
    secaudit_check_audit_log_min 40 audit-log-maxsize 100 "apiserver audit-log-maxsize"
    secaudit_check_request_timeout 41
    secaudit_check_sa_lookup 42
    secaudit_check_existing_flag_file 43 apiserver service-account-key-file "apiserver service-account-key-file"
    secaudit_check_tls_pair 44 "apiserver etcd client TLS" etcd-certfile etcd-keyfile "$_KUBE_APISERVER_FLAGS" 0 0
    secaudit_check_tls_pair 45 "apiserver serving TLS" tls-cert-file tls-private-key-file "$_KUBE_APISERVER_FLAGS" 1 1
    secaudit_check_ca_file_flag 46 client-ca-file "apiserver client-ca-file"
    secaudit_check_ca_file_flag 47 etcd-cafile "apiserver etcd-cafile"
    secaudit_check_existing_flag_file 48 apiserver encryption-provider-config "apiserver encryption-provider-config"
    secaudit_check_encryption_providers 49
    secaudit_check_apiserver_ciphers 50
}

secaudit_run_controller_scheduler() {
    # RULE51-59
    secaudit_check_terminated_pod_gc 51
    secaudit_check_comp_eq 52 controller profiling false "kube-controller-manager profiling"
    secaudit_check_comp_eq 53 controller use-service-account-credentials true "controller-manager use-service-account-credentials"
    secaudit_check_cm_sa_key 54
    secaudit_check_cm_root_ca 55
    secaudit_check_cm_rotate_kubelet_cert 56
    secaudit_check_comp_eq 57 controller bind-address 127.0.0.1 "controller-manager bind-address"
    secaudit_check_comp_eq 58 scheduler profiling false "kube-scheduler profiling"
    secaudit_check_comp_eq 59 scheduler bind-address 127.0.0.1 "kube-scheduler bind-address"
}

secaudit_run_etcd() {
    # RULE60-66
    secaudit_check_etcd_tls_pair 60 "etcd client cert-file/key-file" cert-file key-file 1
    secaudit_check_comp_eq 61 etcd client-cert-auth true "etcd client-cert-auth"
    secaudit_check_comp_not_true 62 etcd auto-tls "etcd auto-tls"
    secaudit_check_etcd_tls_pair 63 "etcd peer TLS certificates" peer-cert-file peer-key-file 0
    secaudit_check_comp_eq 64 etcd peer-client-cert-auth true "etcd peer-client-cert-auth"
    secaudit_check_comp_not_true 65 etcd peer-auto-tls "etcd peer-auto-tls"
    secaudit_check_etcd_unique_ca 66
}

secaudit_run_auth_audit_policy() {
    # RULE67-71
    secaudit_check_user_client_certs 67
    secaudit_check_user_sa_tokens 68
    secaudit_check_bootstrap_tokens 69
    secaudit_check_audit_policy_file 70
    secaudit_check_audit_policy_coverage 71
}

secaudit_run_kubelet_files() {
    # RULE72-81
    secaudit_check_kubelet_unit_mode 72
    secaudit_check_kubelet_unit_owner 73
    secaudit_check_proxy_kubeconfig_mode 74
    secaudit_check_proxy_kubeconfig_owner 75
    secaudit_check_path_mode 76 "$_KUBE_KUBELET_CONF" "kubelet.conf" 077
    secaudit_check_path_owner 77 "$_KUBE_KUBELET_CONF" "root:root" "kubelet.conf"
    secaudit_check_client_ca_mode 78
    secaudit_check_client_ca_owner 79
    secaudit_check_kubelet_yaml_mode 80
    secaudit_check_kubelet_yaml_owner 81
}

secaudit_run_kubelet_runtime() {
    # RULE82-95
    secaudit_check_kubelet_anonymous 82
    secaudit_check_kubelet_authz_mode 83
    secaudit_check_kubelet_client_ca_flag 84
    secaudit_check_kubelet_readonly_port 85
    secaudit_check_kubelet_streaming_timeout 86
    secaudit_check_kubelet_iptables 87
    secaudit_check_kubelet_hostname_override 88
    secaudit_check_kubelet_event_qps 89
    secaudit_check_kubelet_tls_files 90
    secaudit_check_kubelet_rotate_client 91
    secaudit_check_kubelet_rotate_server 92
    secaudit_check_kubelet_ciphers 93
    secaudit_check_kubelet_pod_pids 94
    secaudit_check_kube_proxy_metrics 95
}

secaudit_run_rbac() {
    # RULE96-108
    secaudit_check_cluster_admin_bindings 96
    secaudit_check_secrets_rbac 97
    secaudit_check_wildcard_rbac 98
    secaudit_check_pod_create_rbac 99
    secaudit_check_default_sa_automount 100
    secaudit_check_sa_token_mounts 101
    secaudit_check_system_masters 102
    secaudit_check_bind_impersonate_escalate 103
    secaudit_check_rbac_resource 104 "PersistentVolume create RBAC" persistentvolumes "create" 1 \
        "custom roles allow persistentvolumes create (count=%s)" \
        "custom persistentvolumes create roles count=%s"
    secaudit_check_rbac_resource 105 "nodes/proxy RBAC" nodes/proxy "get,create,list,update,patch" 0 \
        "custom roles allow nodes/proxy access (count=%s)" \
        "no custom roles grant nodes/proxy"
    secaudit_check_rbac_resource 106 "CSR approval RBAC" certificatesigningrequests/approval "update,patch,create" 1 \
        "custom roles allow CSR approval (count=%s)" \
        "custom CSR approval roles count=%s"
    secaudit_check_webhook_config_rbac 107
    secaudit_check_rbac_resource 108 "serviceaccount token create RBAC" serviceaccounts/token "create" 1 \
        "custom roles allow serviceaccounts/token create (count=%s)" \
        "custom serviceaccounts/token create roles count=%s"
}

secaudit_run_workloads() {
    # RULE109-130
    secaudit_check_policy_mechanism 109
    secaudit_check_pod_jsonpath 110 "privileged containers" \
        '{range .items[*]}{.metadata.namespace}:{.metadata.name}:{.spec.containers[*].securityContext.privileged}{"\n"}{end}' \
        ':true' "privileged pods:" "no privileged pods detected"
    secaudit_check_pod_jsonpath 111 "hostPID pods" \
        '{range .items[*]}{.metadata.namespace}:{.metadata.name}:{.spec.hostPID}{"\n"}{end}' \
        ':true' "hostPID pods:" "no hostPID pods"
    secaudit_check_pod_jsonpath 112 "hostIPC pods" \
        '{range .items[*]}{.metadata.namespace}:{.metadata.name}:{.spec.hostIPC}{"\n"}{end}' \
        ':true' "hostIPC pods:" "no hostIPC pods"
    secaudit_check_pod_jsonpath 113 "hostNetwork pods" \
        '{range .items[*]}{.metadata.namespace}:{.metadata.name}:{.spec.hostNetwork}{"\n"}{end}' \
        ':true' "hostNetwork pods:" "no hostNetwork pods"
    secaudit_check_pod_jsonpath 114 "allowPrivilegeEscalation" \
        '{range .items[*]}{.metadata.namespace}:{.metadata.name}:{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{end}' \
        ':true' "allowPrivilegeEscalation=true pods:" "no allowPrivilegeEscalation=true pods"
    secaudit_check_pod_jsonpath 115 "root containers" \
        '{range .items[*]}{.metadata.namespace}:{.metadata.name}:{.spec.containers[*].securityContext.runAsUser}{"\n"}{end}' \
        ':0$' "runAsUser=0 containers:" "no runAsUser=0 containers detected"
    secaudit_check_pod_grep 116 "NET_RAW capability" \
        '{range .items[*]}{.metadata.namespace}:{.metadata.name}:{.spec.containers[*].securityContext.capabilities.add}{"\n"}{end}' \
        'NET_RAW' 0 "NET_RAW capability pods:" "no NET_RAW capability added on pods"
    secaudit_check_pod_grep 117 "added capabilities" \
        '{range .items[*]}{.metadata.namespace}:{.metadata.name}:{.spec.containers[*].securityContext.capabilities.add}{"\n"}{end}' \
        '^$|<nil>|\[\]' 1 "containers with added capabilities:" "no added capabilities on pods"
    secaudit_check_assigned_capabilities 118
    secaudit_check_windows_hostprocess 119
    secaudit_check_pod_grep 120 "HostPath volumes" \
        '{range .items[*]}{.metadata.namespace}:{.metadata.name}:{.spec.volumes[*].hostPath.path}{"\n"}{end}' \
        '^$|<nil>' 1 "HostPath volumes in use:" "no HostPath volumes detected"
    secaudit_check_pod_grep 121 "HostPorts" \
        '{range .items[*]}{.metadata.namespace}:{.metadata.name}:{.spec.containers[*].ports[*].hostPort}{"\n"}{end}' \
        '^$|<nil>|:0$' 1 "pods using hostPort:" "no hostPort usage detected"
    secaudit_check_cni_networkpolicy_support 122
    secaudit_check_networkpolicies_per_ns 123
    secaudit_check_secrets_as_env 124
    secaudit_check_external_secret_store 125
    secaudit_check_imagepolicy_webhook 126
    secaudit_check_namespace_boundaries 127
    secaudit_check_seccomp_profile 128
    secaudit_check_security_context 129
    secaudit_check_default_namespace_empty 130
}

secaudit_skip_all_rules() {
    local n=1
    while [ "$n" -le "$_KUBE_RULE_COUNT" ]; do
        secaudit_report_skip "$n" "kubernetes/kubelet not present on this host"
        n=$((n + 1))
    done
}

secaudit_gather_runtime() {
    local f
    _KUBE_KUBELET_CLI=$(secaudit_live_proc_flags kubelet | secaudit_normalize_flags)
    _KUBE_KUBELET_DROPIN_TEXT=""
    while IFS= read -r f; do
        [ -f "$f" ] && _KUBE_KUBELET_DROPIN_TEXT="${_KUBE_KUBELET_DROPIN_TEXT}
$(cat "$f" 2>/dev/null)"
    done < <(secaudit_kubelet_dropin_paths)
    _KUBE_KUBELET_DROPIN=$(secaudit_locate_kubelet_dropin || true)
    _KUBE_KUBELET_YAML=$(secaudit_locate_kubelet_yaml || true)
    _KUBE_CLIENT_CA=$(secaudit_kubelet_val client-ca-file authentication.x509.clientCAFile)
    [ -z "$_KUBE_CLIENT_CA" ] && _KUBE_CLIENT_CA=$(secaudit_first_file "${_KUBE_PKI_DIR}/ca.crt")
    _KUBE_PROXY_FLAGS=$(secaudit_live_proc_flags kube-proxy | secaudit_normalize_flags)
    _KUBE_PROXY_KUBECONFIG=$(secaudit_locate_proxy_kubeconfig || true)
    _KUBE_PROXY_CONFIG=$(secaudit_locate_proxy_config || true)
    _KUBE_CNI_DIR=$(secaudit_resolve_cni_dir)
    if secaudit_on_control_plane; then
        _KUBE_APISERVER_FLAGS=$(secaudit_merge_component_flags "$_KUBE_MANIFEST_APISERVER" kube-apiserver)
        _KUBE_CONTROLLER_FLAGS=$(secaudit_merge_component_flags "$_KUBE_MANIFEST_CONTROLLER" kube-controller-manager)
        _KUBE_SCHEDULER_FLAGS=$(secaudit_merge_component_flags "$_KUBE_MANIFEST_SCHEDULER" kube-scheduler)
        _KUBE_ETCD_FLAGS=$(secaudit_merge_component_flags "$_KUBE_MANIFEST_ETCD" etcd)
        _KUBE_ETCD_DATA=$(secaudit_etcd_data_dir || true)
    fi
    secaudit_probe_api || true
}

secaudit_bootstrap_kubernetes() {
    if ! secaudit_cluster_present; then
        secaudit_skip_all_rules
        return 1
    fi
    secaudit_classify_node
    secaudit_gather_runtime
    return 0
}

secaudit_main() {
    if ! secaudit_bootstrap_kubernetes; then
        exit 0
    fi
    secaudit_run_control_plane_files
    secaudit_run_apiserver_auth
    secaudit_run_apiserver_audit_tls
    secaudit_run_controller_scheduler
    secaudit_run_etcd
    secaudit_run_auth_audit_policy
    secaudit_run_kubelet_files
    secaudit_run_kubelet_runtime
    secaudit_run_rbac
    secaudit_run_workloads
    exit 0
}

secaudit_main "$@"
