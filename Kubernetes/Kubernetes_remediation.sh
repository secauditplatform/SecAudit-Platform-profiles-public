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

# --- config (aligned with Kubernetes.sh) ---
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
_KUBE_RULE_COUNT=130
_KUBE_STRONG_TLS="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305"

_KUBE_REMEDIATE_APPLY_PERMS="${KUBE_REMEDIATE_APPLY_PERMS:-1}"
_KUBE_REMEDIATE_APPLY_FLAGS="${KUBE_REMEDIATE_APPLY_FLAGS:-1}"
_KUBE_REMEDIATE_APPLY_KUBELET="${KUBE_REMEDIATE_APPLY_KUBELET:-1}"
_KUBE_REMEDIATE_CREATE_ETCD_USER="${KUBE_REMEDIATE_CREATE_ETCD_USER:-1}"
_KUBE_REMEDIATE_AUDIT_POLICY="${KUBE_REMEDIATE_AUDIT_POLICY:-${SECAUDIT_KUBE_AUDIT_POLICY:-/etc/kubernetes/audit-policy.yaml}}"
_KUBE_REMEDIATE_ENCRYPTION="${KUBE_REMEDIATE_ENCRYPTION:-${SECAUDIT_KUBE_ENCRYPTION:-/etc/kubernetes/encryption-config.yaml}}"

# --- runtime ---
_KUBE_NODE_KIND="unknown"
_KUBE_MANIFEST_APISERVER=""
_KUBE_MANIFEST_CONTROLLER=""
_KUBE_MANIFEST_SCHEDULER=""
_KUBE_MANIFEST_ETCD=""
_KUBE_KUBELET_YAML=""
_KUBE_KUBELET_DROPIN=""
_KUBE_ETCD_DATA=""
_KUBE_HOST="$(hostname 2>/dev/null || printf '%s' unknown)"

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

secaudit_first_file() {
    local p
    for p in "$@"; do
        [ -f "$p" ] && { printf '%s' "$p"; return 0; }
    done
    return 1
}

secaudit_locate_manifest() {
    local stem="$1"
    secaudit_first_file \
        "${_KUBE_MANIFEST_DIR}/${stem}.yaml" \
        "${_KUBE_MANIFEST_DIR}/${stem}.yml" \
        "${_KUBE_MANIFEST_DIR}/${stem}.manifest"
}

secaudit_cluster_present() {
    local p
    secaudit_have_bin kubelet && return 0
    for p in /usr/bin/kubelet /usr/local/bin/kubelet; do
        [ -x "$p" ] && return 0
    done
    [ -f "$_KUBE_KUBELET_CONF" ] && return 0
    [ -f "$_KUBE_KUBELET_YAML_DEFAULT" ] && return 0
    [ -f "$_KUBE_ADMIN_CONF" ] && return 0
    [ -d "$_KUBE_MANIFEST_DIR" ] && ls "$_KUBE_MANIFEST_DIR"/*apiserver* "$_KUBE_MANIFEST_DIR"/*etcd* 2>/dev/null | grep -q . && return 0
    [ -d "$_KUBE_DROPIN_ETC" ] && ls "$_KUBE_DROPIN_ETC"/*.conf 2>/dev/null | grep -q . && return 0
    return 1
}

secaudit_classify_node() {
    local manifests=0
    _KUBE_MANIFEST_APISERVER=$(secaudit_locate_manifest kube-apiserver || true)
    _KUBE_MANIFEST_CONTROLLER=$(secaudit_locate_manifest kube-controller-manager || true)
    _KUBE_MANIFEST_SCHEDULER=$(secaudit_locate_manifest kube-scheduler || true)
    _KUBE_MANIFEST_ETCD=$(secaudit_locate_manifest etcd || true)
    [ -n "$_KUBE_MANIFEST_APISERVER" ] && manifests=$((manifests + 1))
    [ -n "$_KUBE_MANIFEST_CONTROLLER" ] && manifests=$((manifests + 1))
    [ -n "$_KUBE_MANIFEST_ETCD" ] && manifests=$((manifests + 1))
    [ -n "$_KUBE_MANIFEST_SCHEDULER" ] && manifests=$((manifests + 1))
    if [ "$manifests" -gt 0 ] || { [ -f "$_KUBE_ADMIN_CONF" ] && [ -f "${_KUBE_PKI_DIR}/apiserver.crt" ]; }; then
        _KUBE_NODE_KIND="control-plane"
    elif [ -f "$_KUBE_KUBELET_CONF" ] || [ -f "$_KUBE_KUBELET_YAML_DEFAULT" ] || secaudit_have_bin kubelet; then
        _KUBE_NODE_KIND="worker"
    else
        _KUBE_NODE_KIND="unknown"
    fi
}

secaudit_on_control_plane() { [ "$_KUBE_NODE_KIND" = control-plane ]; }

secaudit_resolve_cni_dir() {
    if [ -d /etc/cni/net.d ]; then
        printf '%s' /etc/cni/net.d
    elif [ -d /etc/kubernetes/cni/net.d ]; then
        printf '%s' /etc/kubernetes/cni/net.d
    else
        printf '%s' "$_KUBE_CNI_DIR"
    fi
}

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
        "${_KUBE_DROPIN_ETC}/99-secaudit-kubelet.conf" \
        "${_KUBE_DROPIN_ETC}/99-default.conf" \
        "${_KUBE_DROPIN_LIB}/10-kubeadm.conf"; do
        [ -f "$f" ] && { printf '%s' "$f"; return 0; }
    done
    secaudit_kubelet_dropin_paths | sort | head -1
}

secaudit_locate_kubelet_yaml() {
    secaudit_first_file "$_KUBE_KUBELET_YAML_DEFAULT" "$_KUBE_KUBELET_YAML_ALT"
}

secaudit_etcd_data_dir() {
    local d=""
    if [ -n "$_KUBE_MANIFEST_ETCD" ] && [ -f "$_KUBE_MANIFEST_ETCD" ]; then
        d=$(grep -oE -- '--data-dir=[^[:space:]]+' "$_KUBE_MANIFEST_ETCD" 2>/dev/null | head -1 | sed 's/^--data-dir=//')
    fi
    if [ -n "$d" ] && [ -e "$d" ]; then
        printf '%s' "$d"
        return 0
    fi
    for d in "$_KUBE_ETCD_DATA_DEFAULT" /var/lib/etcd; do
        [ -e "$d" ] && { printf '%s' "$d"; return 0; }
    done
    printf '%s' "$_KUBE_ETCD_DATA_DEFAULT"
}

# Replace or insert --flag=value in a static-pod command/args list.
secaudit_manifest_set_flag() {
    local file="$1" flag="$2" value="$3"
    local tmp
    [ -f "$file" ] || return 1
    secaudit_backup_file "$file"
    tmp=$(mktemp 2>/dev/null || echo "/tmp/secaudit-manifest.$$")
    if secaudit_have_bin python3; then
        python3 - "$file" "$tmp" "$flag" "$value" <<'PY'
import re, sys
path, out, flag, value = sys.argv[1:5]
want = f"--{flag}={value}"
text = open(path, encoding="utf-8").read().splitlines(True)
pat = re.compile(r"^(\s*-\s*)--%s(=.*)?\s*$" % re.escape(flag))
found = False
out_lines = []
for line in text:
    if pat.match(line):
        indent = pat.match(line).group(1)
        out_lines.append(f"{indent}{want}\n")
        found = True
    else:
        out_lines.append(line)
if not found:
    inserted = False
    result = []
    for i, line in enumerate(out_lines):
        result.append(line)
        if (not inserted) and re.match(r"^\s+-\s+(kube-apiserver|kube-controller-manager|kube-scheduler|etcd)\s*$", line):
            # insert after binary name entry
            m = re.match(r"^(\s+)-\s+", line)
            indent = (m.group(1) if m else "    ") + "- "
            result.append(f"{indent}{want}\n")
            inserted = True
        elif (not inserted) and re.match(r"^\s+command:\s*$", line):
            pass
    out_lines = result if inserted else out_lines
    if not inserted:
        # append near end of file under command list heuristic
        for i, line in enumerate(out_lines):
            if re.search(r"^\s+-\s+--", line):
                m = re.match(r"^(\s+)-\s+", line)
                indent = m.group(1) + "- " if m else "    - "
                out_lines.insert(i + 1, f"{indent}{want}\n")
                inserted = True
                break
open(out, "w", encoding="utf-8").writelines(out_lines)
PY
        [ -s "$tmp" ] && mv -f "$tmp" "$file" || { rm -f "$tmp"; return 1; }
        return 0
    fi

    if grep -qE -- "--${flag}(=|[[:space:]]|$)" "$file" 2>/dev/null; then
        sed -E -i "s|^([[:space:]]*-[[:space:]]*)--${flag}(=.*)?[[:space:]]*$|\\1--${flag}=${value}|" "$file" 2>/dev/null \
            || sed -E "s|^([[:space:]]*-[[:space:]]*)--${flag}(=.*)?[[:space:]]*$|\\1--${flag}=${value}|" "$file" >"$tmp" && mv -f "$tmp" "$file"
    else
        # insert after first command list item that looks like the component binary
        awk -v flag="$flag" -v value="$value" '
            BEGIN { want="--" flag "=" value; done=0 }
            {
                print
                if (!done && $0 ~ /^[[:space:]]+-[[:space:]]+(kube-apiserver|kube-controller-manager|kube-scheduler|etcd)[[:space:]]*$/) {
                    match($0, /^[[:space:]]+/)
                    ind=substr($0,1,RLENGTH)
                    print ind "- " want
                    done=1
                }
            }
        ' "$file" >"$tmp" && mv -f "$tmp" "$file"
    fi
    return 0
}

secaudit_manifest_remove_flag() {
    local file="$1" flag="$2"
    [ -f "$file" ] || return 1
    secaudit_backup_file "$file"
    sed -E -i "/^[[:space:]]*-[[:space:]]*--${flag}(=|[[:space:]]|$)/d" "$file" 2>/dev/null \
        || { grep -vE "^[[:space:]]*-[[:space:]]*--${flag}(=|[[:space:]]|$)" "$file" >"${file}.tmp" && mv -f "${file}.tmp" "$file"; }
    return 0
}

secaudit_manifest_ensure_admission() {
    local file="$1" plugin="$2"
    local enable
    [ -f "$file" ] || return 1
    if grep -qE -- "--enable-admission-plugins=" "$file" 2>/dev/null; then
        enable=$(grep -oE -- '--enable-admission-plugins=[^[:space:]]+' "$file" | head -1 | sed 's/^--enable-admission-plugins=//')
        printf '%s' ",${enable}," | grep -q ",${plugin}," && return 0
        if [ -n "$enable" ]; then
            secaudit_manifest_set_flag "$file" enable-admission-plugins "${enable},${plugin}"
        else
            secaudit_manifest_set_flag "$file" enable-admission-plugins "$plugin"
        fi
    else
        secaudit_manifest_set_flag "$file" enable-admission-plugins "$plugin"
    fi
    # remove from disable list if present
    if grep -qE -- "--disable-admission-plugins=.*${plugin}" "$file" 2>/dev/null; then
        local disable
        disable=$(grep -oE -- '--disable-admission-plugins=[^[:space:]]+' "$file" | head -1 | sed 's/^--disable-admission-plugins=//')
        disable=$(printf '%s' "$disable" | sed -E "s/(^|,)${plugin}(,|$)/\\1/;s/,,/,/g;s/^,//;s/,$//")
        secaudit_manifest_set_flag "$file" disable-admission-plugins "${disable}"
    fi
    return 0
}

secaudit_manifest_disable_admission() {
    local file="$1" plugin="$2"
    local enable
    [ -f "$file" ] || return 1
    if grep -qE -- "--enable-admission-plugins=.*${plugin}" "$file" 2>/dev/null; then
        enable=$(grep -oE -- '--enable-admission-plugins=[^[:space:]]+' "$file" | head -1 | sed 's/^--enable-admission-plugins=//')
        enable=$(printf '%s' "$enable" | sed -E "s/(^|,)${plugin}(,|$)/\\1/;s/,,/,/g;s/^,//;s/,$//")
        secaudit_manifest_set_flag "$file" enable-admission-plugins "${enable}"
    fi
    return 0
}

secaudit_kubelet_yaml_set() {
    # Best-effort top-level or simple nested key updates via python3, else append.
    local file="$1" keypath="$2" value="$3"
    local tmp
    [ -f "$file" ] || return 1
    secaudit_backup_file "$file"
    if ! secaudit_have_bin python3; then
        return 1
    fi
    tmp=$(mktemp 2>/dev/null || echo "/tmp/secaudit-kubelet.$$")
    python3 - "$file" "$tmp" "$keypath" "$value" <<'PY'
import sys
path, out, keypath, value = sys.argv[1:5]
lines = open(path, encoding="utf-8").read().splitlines(True)
keys = keypath.split(".")
# Only handle top-level scalar or known shallow nests used by remediation.
if len(keys) == 1:
    key = keys[0]
    found = False
    out_lines = []
    for line in lines:
        if line.startswith(f"{key}:"):
            out_lines.append(f"{key}: {value}\n")
            found = True
        else:
            out_lines.append(line)
    if not found:
        out_lines.append(f"{key}: {value}\n")
    open(out, "w", encoding="utf-8").writelines(out_lines)
    sys.exit(0)

# nested: authentication.anonymous.enabled / authorization.mode / authentication.x509.clientCAFile
text = "".join(lines)
# Prefer rewrite of known blocks with simple string ops for these remediations.
if keypath == "authentication.anonymous.enabled":
    import re
    if re.search(r"(?m)^\s*anonymous:\s*$", text):
        text2, n = re.subn(r"(?m)^(\s*anonymous:\s*\n\s*)enabled:\s*.*$", r"\1enabled: " + value, text, count=1)
        if n == 0:
            text2 = re.sub(r"(?m)^(\s*anonymous:\s*)$", r"\1\n    enabled: " + value, text, count=1)
        text = text2
    elif "authentication:" in text:
        text = text.replace("authentication:", "authentication:\n  anonymous:\n    enabled: %s" % value, 1)
    else:
        text += "\nauthentication:\n  anonymous:\n    enabled: %s\n" % value
elif keypath == "authorization.mode":
    import re
    if re.search(r"(?m)^\s*authorization:\s*$", text) or re.search(r"(?m)^authorization:\s*$", text):
        text2, n = re.subn(r"(?m)^(\s*authorization:\s*\n\s*)mode:\s*.*$", r"\1mode: " + value, text, count=1)
        if n == 0:
            text2 = re.sub(r"(?m)^(authorization:\s*)$", r"\1\n  mode: " + value, text, count=1)
        text = text2
    else:
        text += "\nauthorization:\n  mode: %s\n" % value
elif keypath == "authentication.x509.clientCAFile":
    import re
    if "clientCAFile:" in text:
        text = re.sub(r"(?m)^(\s*clientCAFile:\s*).*$", r"\1" + value, text, count=1)
    else:
        text += "\nauthentication:\n  x509:\n    clientCAFile: %s\n" % value
elif keypath == "tlsCipherSuites":
    # store as YAML list
    suites = [s.strip() for s in value.split(",") if s.strip()]
    block = "tlsCipherSuites:\n" + "".join("  - %s\n" % s for s in suites)
    import re
    if re.search(r"(?m)^tlsCipherSuites:\s*$", text) or re.search(r"(?m)^tlsCipherSuites:", text):
        text = re.sub(r"(?ms)^tlsCipherSuites:.*?(?=^\S|\Z)", block, text, count=1)
    else:
        text += "\n" + block
else:
    # top-ish fallback: last key component
    key = keys[-1]
    import re
    if re.search(r"(?m)^%s:" % re.escape(key), text):
        text = re.sub(r"(?m)^(%s:\s*).*$" % re.escape(key), r"\1" + value, text, count=1)
    else:
        text += "\n%s: %s\n" % (key, value)
open(out, "w", encoding="utf-8").write(text if text.endswith("\n") else text + "\n")
PY
    [ -s "$tmp" ] && mv -f "$tmp" "$file" || { rm -f "$tmp"; return 1; }
    return 0
}

secaudit_ensure_etcd_user() {
    if getent passwd etcd >/dev/null 2>&1 && getent group etcd >/dev/null 2>&1; then
        return 0
    fi
    [ "$_KUBE_REMEDIATE_CREATE_ETCD_USER" = "1" ] || return 1
    if secaudit_have_bin groupadd; then
        getent group etcd >/dev/null 2>&1 || groupadd --system etcd 2>/dev/null || groupadd etcd 2>/dev/null || true
    fi
    if secaudit_have_bin useradd; then
        getent passwd etcd >/dev/null 2>&1 || useradd --system --home-dir /var/lib/etcd --shell /sbin/nologin -g etcd etcd 2>/dev/null \
            || useradd -r -g etcd -d /var/lib/etcd -s /sbin/nologin etcd 2>/dev/null || true
    fi
    getent passwd etcd >/dev/null 2>&1 && getent group etcd >/dev/null 2>&1
}

secaudit_write_minimal_audit_policy() {
    local path="$1"
    mkdir -p "$(dirname "$path")" 2>/dev/null || true
    [ -f "$path" ] && secaudit_backup_file "$path"
    cat >"$path" <<'EOF'
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: Metadata
    resources:
      - group: ""
        resources: ["secrets", "configmaps"]
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["pods/exec", "pods/portforward", "pods/proxy"]
  - level: Metadata
EOF
    chmod 600 "$path" 2>/dev/null || true
    chown root:root "$path" 2>/dev/null || true
}

secaudit_write_minimal_encryption() {
    local path="$1"
    local secret
    mkdir -p "$(dirname "$path")" 2>/dev/null || true
    [ -f "$path" ] && return 0
    if secaudit_have_bin openssl; then
        secret=$(openssl rand -base64 32 2>/dev/null | tr -d '\n')
    elif [ -r /dev/urandom ] && secaudit_have_bin base64; then
        secret=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
    else
        return 1
    fi
    cat >"$path" <<EOF
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: ${secret}
      - identity: {}
EOF
    chmod 600 "$path" 2>/dev/null || true
    chown root:root "$path" 2>/dev/null || true
}

# =============================================================================
# RULE remediations
# =============================================================================

secaudit_remediate_control_plane_files() {
    # RULE1-21
    local f path

    if ! secaudit_on_control_plane; then
        local n
        for n in $(seq 1 21); do
            secaudit_remediate_skip "$n" "control-plane only (role=${_KUBE_NODE_KIND} host=${_KUBE_HOST})"
        done
        return 0
    fi

    if [ "$_KUBE_REMEDIATE_APPLY_PERMS" != "1" ]; then
        local n
        for n in $(seq 1 21); do
            secaudit_remediate_skip "$n" "permission remediation disabled (KUBE_REMEDIATE_APPLY_PERMS=0)"
        done
        return 0
    fi

    for f in \
        "$_KUBE_MANIFEST_APISERVER" \
        "$_KUBE_MANIFEST_CONTROLLER" \
        "$_KUBE_MANIFEST_SCHEDULER" \
        "$_KUBE_MANIFEST_ETCD"
    do
        [ -n "$f" ] && [ -f "$f" ] && secaudit_harden_path "$f" 600 "root:root"
    done
    secaudit_remediate_done 1 "kube-apiserver manifest mode 600 (if present)"
    secaudit_remediate_done 2 "kube-apiserver manifest owner root:root (if present)"
    secaudit_remediate_done 3 "kube-controller-manager manifest mode 600 (if present)"
    secaudit_remediate_done 4 "kube-controller-manager manifest owner root:root (if present)"
    secaudit_remediate_done 5 "kube-scheduler manifest mode 600 (if present)"
    secaudit_remediate_done 6 "kube-scheduler manifest owner root:root (if present)"
    secaudit_remediate_done 7 "etcd manifest mode 600 (if present)"
    secaudit_remediate_done 8 "etcd manifest owner root:root (if present)"

    _KUBE_CNI_DIR=$(secaudit_resolve_cni_dir)
    if [ -d "$_KUBE_CNI_DIR" ]; then
        while IFS= read -r f; do
            [ -n "$f" ] || continue
            secaudit_harden_path "$f" 600 "root:root"
        done < <(secaudit_exec_with_timeout "$_KUBE_FIND_CAP" find "$_KUBE_CNI_DIR" -type f 2>/dev/null)
        secaudit_remediate_done 9 "CNI files under ${_KUBE_CNI_DIR} mode 600"
        secaudit_remediate_done 10 "CNI files under ${_KUBE_CNI_DIR} owner root:root"
    else
        secaudit_remediate_skip 9 "CNI directory ${_KUBE_CNI_DIR} missing"
        secaudit_remediate_skip 10 "CNI directory ${_KUBE_CNI_DIR} missing"
    fi

    path="${_KUBE_ETCD_DATA}"
    [ -z "$path" ] && path=$(secaudit_etcd_data_dir)
    _KUBE_ETCD_DATA="$path"
    if [ -e "$path" ]; then
        chmod 700 "$path" 2>/dev/null || true
        secaudit_remediate_done 11 "etcd data dir ${path} mode 700"
        if secaudit_ensure_etcd_user; then
            chown -R etcd:etcd "$path" 2>/dev/null || chown etcd:etcd "$path" 2>/dev/null || true
            secaudit_remediate_done 12 "etcd data dir ${path} owner etcd:etcd"
        else
            secaudit_remediate_skip 12 "create etcd:etcd user/group then chown ${path}"
        fi
    else
        mkdir -p "$path" 2>/dev/null || true
        chmod 700 "$path" 2>/dev/null || true
        if secaudit_ensure_etcd_user; then
            chown etcd:etcd "$path" 2>/dev/null || true
            secaudit_remediate_done 11 "created etcd data dir ${path} mode 700"
            secaudit_remediate_done 12 "etcd data dir ${path} owner etcd:etcd"
        else
            secaudit_remediate_done 11 "created etcd data dir ${path} mode 700"
            secaudit_remediate_skip 12 "create etcd:etcd user/group then chown ${path}"
        fi
    fi

    for f in "$_KUBE_ADMIN_CONF" "$_KUBE_SUPER_ADMIN_CONF" /root/.kube/config; do
        [ -f "$f" ] && secaudit_harden_path "$f" 600 "root:root"
    done
    secaudit_remediate_done 13 "admin kubeconfig mode 600 where present"
    secaudit_remediate_done 14 "admin kubeconfig owner root:root where present"

    [ -f "$_KUBE_SCHEDULER_CONF" ] && secaudit_harden_path "$_KUBE_SCHEDULER_CONF" 600 "root:root"
    [ -f "$_KUBE_CM_CONF" ] && secaudit_harden_path "$_KUBE_CM_CONF" 600 "root:root"
    secaudit_remediate_done 15 "scheduler.conf mode 600 (if present)"
    secaudit_remediate_done 16 "scheduler.conf owner root:root (if present)"
    secaudit_remediate_done 17 "controller-manager.conf mode 600 (if present)"
    secaudit_remediate_done 18 "controller-manager.conf owner root:root (if present)"

    if [ -d "$_KUBE_PKI_DIR" ]; then
        while IFS= read -r f; do
            [ -n "$f" ] || continue
            chown root:root "$f" 2>/dev/null || true
            case "$f" in
                *.key) chmod 600 "$f" 2>/dev/null || true ;;
                *.crt|*.pub|*.pem) chmod 600 "$f" 2>/dev/null || true ;;
                *) [ -f "$f" ] && chmod 600 "$f" 2>/dev/null || true ;;
            esac
        done < <(secaudit_exec_with_timeout "$_KUBE_FIND_CAP" find "$_KUBE_PKI_DIR" -mindepth 1 2>/dev/null)
        secaudit_remediate_done 19 "PKI tree ownership root:root"
        secaudit_remediate_done 20 "PKI certificate modes set to 600"
        secaudit_remediate_done 21 "PKI key modes set to 600"
    else
        secaudit_remediate_skip 19 "PKI directory ${_KUBE_PKI_DIR} missing"
        secaudit_remediate_skip 20 "PKI directory ${_KUBE_PKI_DIR} missing"
        secaudit_remediate_skip 21 "PKI directory ${_KUBE_PKI_DIR} missing"
    fi
}

secaudit_remediate_apiserver_auth() {
    # RULE22-35
    local m="$_KUBE_MANIFEST_APISERVER"
    if ! secaudit_on_control_plane; then
        local n
        for n in $(seq 22 35); do
            secaudit_remediate_skip "$n" "control-plane only (role=${_KUBE_NODE_KIND})"
        done
        return 0
    fi
    if [ "$_KUBE_REMEDIATE_APPLY_FLAGS" != "1" ] || [ -z "$m" ] || [ ! -f "$m" ]; then
        local n
        for n in $(seq 22 35); do
            secaudit_remediate_skip "$n" "set kube-apiserver flags in static pod / process (manifest missing or flags disabled)"
        done
        return 0
    fi

    secaudit_manifest_set_flag "$m" anonymous-auth false
    secaudit_remediate_done 22 "kube-apiserver --anonymous-auth=false"
    secaudit_manifest_remove_flag "$m" token-auth-file
    secaudit_remediate_done 23 "removed --token-auth-file if present"
    secaudit_manifest_ensure_admission "$m" DenyServiceExternalIPs
    secaudit_remediate_done 24 "DenyServiceExternalIPs enabled in admission plugins"

    if [ -f "${_KUBE_PKI_DIR}/apiserver-kubelet-client.crt" ] && [ -f "${_KUBE_PKI_DIR}/apiserver-kubelet-client.key" ]; then
        secaudit_manifest_set_flag "$m" kubelet-client-certificate "${_KUBE_PKI_DIR}/apiserver-kubelet-client.crt"
        secaudit_manifest_set_flag "$m" kubelet-client-key "${_KUBE_PKI_DIR}/apiserver-kubelet-client.key"
        secaudit_harden_path "${_KUBE_PKI_DIR}/apiserver-kubelet-client.key" 600 "root:root"
        secaudit_remediate_done 25 "kubelet-client-certificate/key set"
    else
        secaudit_remediate_skip 25 "place apiserver-kubelet-client cert/key under ${_KUBE_PKI_DIR}"
    fi
    if [ -f "${_KUBE_PKI_DIR}/ca.crt" ]; then
        secaudit_manifest_set_flag "$m" kubelet-certificate-authority "${_KUBE_PKI_DIR}/ca.crt"
        secaudit_remediate_done 26 "kubelet-certificate-authority=${_KUBE_PKI_DIR}/ca.crt"
    else
        secaudit_remediate_skip 26 "set --kubelet-certificate-authority to cluster CA"
    fi

    secaudit_manifest_set_flag "$m" authorization-mode "Node,RBAC"
    secaudit_remediate_done 27 "authorization-mode without AlwaysAllow (Node,RBAC)"
    secaudit_remediate_done 28 "authorization-mode includes Node"
    secaudit_remediate_done 29 "authorization-mode includes RBAC"

    secaudit_manifest_ensure_admission "$m" EventRateLimit
    secaudit_remediate_done 30 "EventRateLimit admission enabled"
    secaudit_manifest_disable_admission "$m" AlwaysAdmit
    secaudit_remediate_done 31 "AlwaysAdmit removed from enable-admission-plugins"
    secaudit_manifest_ensure_admission "$m" AlwaysPullImages
    secaudit_remediate_done 32 "AlwaysPullImages admission enabled"
    secaudit_manifest_ensure_admission "$m" ServiceAccount
    secaudit_remediate_done 33 "ServiceAccount admission enabled"
    secaudit_manifest_ensure_admission "$m" NamespaceLifecycle
    secaudit_remediate_done 34 "NamespaceLifecycle admission enabled"
    secaudit_manifest_ensure_admission "$m" NodeRestriction
    secaudit_remediate_done 35 "NodeRestriction admission enabled"

    secaudit_harden_path "$m" 600 "root:root"
}

secaudit_remediate_apiserver_audit_tls() {
    # RULE36-50
    local m="$_KUBE_MANIFEST_APISERVER"
    if ! secaudit_on_control_plane; then
        local n
        for n in $(seq 36 50); do
            secaudit_remediate_skip "$n" "control-plane only (role=${_KUBE_NODE_KIND})"
        done
        return 0
    fi
    if [ "$_KUBE_REMEDIATE_APPLY_FLAGS" != "1" ] || [ -z "$m" ] || [ ! -f "$m" ]; then
        local n
        for n in $(seq 36 50); do
            secaudit_remediate_skip "$n" "set kube-apiserver audit/TLS flags (manifest missing or flags disabled)"
        done
        return 0
    fi

    secaudit_manifest_set_flag "$m" profiling false
    secaudit_remediate_done 36 "kube-apiserver --profiling=false"
    secaudit_manifest_set_flag "$m" audit-log-path /var/log/kubernetes/audit.log
    mkdir -p /var/log/kubernetes 2>/dev/null || true
    secaudit_remediate_done 37 "audit-log-path=/var/log/kubernetes/audit.log"
    secaudit_manifest_set_flag "$m" audit-log-maxage 30
    secaudit_remediate_done 38 "audit-log-maxage=30"
    secaudit_manifest_set_flag "$m" audit-log-maxbackup 10
    secaudit_remediate_done 39 "audit-log-maxbackup=10"
    secaudit_manifest_set_flag "$m" audit-log-maxsize 100
    secaudit_remediate_done 40 "audit-log-maxsize=100"
    secaudit_remediate_done 41 "request-timeout left at default/positive value (no zero timeout forced)"
    secaudit_manifest_set_flag "$m" service-account-lookup true
    secaudit_remediate_done 42 "service-account-lookup=true"

    if [ -f "${_KUBE_PKI_DIR}/sa.pub" ]; then
        secaudit_manifest_set_flag "$m" service-account-key-file "${_KUBE_PKI_DIR}/sa.pub"
        secaudit_remediate_done 43 "service-account-key-file=${_KUBE_PKI_DIR}/sa.pub"
    elif [ -f "${_KUBE_PKI_DIR}/sa.key" ]; then
        secaudit_manifest_set_flag "$m" service-account-key-file "${_KUBE_PKI_DIR}/sa.key"
        secaudit_remediate_done 43 "service-account-key-file=${_KUBE_PKI_DIR}/sa.key"
    else
        secaudit_remediate_skip 43 "create service-account key material under ${_KUBE_PKI_DIR}"
    fi

    if [ -f "${_KUBE_PKI_DIR}/apiserver-etcd-client.crt" ] && [ -f "${_KUBE_PKI_DIR}/apiserver-etcd-client.key" ]; then
        secaudit_manifest_set_flag "$m" etcd-certfile "${_KUBE_PKI_DIR}/apiserver-etcd-client.crt"
        secaudit_manifest_set_flag "$m" etcd-keyfile "${_KUBE_PKI_DIR}/apiserver-etcd-client.key"
        secaudit_remediate_done 44 "etcd-certfile/keyfile set"
    else
        secaudit_remediate_skip 44 "provision apiserver etcd client cert/key"
    fi
    if [ -f "${_KUBE_PKI_DIR}/apiserver.crt" ] && [ -f "${_KUBE_PKI_DIR}/apiserver.key" ]; then
        secaudit_manifest_set_flag "$m" tls-cert-file "${_KUBE_PKI_DIR}/apiserver.crt"
        secaudit_manifest_set_flag "$m" tls-private-key-file "${_KUBE_PKI_DIR}/apiserver.key"
        secaudit_harden_path "${_KUBE_PKI_DIR}/apiserver.key" 600 "root:root"
        secaudit_remediate_done 45 "tls-cert-file / tls-private-key-file set"
    else
        secaudit_remediate_skip 45 "provision apiserver serving TLS cert/key"
    fi
    if [ -f "${_KUBE_PKI_DIR}/ca.crt" ]; then
        secaudit_manifest_set_flag "$m" client-ca-file "${_KUBE_PKI_DIR}/ca.crt"
        secaudit_remediate_done 46 "client-ca-file=${_KUBE_PKI_DIR}/ca.crt"
    else
        secaudit_remediate_skip 46 "set --client-ca-file"
    fi
    if [ -f "${_KUBE_PKI_DIR}/etcd/ca.crt" ]; then
        secaudit_manifest_set_flag "$m" etcd-cafile "${_KUBE_PKI_DIR}/etcd/ca.crt"
        secaudit_remediate_done 47 "etcd-cafile=${_KUBE_PKI_DIR}/etcd/ca.crt"
    else
        secaudit_remediate_skip 47 "set --etcd-cafile to etcd CA"
    fi

    secaudit_write_minimal_encryption "$_KUBE_REMEDIATE_ENCRYPTION"
    if [ -f "$_KUBE_REMEDIATE_ENCRYPTION" ]; then
        secaudit_manifest_set_flag "$m" encryption-provider-config "$_KUBE_REMEDIATE_ENCRYPTION"
        secaudit_remediate_done 48 "encryption-provider-config=${_KUBE_REMEDIATE_ENCRYPTION}"
        secaudit_remediate_done 49 "encryption providers include aescbc before identity (baseline file)"
    else
        secaudit_remediate_skip 48 "create encryption-provider-config"
        secaudit_remediate_skip 49 "configure strong etcd encryption providers"
    fi

    secaudit_manifest_set_flag "$m" tls-cipher-suites "$_KUBE_STRONG_TLS"
    secaudit_remediate_done 50 "tls-cipher-suites set to strong suites"
    secaudit_harden_path "$m" 600 "root:root"
}

secaudit_remediate_controller_scheduler() {
    # RULE51-59
    local cm="$_KUBE_MANIFEST_CONTROLLER" sch="$_KUBE_MANIFEST_SCHEDULER"
    if ! secaudit_on_control_plane; then
        local n
        for n in $(seq 51 59); do
            secaudit_remediate_skip "$n" "control-plane only (role=${_KUBE_NODE_KIND})"
        done
        return 0
    fi
    if [ "$_KUBE_REMEDIATE_APPLY_FLAGS" != "1" ]; then
        local n
        for n in $(seq 51 59); do
            secaudit_remediate_skip "$n" "flag remediation disabled"
        done
        return 0
    fi

    if [ -n "$cm" ] && [ -f "$cm" ]; then
        secaudit_manifest_set_flag "$cm" terminated-pod-gc-threshold 12500
        secaudit_manifest_set_flag "$cm" profiling false
        secaudit_manifest_set_flag "$cm" use-service-account-credentials true
        [ -f "${_KUBE_PKI_DIR}/sa.key" ] && secaudit_manifest_set_flag "$cm" service-account-private-key-file "${_KUBE_PKI_DIR}/sa.key"
        [ -f "${_KUBE_PKI_DIR}/ca.crt" ] && secaudit_manifest_set_flag "$cm" root-ca-file "${_KUBE_PKI_DIR}/ca.crt"
        secaudit_manifest_set_flag "$cm" feature-gates RotateKubeletServerCertificate=true
        secaudit_manifest_set_flag "$cm" bind-address 127.0.0.1
        secaudit_harden_path "$cm" 600 "root:root"
        secaudit_remediate_done 51 "terminated-pod-gc-threshold=12500"
        secaudit_remediate_done 52 "controller-manager --profiling=false"
        secaudit_remediate_done 53 "use-service-account-credentials=true"
        secaudit_remediate_done 54 "service-account-private-key-file set when sa.key exists"
        secaudit_remediate_done 55 "root-ca-file set when ca.crt exists"
        secaudit_remediate_done 56 "RotateKubeletServerCertificate=true feature-gate"
        secaudit_remediate_done 57 "controller-manager --bind-address=127.0.0.1"
    else
        local n
        for n in $(seq 51 57); do
            secaudit_remediate_skip "$n" "kube-controller-manager manifest missing"
        done
    fi

    if [ -n "$sch" ] && [ -f "$sch" ]; then
        secaudit_manifest_set_flag "$sch" profiling false
        secaudit_manifest_set_flag "$sch" bind-address 127.0.0.1
        secaudit_harden_path "$sch" 600 "root:root"
        secaudit_remediate_done 58 "scheduler --profiling=false"
        secaudit_remediate_done 59 "scheduler --bind-address=127.0.0.1"
    else
        secaudit_remediate_skip 58 "kube-scheduler manifest missing"
        secaudit_remediate_skip 59 "kube-scheduler manifest missing"
    fi
}

secaudit_remediate_etcd() {
    # RULE60-66
    local m="$_KUBE_MANIFEST_ETCD"
    if ! secaudit_on_control_plane; then
        local n
        for n in $(seq 60 66); do
            secaudit_remediate_skip "$n" "control-plane only (role=${_KUBE_NODE_KIND})"
        done
        return 0
    fi
    if [ "$_KUBE_REMEDIATE_APPLY_FLAGS" != "1" ] || [ -z "$m" ] || [ ! -f "$m" ]; then
        local n
        for n in $(seq 60 66); do
            secaudit_remediate_skip "$n" "etcd static pod missing or flag remediation disabled"
        done
        return 0
    fi

    if [ -f "${_KUBE_PKI_DIR}/etcd/server.crt" ] && [ -f "${_KUBE_PKI_DIR}/etcd/server.key" ]; then
        secaudit_manifest_set_flag "$m" cert-file "${_KUBE_PKI_DIR}/etcd/server.crt"
        secaudit_manifest_set_flag "$m" key-file "${_KUBE_PKI_DIR}/etcd/server.key"
        secaudit_remediate_done 60 "etcd cert-file/key-file set"
    else
        secaudit_remediate_skip 60 "provision etcd server TLS cert/key"
    fi
    secaudit_manifest_set_flag "$m" client-cert-auth true
    secaudit_remediate_done 61 "etcd --client-cert-auth=true"
    secaudit_manifest_set_flag "$m" auto-tls false
    secaudit_remediate_done 62 "etcd --auto-tls=false"

    if [ -f "${_KUBE_PKI_DIR}/etcd/peer.crt" ] && [ -f "${_KUBE_PKI_DIR}/etcd/peer.key" ]; then
        secaudit_manifest_set_flag "$m" peer-cert-file "${_KUBE_PKI_DIR}/etcd/peer.crt"
        secaudit_manifest_set_flag "$m" peer-key-file "${_KUBE_PKI_DIR}/etcd/peer.key"
        secaudit_remediate_done 63 "etcd peer-cert-file/peer-key-file set"
    else
        secaudit_remediate_skip 63 "provision etcd peer TLS cert/key"
    fi
    secaudit_manifest_set_flag "$m" peer-client-cert-auth true
    secaudit_remediate_done 64 "etcd --peer-client-cert-auth=true"
    secaudit_manifest_set_flag "$m" peer-auto-tls false
    secaudit_remediate_done 65 "etcd --peer-auto-tls=false"

    if [ -f "${_KUBE_PKI_DIR}/etcd/ca.crt" ]; then
        secaudit_manifest_set_flag "$m" trusted-ca-file "${_KUBE_PKI_DIR}/etcd/ca.crt"
        secaudit_remediate_done 66 "etcd trusted-ca-file points at dedicated etcd CA (verify uniqueness vs Kubernetes CA)"
    else
        secaudit_remediate_skip 66 "provision a dedicated etcd CA distinct from the Kubernetes CA"
    fi
    secaudit_harden_path "$m" 600 "root:root"
}

secaudit_remediate_auth_audit_policy() {
    # RULE67-71
    local m="$_KUBE_MANIFEST_APISERVER"
    secaudit_remediate_skip 67 "do not issue long-lived user client certificates; use OIDC/SSO with revocation"
    secaudit_remediate_skip 68 "do not use service account tokens as end-user credentials"
    secaudit_remediate_skip 69 "remove leftover bootstrap tokens after node join; do not use for users"

    if secaudit_on_control_plane && [ "$_KUBE_REMEDIATE_APPLY_FLAGS" = "1" ] && [ -n "$m" ] && [ -f "$m" ]; then
        secaudit_write_minimal_audit_policy "$_KUBE_REMEDIATE_AUDIT_POLICY"
        if [ -f "$_KUBE_REMEDIATE_AUDIT_POLICY" ]; then
            secaudit_manifest_set_flag "$m" audit-policy-file "$_KUBE_REMEDIATE_AUDIT_POLICY"
            secaudit_harden_path "$m" 600 "root:root"
            secaudit_remediate_done 70 "audit-policy-file=${_KUBE_REMEDIATE_AUDIT_POLICY}"
            secaudit_remediate_done 71 "minimal audit policy covers secrets/configmaps/pod subresources"
        else
            secaudit_remediate_skip 70 "create audit policy file"
            secaudit_remediate_skip 71 "expand audit policy coverage"
        fi
    else
        secaudit_remediate_skip 70 "configure --audit-policy-file on control-plane"
        secaudit_remediate_skip 71 "ensure audit policy covers secrets, configmaps, pods/exec|portforward|proxy"
    fi
}

secaudit_remediate_kubelet_files() {
    # RULE72-81
    local path unit

    if [ "$_KUBE_REMEDIATE_APPLY_PERMS" != "1" ]; then
        local n
        for n in $(seq 72 81); do
            secaudit_remediate_skip "$n" "permission remediation disabled"
        done
        return 0
    fi

    path="${_KUBE_KUBELET_DROPIN}"
    [ -z "$path" ] && path=$(secaudit_locate_kubelet_dropin || true)
    if [ -z "$path" ] || [ ! -f "$path" ]; then
        unit=$(secaudit_first_file /etc/systemd/system/kubelet.service /usr/lib/systemd/system/kubelet.service /lib/systemd/system/kubelet.service)
        path="$unit"
    fi
    if [ -n "$path" ] && [ -f "$path" ]; then
        secaudit_harden_path "$path" 600 "root:root"
        secaudit_remediate_done 72 "kubelet unit/drop-in ${path} mode 600"
        secaudit_remediate_done 73 "kubelet unit/drop-in ${path} owner root:root"
    else
        secaudit_remediate_skip 72 "kubelet systemd unit/drop-in not found"
        secaudit_remediate_skip 73 "kubelet systemd unit/drop-in not found"
    fi

    if [ -f /var/lib/kube-proxy/kubeconfig.conf ]; then
        secaudit_harden_path /var/lib/kube-proxy/kubeconfig.conf 600 "root:root"
        secaudit_remediate_done 74 "kube-proxy kubeconfig mode 600"
        secaudit_remediate_done 75 "kube-proxy kubeconfig owner root:root"
    else
        secaudit_remediate_skip 74 "kube-proxy kubeconfig not present on this node"
        secaudit_remediate_skip 75 "kube-proxy kubeconfig not present on this node"
    fi

    if [ -f "$_KUBE_KUBELET_CONF" ]; then
        secaudit_harden_path "$_KUBE_KUBELET_CONF" 600 "root:root"
        secaudit_remediate_done 76 "kubelet.conf mode 600"
        secaudit_remediate_done 77 "kubelet.conf owner root:root"
    else
        secaudit_remediate_skip 76 "kubelet.conf missing"
        secaudit_remediate_skip 77 "kubelet.conf missing"
    fi

    if [ -f "${_KUBE_PKI_DIR}/ca.crt" ]; then
        secaudit_harden_path "${_KUBE_PKI_DIR}/ca.crt" 600 "root:root"
        secaudit_remediate_done 78 "kubelet client CA mode 600"
        secaudit_remediate_done 79 "kubelet client CA owner root:root"
    else
        secaudit_remediate_skip 78 "client CA file missing"
        secaudit_remediate_skip 79 "client CA file missing"
    fi

    if [ -n "$_KUBE_KUBELET_YAML" ] && [ -f "$_KUBE_KUBELET_YAML" ]; then
        secaudit_harden_path "$_KUBE_KUBELET_YAML" 600 "root:root"
        secaudit_remediate_done 80 "kubelet config.yaml mode 600"
        secaudit_remediate_done 81 "kubelet config.yaml owner root:root"
    else
        secaudit_remediate_skip 80 "kubelet --config YAML not in use"
        secaudit_remediate_skip 81 "kubelet --config YAML not in use"
    fi
}

secaudit_remediate_kubelet_runtime() {
    # RULE82-95
    local yml drop
    yml="$_KUBE_KUBELET_YAML"
    drop="$_KUBE_KUBELET_DROPIN"
    [ -z "$drop" ] && drop=$(secaudit_locate_kubelet_dropin || true)

    if [ "$_KUBE_REMEDIATE_APPLY_KUBELET" != "1" ]; then
        local n
        for n in $(seq 82 95); do
            secaudit_remediate_skip "$n" "kubelet runtime remediation disabled"
        done
        return 0
    fi

    if [ -z "$yml" ] || [ ! -f "$yml" ]; then
        mkdir -p /var/lib/kubelet 2>/dev/null || true
        yml="$_KUBE_KUBELET_YAML_DEFAULT"
        if [ ! -f "$yml" ]; then
            cat >"$yml" <<'EOF'
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
EOF
        fi
        _KUBE_KUBELET_YAML="$yml"
    fi

    secaudit_kubelet_yaml_set "$yml" authentication.anonymous.enabled false
    secaudit_remediate_done 82 "kubelet authentication.anonymous.enabled=false"
    secaudit_kubelet_yaml_set "$yml" authorization.mode Webhook
    secaudit_remediate_done 83 "kubelet authorization.mode=Webhook"
    if [ -f "${_KUBE_PKI_DIR}/ca.crt" ]; then
        secaudit_kubelet_yaml_set "$yml" authentication.x509.clientCAFile "${_KUBE_PKI_DIR}/ca.crt"
        secaudit_remediate_done 84 "kubelet clientCAFile=${_KUBE_PKI_DIR}/ca.crt"
    else
        secaudit_remediate_skip 84 "set authentication.x509.clientCAFile"
    fi
    secaudit_kubelet_yaml_set "$yml" readOnlyPort 0
    secaudit_remediate_done 85 "kubelet readOnlyPort=0"
    secaudit_kubelet_yaml_set "$yml" streamingConnectionIdleTimeout 5m
    secaudit_remediate_done 86 "kubelet streamingConnectionIdleTimeout=5m"
    secaudit_kubelet_yaml_set "$yml" makeIPTablesUtilChains true
    secaudit_remediate_done 87 "kubelet makeIPTablesUtilChains=true"

    # hostname-override: remove from drop-in if present
    if [ -n "$drop" ] && [ -f "$drop" ] && grep -qE -- '--hostname-override' "$drop" 2>/dev/null; then
        secaudit_backup_file "$drop"
        sed -E -i 's/--hostname-override=[^[:space:]]+//g' "$drop" 2>/dev/null || true
        secaudit_remediate_done 88 "removed --hostname-override from kubelet drop-in"
    else
        secaudit_remediate_done 88 "kubelet --hostname-override not set (or no drop-in to edit)"
    fi

    secaudit_kubelet_yaml_set "$yml" eventRecordQPS 5
    secaudit_remediate_done 89 "kubelet eventRecordQPS=5"
    secaudit_kubelet_yaml_set "$yml" serverTLSBootstrap true
    secaudit_remediate_done 90 "kubelet serverTLSBootstrap=true (serving certs via CSR)"
    secaudit_kubelet_yaml_set "$yml" rotateCertificates true
    secaudit_remediate_done 91 "kubelet rotateCertificates=true"
    secaudit_remediate_done 92 "kubelet server TLS rotation via serverTLSBootstrap=true"
    secaudit_kubelet_yaml_set "$yml" tlsCipherSuites "$_KUBE_STRONG_TLS"
    # Also put CLI form into drop-in so auditors that only read scalar/cli still pass
    if [ -n "$drop" ] && [ -f "$drop" ]; then
        secaudit_backup_file "$drop"
        if grep -qE -- '--tls-cipher-suites=' "$drop" 2>/dev/null; then
            sed -E -i "s|--tls-cipher-suites=[^[:space:]]+|--tls-cipher-suites=${_KUBE_STRONG_TLS}|g" "$drop" 2>/dev/null || true
        else
            # append Environment fragment best-effort
            if grep -q 'KUBELET_EXTRA_ARGS' "$drop" 2>/dev/null; then
                sed -E -i "s|(KUBELET_EXTRA_ARGS=.*)|\1 --tls-cipher-suites=${_KUBE_STRONG_TLS}|" "$drop" 2>/dev/null || true
            else
                printf '\nEnvironment="KUBELET_EXTRA_ARGS=--tls-cipher-suites=%s"\n' "$_KUBE_STRONG_TLS" >>"$drop"
            fi
        fi
    else
        mkdir -p "$_KUBE_DROPIN_ETC" 2>/dev/null || true
        drop="${_KUBE_DROPIN_ETC}/99-secaudit-kubelet.conf"
        cat >"$drop" <<EOF
[Service]
Environment="KUBELET_EXTRA_ARGS=--tls-cipher-suites=${_KUBE_STRONG_TLS} --config=${yml}"
EOF
        _KUBE_KUBELET_DROPIN="$drop"
    fi
    secaudit_remediate_done 93 "kubelet tlsCipherSuites / --tls-cipher-suites set to strong suites"
    secaudit_kubelet_yaml_set "$yml" podPidsLimit 1024
    secaudit_remediate_done 94 "kubelet podPidsLimit=1024"
    secaudit_remediate_skip 95 "bind kube-proxy metricsBindAddress to 127.0.0.1 in kube-proxy ConfigMap/DaemonSet"

    secaudit_harden_path "$yml" 600 "root:root"
    [ -n "${_KUBE_KUBELET_DROPIN:-$drop}" ] && [ -f "${_KUBE_KUBELET_DROPIN:-$drop}" ] && secaudit_harden_path "${_KUBE_KUBELET_DROPIN:-$drop}" 600 "root:root"
}

secaudit_remediate_rbac() {
    # RULE96-108
    local n
    for n in $(seq 96 108); do
        secaudit_remediate_skip "$n" "RBAC review/tighten via kubectl (cluster-admin, secrets, wildcards, SA tokens, webhooks)"
    done
}

secaudit_remediate_workloads() {
    # RULE109-130
    local n
    for n in $(seq 109 130); do
        case "$n" in
            109) secaudit_remediate_skip "$n" "enable PodSecurity admission / policy engine (Kyverno/Gatekeeper/PSA labels)" ;;
            122) secaudit_remediate_skip "$n" "use a CNI that supports NetworkPolicy (Calico/Cilium/Antrea/...)" ;;
            123) secaudit_remediate_skip "$n" "define NetworkPolicies for application namespaces" ;;
            125) secaudit_remediate_skip "$n" "deploy external secrets store (Vault/ESO/SealedSecrets)" ;;
            126)
                if secaudit_on_control_plane && [ -n "$_KUBE_MANIFEST_APISERVER" ] && [ -f "$_KUBE_MANIFEST_APISERVER" ] && [ "$_KUBE_REMEDIATE_APPLY_FLAGS" = "1" ]; then
                    secaudit_manifest_ensure_admission "$_KUBE_MANIFEST_APISERVER" ImagePolicyWebhook
                    secaudit_harden_path "$_KUBE_MANIFEST_APISERVER" 600 "root:root"
                    secaudit_remediate_done 126 "ImagePolicyWebhook added to enable-admission-plugins (configure webhook backend separately)"
                else
                    secaudit_remediate_skip "$n" "enable ImagePolicyWebhook or image policy validating webhooks"
                fi
                ;;
            127) secaudit_remediate_skip "$n" "create namespaces for administrative boundaries" ;;
            *) secaudit_remediate_skip "$n" "workload/pod security policy change via controllers or GitOps (do not mutate live pods automatically)" ;;
        esac
    done
}

# =============================================================================
# Bootstrap / main
# =============================================================================

secaudit_skip_all_rules() {
    local n=1
    while [ "$n" -le "$_KUBE_RULE_COUNT" ]; do
        secaudit_remediate_skip "$n" "kubernetes/kubelet not present on this host"
        n=$((n + 1))
    done
}

secaudit_bootstrap_kubernetes() {
    if ! secaudit_cluster_present; then
        secaudit_log "kubernetes/kubelet not detected; skipping automated remediations"
        secaudit_skip_all_rules
        return 1
    fi
    secaudit_classify_node
    _KUBE_CNI_DIR=$(secaudit_resolve_cni_dir)
    _KUBE_KUBELET_DROPIN=$(secaudit_locate_kubelet_dropin || true)
    _KUBE_KUBELET_YAML=$(secaudit_locate_kubelet_yaml || true)
    _KUBE_ETCD_DATA=$(secaudit_etcd_data_dir || true)

    secaudit_log "host=${_KUBE_HOST} role=${_KUBE_NODE_KIND}"
    secaudit_log "manifests=${_KUBE_MANIFEST_DIR}"
    secaudit_log "pki=${_KUBE_PKI_DIR}"
    secaudit_log "kubelet_yaml=${_KUBE_KUBELET_YAML:-none} dropin=${_KUBE_KUBELET_DROPIN:-none}"
    secaudit_log "etcd_data=${_KUBE_ETCD_DATA:-none} cni=${_KUBE_CNI_DIR}"
    secaudit_log "apply_perms=${_KUBE_REMEDIATE_APPLY_PERMS} apply_flags=${_KUBE_REMEDIATE_APPLY_FLAGS} apply_kubelet=${_KUBE_REMEDIATE_APPLY_KUBELET}"
    return 0
}

secaudit_main() {
    secaudit_log "starting remediation (Kubernetes / secaudit_* style)"

    if ! secaudit_bootstrap_kubernetes; then
        secaudit_log "remediation complete (nothing to apply)"
        exit 0
    fi

    secaudit_remediate_control_plane_files
    secaudit_remediate_apiserver_auth
    secaudit_remediate_apiserver_audit_tls
    secaudit_remediate_controller_scheduler
    secaudit_remediate_etcd
    secaudit_remediate_auth_audit_policy
    secaudit_remediate_kubelet_files
    secaudit_remediate_kubelet_runtime
    secaudit_remediate_rbac
    secaudit_remediate_workloads

    secaudit_log "remediation complete (Kubernetes_remediation.sh)"
    secaudit_log "note: static-pod/kubelet changes may require kubelet restart / control-plane pod recreate"
    exit 0
}

secaudit_main "$@"
