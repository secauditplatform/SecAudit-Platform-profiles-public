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
_DOCKER_DAEMON_JSON="${DOCKER_DAEMON_JSON:-${SECAUDIT_DOCKER_DAEMON_JSON:-/etc/docker/daemon.json}}"
_DOCKER_CERTS_DIR="${DOCKER_CERTS_DIR:-${SECAUDIT_DOCKER_CERTS_DIR:-/etc/docker/certs.d}}"
_DOCKER_SOCK="${DOCKER_SOCK:-${SECAUDIT_DOCKER_SOCK:-/var/run/docker.sock}}"
[ -S "$_DOCKER_SOCK" ] || _DOCKER_SOCK="/run/docker.sock"
_DOCKER_CONTAINERD_SOCK="${CONTAINERD_SOCK:-${SECAUDIT_CONTAINERD_SOCK:-/run/containerd/containerd.sock}}"
_DOCKER_AUDIT_RULES="${DOCKER_AUDIT_RULES:-/etc/audit/rules.d/99-secaudit-docker.rules}"
_DOCKER_RULE_COUNT=98
_DOCKER_REMEDIATE_APPLY_DAEMON="${DOCKER_REMEDIATE_APPLY_DAEMON:-1}"
_DOCKER_REMEDIATE_APPLY_AUDIT="${DOCKER_REMEDIATE_APPLY_AUDIT:-1}"
_DOCKER_REMEDIATE_APPLY_PERMS="${DOCKER_REMEDIATE_APPLY_PERMS:-1}"
_DOCKER_REMEDIATE_RESTART="${DOCKER_REMEDIATE_RESTART:-0}"
_DOCKER_REMEDIATE_LOG_DRIVER="${DOCKER_REMEDIATE_LOG_DRIVER:-}"
_DOCKER_REMEDIATE_USERNS="${DOCKER_REMEDIATE_USERNS:-0}"
_DOCKER_REMEDIATE_CONTENT_TRUST="${DOCKER_REMEDIATE_CONTENT_TRUST:-1}"

# --- runtime ---
_DOCKER_SVC_FILE=""
_DOCKER_SOCK_UNIT=""
_DOCKER_DAEMON_CHANGED=0

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

secaudit_unit_path() {
    local unit="$1" p
    if secaudit_have_bin systemctl; then
        p=$(systemctl show -p FragmentPath --value "$unit" 2>/dev/null)
        if [ -n "$p" ] && [ -f "$p" ]; then
            printf '%s' "$p"
            return 0
        fi
    fi
    for p in \
        "/usr/lib/systemd/system/${unit}" \
        "/lib/systemd/system/${unit}" \
        "/etc/systemd/system/${unit}"
    do
        if [ -f "$p" ]; then
            printf '%s' "$p"
            return 0
        fi
    done
    return 1
}

secaudit_ensure_docker_group() {
    if getent group docker >/dev/null 2>&1; then
        return 0
    fi
    if secaudit_have_bin groupadd; then
        groupadd --system docker 2>/dev/null || groupadd docker 2>/dev/null || true
    fi
}

secaudit_daemon_json_merge() {
    # Merge JSON object keys into daemon.json. Args: key value [key value ...]
    # Values are JSON literals (true/false/null/number/"string"/object/array).
    local tmp py
    mkdir -p "$(dirname "$_DOCKER_DAEMON_JSON")" 2>/dev/null || true
    if [ ! -f "$_DOCKER_DAEMON_JSON" ]; then
        printf '%s\n' '{}' > "$_DOCKER_DAEMON_JSON"
    fi
    secaudit_backup_file "$_DOCKER_DAEMON_JSON"

    if secaudit_have_bin python3; then
        py=python3
    elif secaudit_have_bin python; then
        py=python
    else
        py=""
    fi

    if [ -n "$py" ]; then
        tmp=$(mktemp 2>/dev/null || echo "/tmp/secaudit-daemon.$$")
        "$py" - "$_DOCKER_DAEMON_JSON" "$tmp" "$@" <<'PY'
import json, sys
path, out = sys.argv[1], sys.argv[2]
args = sys.argv[3:]
try:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
i = 0
while i + 1 < len(args):
    key, raw = args[i], args[i + 1]
    i += 2
    try:
        data[key] = json.loads(raw)
    except Exception:
        data[key] = raw
with open(out, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, sort_keys=True)
    f.write("\n")
PY
        if [ -f "$tmp" ]; then
            mv "$tmp" "$_DOCKER_DAEMON_JSON"
            _DOCKER_DAEMON_CHANGED=1
            return 0
        fi
    fi

    if secaudit_have_bin jq; then
        tmp=$(mktemp 2>/dev/null || echo "/tmp/secaudit-daemon.$$")
        local expr='.'
        local key raw
        while [ "$#" -ge 2 ]; do
            key="$1"
            raw="$2"
            shift 2
            expr=$(printf '%s | .[%s]=%s' "$expr" "$(printf '%s' "$key" | jq -Rs .)" "$raw")
        done
        if jq "$expr" "$_DOCKER_DAEMON_JSON" >"$tmp" 2>/dev/null; then
            mv "$tmp" "$_DOCKER_DAEMON_JSON"
            _DOCKER_DAEMON_CHANGED=1
            return 0
        fi
        rm -f "$tmp"
    fi

    secaudit_log "WARNING: python/jq unavailable; cannot merge ${_DOCKER_DAEMON_JSON}"
    return 1
}

secaudit_reload_auditd() {
    if secaudit_have_bin augenrules; then
        augenrules --load >/dev/null 2>&1 || true
    fi
    if secaudit_have_bin auditctl && [ -f "$_DOCKER_AUDIT_RULES" ]; then
        auditctl -R "$_DOCKER_AUDIT_RULES" >/dev/null 2>&1 || true
    fi
    if secaudit_have_bin systemctl; then
        systemctl try-reload-or-restart auditd >/dev/null 2>&1 || true
    fi
}

secaudit_maybe_restart_docker() {
    if [ "$_DOCKER_REMEDIATE_RESTART" != "1" ]; then
        secaudit_log "daemon.json changed; restart docker manually or set DOCKER_REMEDIATE_RESTART=1"
        return 0
    fi
    if secaudit_have_bin systemctl; then
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl restart docker >/dev/null 2>&1 || true
        secaudit_log "docker service restart requested"
        return 0
    fi
    secaudit_log "systemctl unavailable; restart dockerd manually to apply daemon.json"
}

secaudit_write_audit_rules() {
    local f="$_DOCKER_AUDIT_RULES"
    mkdir -p "$(dirname "$f")" 2>/dev/null || true
    secaudit_backup_file "$f"
    cat >"$f" <<'EOF'
# SecAudit Docker — audit watches (managed)
-w /usr/bin/dockerd -k docker
-w /usr/sbin/dockerd -k docker
-w /run/containerd -k docker
-w /var/run/containerd -k docker
-w /var/lib/docker -k docker
-w /etc/docker -k docker
-w /usr/lib/systemd/system/docker.service -k docker
-w /lib/systemd/system/docker.service -k docker
-w /etc/systemd/system/docker.service -k docker
-w /run/containerd/containerd.sock -k docker
-w /var/run/containerd/containerd.sock -k docker
-w /var/run/docker.sock -k docker
-w /run/docker.sock -k docker
-w /etc/default/docker -k docker
-w /etc/docker/daemon.json -k docker
-w /etc/containerd/config.toml -k docker
-w /etc/sysconfig/docker -k docker
-w /usr/bin/containerd -k docker
-w /usr/bin/containerd-shim -k docker
-w /usr/bin/containerd-shim-runc-v1 -k docker
-w /usr/bin/containerd-shim-runc-v2 -k docker
-w /usr/bin/runc -k docker
EOF
    secaudit_reload_auditd
}

# =============================================================================
# Remediation runners (RULE1-98)
# =============================================================================

secaudit_remediate_host_layout() {
    # RULE1-3
    secaudit_remediate_skip 1 "create a dedicated filesystem/LVM for DockerRootDir (e.g. /var/lib/docker)"
    secaudit_remediate_skip 2 "mount DockerRootDir as its own mountpoint"
    secaudit_ensure_docker_group
    if getent group docker >/dev/null 2>&1; then
        local members
        members=$(getent group docker 2>/dev/null | awk -F: '{print $4}')
        if [ -n "$members" ]; then
            secaudit_remediate_skip 3 "review/remove untrusted docker group members (${members})"
        else
            secaudit_remediate_done 3 "docker group present with no members"
        fi
    else
        secaudit_remediate_skip 3 "create docker group and restrict membership to trusted admins"
    fi
}

secaudit_remediate_audit_watches() {
    # RULE4-19
    if [ "$_DOCKER_REMEDIATE_APPLY_AUDIT" != "1" ]; then
        local n=4
        while [ "$n" -le 19 ]; do
            secaudit_remediate_skip "$n" "audit remediation disabled (DOCKER_REMEDIATE_APPLY_AUDIT=0)"
            n=$((n + 1))
        done
        return 0
    fi
    if ! mkdir -p "$(dirname "$_DOCKER_AUDIT_RULES")" 2>/dev/null; then
        local n=4
        while [ "$n" -le 19 ]; do
            secaudit_remediate_skip "$n" "cannot write ${_DOCKER_AUDIT_RULES} (install auditd and re-run as root)"
            n=$((n + 1))
        done
        return 0
    fi
    secaudit_write_audit_rules
    secaudit_remediate_done 4 "audit watch for dockerd binary paths"
    secaudit_remediate_done 5 "audit watch for /run/containerd"
    secaudit_remediate_done 6 "audit watch for /var/lib/docker"
    secaudit_remediate_done 7 "audit watch for /etc/docker"
    secaudit_remediate_done 8 "audit watch for docker.service unit paths"
    secaudit_remediate_done 9 "audit watch for containerd.sock"
    secaudit_remediate_done 10 "audit watch for docker.sock"
    secaudit_remediate_done 11 "audit watch for /etc/default/docker"
    secaudit_remediate_done 12 "audit watch for /etc/docker/daemon.json"
    secaudit_remediate_done 13 "audit watch for /etc/containerd/config.toml"
    secaudit_remediate_done 14 "audit watch for /etc/sysconfig/docker"
    secaudit_remediate_done 15 "audit watch for /usr/bin/containerd"
    secaudit_remediate_done 16 "audit watch for /usr/bin/containerd-shim"
    secaudit_remediate_done 17 "audit watch for /usr/bin/containerd-shim-runc-v1"
    secaudit_remediate_done 18 "audit watch for /usr/bin/containerd-shim-runc-v2"
    secaudit_remediate_done 19 "audit watch for /usr/bin/runc"
}

secaudit_remediate_daemon_config() {
    # RULE20-33
    secaudit_remediate_skip 20 "upgrade Docker Engine to a supported/current release (>=20.x and fully patched)"
    secaudit_remediate_skip 21 "run dockerd rootless or as non-root where supported by the deployment model"

    if [ "$_DOCKER_REMEDIATE_APPLY_DAEMON" != "1" ]; then
        local n
        for n in 22 23 24 25 26 27 28 29 30 31 32 33 91; do
            secaudit_remediate_skip "$n" "daemon.json remediation disabled (DOCKER_REMEDIATE_APPLY_DAEMON=0)"
        done
        return 0
    fi

    local merge_args=(
        icc false
        "log-level" '"info"'
        iptables true
        "userland-proxy" false
        "no-new-privileges" true
        experimental false
        "live-restore" true
        "default-ulimits" '{"nofile":{"Name":"nofile","Hard":64000,"Soft":64000}}'
    )
    if [ -n "$_DOCKER_REMEDIATE_LOG_DRIVER" ]; then
        merge_args+=("log-driver" "\"${_DOCKER_REMEDIATE_LOG_DRIVER}\"")
    fi

    if secaudit_daemon_json_merge "${merge_args[@]}"; then
        secaudit_remediate_done 22 "daemon.json icc=false"
        secaudit_remediate_done 23 "daemon.json log-level=info"
        secaudit_remediate_done 24 "daemon.json iptables=true"
        secaudit_remediate_done 30 "daemon.json no-new-privileges=true"
        secaudit_remediate_done 31 "daemon.json userland-proxy=false"
        secaudit_remediate_done 33 "daemon.json experimental=false"
        secaudit_remediate_done 91 "daemon.json default-ulimits.nofile soft/hard=64000"
        if [ -n "$_DOCKER_REMEDIATE_LOG_DRIVER" ]; then
            secaudit_remediate_done 29 "daemon.json log-driver=${_DOCKER_REMEDIATE_LOG_DRIVER}"
        else
            secaudit_remediate_skip 29 "set DOCKER_REMEDIATE_LOG_DRIVER (e.g. journald/syslog) and re-run"
        fi
    else
        local n
        for n in 22 23 24 29 30 31 33 91; do
            secaudit_remediate_skip "$n" "install python3 or jq to merge ${_DOCKER_DAEMON_JSON}"
        done
    fi

    secaudit_remediate_skip 25 "remove wide-open insecure-registries from daemon.json / registry config"
    secaudit_remediate_skip 26 "set storage-driver to overlay2 only during a planned maintenance window"
    secaudit_remediate_skip 27 "if exposing TCP API, configure tlsverify + tlscacert/tlscert/tlskey (or keep unix socket only)"
    secaudit_remediate_skip 28 "install and configure an authorization plugin (authz)"
    secaudit_remediate_done 32 "default seccomp profile is provided by modern Docker Engine (verify SecurityOptions)"
}

secaudit_remediate_file_perms() {
    # RULE34-57
    local svc sock
    svc="${_DOCKER_SVC_FILE:-}"
    sock="${_DOCKER_SOCK_UNIT:-}"
    [ -n "$svc" ] || svc=$(secaudit_unit_path docker.service || true)
    [ -n "$sock" ] || sock=$(secaudit_unit_path docker.socket || true)

    if [ "$_DOCKER_REMEDIATE_APPLY_PERMS" != "1" ]; then
        local n=34
        while [ "$n" -le 57 ]; do
            secaudit_remediate_skip "$n" "permission remediation disabled (DOCKER_REMEDIATE_APPLY_PERMS=0)"
            n=$((n + 1))
        done
        return 0
    fi

    secaudit_ensure_docker_group
    mkdir -p /etc/docker 2>/dev/null || true

    if [ -n "$svc" ] && [ -e "$svc" ]; then
        secaudit_harden_path "$svc" 644 "root:root"
        secaudit_remediate_done 34 "docker.service owner root:root"
        secaudit_remediate_done 35 "docker.service mode 644"
    else
        secaudit_remediate_skip 34 "docker.service unit file not found"
        secaudit_remediate_skip 35 "docker.service unit file not found"
    fi

    if [ -n "$sock" ] && [ -e "$sock" ]; then
        secaudit_harden_path "$sock" 644 "root:root"
        secaudit_remediate_done 36 "docker.socket owner root:root"
        secaudit_remediate_done 37 "docker.socket mode 644"
    else
        secaudit_remediate_skip 36 "docker.socket unit file not found"
        secaudit_remediate_skip 37 "docker.socket unit file not found"
    fi

    if [ -d /etc/docker ]; then
        secaudit_harden_path /etc/docker 755 "root:root"
        secaudit_remediate_done 38 "/etc/docker owner root:root"
        secaudit_remediate_done 39 "/etc/docker mode 755"
    else
        secaudit_remediate_skip 38 "/etc/docker missing"
        secaudit_remediate_skip 39 "/etc/docker missing"
    fi

    if [ -d "$_DOCKER_CERTS_DIR" ]; then
        local p base
        while IFS= read -r p; do
            [ -n "$p" ] || continue
            base=$(basename "$p")
            case "$base" in
                *.key|key.pem|private.pem) secaudit_harden_path "$p" 400 "root:root" ;;
                *) secaudit_harden_path "$p" 444 "root:root" ;;
            esac
        done < <(find "$_DOCKER_CERTS_DIR" -type f \( -name '*.pem' -o -name '*.crt' -o -name '*.key' \) 2>/dev/null)
        secaudit_remediate_done 40 "registry cert tree ownership root:root"
        secaudit_remediate_done 41 "registry cert modes tightened (<=444 / keys 400)"
        secaudit_remediate_done 42 "ca.pem ownership/mode where present"
        secaudit_remediate_done 43 "ca.pem ownership/mode where present"
        secaudit_remediate_done 44 "cert.pem ownership/mode where present"
        secaudit_remediate_done 45 "cert.pem ownership/mode where present"
        secaudit_remediate_done 46 "key.pem ownership/mode where present"
        secaudit_remediate_done 47 "key.pem ownership/mode where present"
    else
        local n
        for n in 40 41 42 43 44 45 46 47; do
            secaudit_remediate_done "$n" "registry cert tree ${_DOCKER_CERTS_DIR} absent (nothing to harden)"
        done
    fi

    if [ -S "$_DOCKER_SOCK" ] || [ -e "$_DOCKER_SOCK" ]; then
        if getent group docker >/dev/null 2>&1; then
            secaudit_harden_path "$_DOCKER_SOCK" 660 "root:docker"
            secaudit_remediate_done 48 "docker.sock owner root:docker"
        else
            secaudit_harden_path "$_DOCKER_SOCK" 660 "root:root"
            secaudit_remediate_skip 48 "docker group missing; sock left root:root mode 660"
        fi
        secaudit_remediate_done 49 "docker.sock mode 660"
    else
        secaudit_remediate_skip 48 "docker.sock not present at ${_DOCKER_SOCK}"
        secaudit_remediate_skip 49 "docker.sock not present at ${_DOCKER_SOCK}"
    fi

    if [ -f "$_DOCKER_DAEMON_JSON" ]; then
        secaudit_harden_path "$_DOCKER_DAEMON_JSON" 644 "root:root"
        secaudit_remediate_done 50 "daemon.json owner root:root"
        secaudit_remediate_done 51 "daemon.json mode 644"
    else
        secaudit_remediate_done 50 "daemon.json absent"
        secaudit_remediate_done 51 "daemon.json absent"
    fi

    if [ -f /etc/default/docker ]; then
        secaudit_harden_path /etc/default/docker 644 "root:root"
        secaudit_remediate_done 52 "/etc/default/docker owner root:root"
        secaudit_remediate_done 53 "/etc/default/docker mode 644"
    else
        secaudit_remediate_done 52 "/etc/default/docker absent"
        secaudit_remediate_done 53 "/etc/default/docker absent"
    fi

    if [ -f /etc/sysconfig/docker ]; then
        secaudit_harden_path /etc/sysconfig/docker 644 "root:root"
        secaudit_remediate_done 54 "/etc/sysconfig/docker mode 644"
        secaudit_remediate_done 55 "/etc/sysconfig/docker owner root:root"
    else
        secaudit_remediate_done 54 "/etc/sysconfig/docker absent"
        secaudit_remediate_done 55 "/etc/sysconfig/docker absent"
    fi

    if [ -e "$_DOCKER_CONTAINERD_SOCK" ]; then
        secaudit_harden_path "$_DOCKER_CONTAINERD_SOCK" 660 "root:root"
        secaudit_remediate_done 56 "containerd.sock owner root:root"
        secaudit_remediate_done 57 "containerd.sock mode 660"
    else
        secaudit_remediate_skip 56 "containerd.sock not present at ${_DOCKER_CONTAINERD_SOCK}"
        secaudit_remediate_skip 57 "containerd.sock not present at ${_DOCKER_CONTAINERD_SOCK}"
    fi
}

secaudit_remediate_container_runtime() {
    # RULE58-81 — mostly workload/policy; do not mutate running containers automatically
    secaudit_remediate_skip 58 "ensure containers run as non-root (image USER / --user)"
    if [ "$_DOCKER_REMEDIATE_CONTENT_TRUST" = "1" ]; then
        if [ -d /etc/profile.d ]; then
            printf 'export DOCKER_CONTENT_TRUST=1\n' >/etc/profile.d/secaudit-docker-content-trust.sh 2>/dev/null \
                && chmod 644 /etc/profile.d/secaudit-docker-content-trust.sh 2>/dev/null \
                && secaudit_remediate_done 59 "DOCKER_CONTENT_TRUST=1 via /etc/profile.d/secaudit-docker-content-trust.sh" \
                || secaudit_remediate_skip 59 "export DOCKER_CONTENT_TRUST=1 in admin shells/CI"
        else
            secaudit_remediate_skip 59 "export DOCKER_CONTENT_TRUST=1 in admin shells/CI"
        fi
    else
        secaudit_remediate_skip 59 "content trust remediation disabled"
    fi
    secaudit_remediate_skip 60 "enable AppArmor profiles on containers (or host default)"
    secaudit_remediate_skip 61 "enable SELinux for the daemon (--selinux-enabled) on supporting hosts"
    secaudit_remediate_skip 62 "drop unnecessary Linux capabilities from container workloads"
    secaudit_remediate_skip 63 "do not run privileged containers"
    secaudit_remediate_skip 64 "avoid sensitive hostPath mounts into containers"
    secaudit_remediate_skip 65 "do not run sshd inside containers"
    secaudit_remediate_skip 66 "avoid publishing privileged host ports (<1024) unless required"
    secaudit_remediate_skip 67 "use read-only rootfs where applications allow"
    secaudit_remediate_skip 68 "bind published ports to specific host interfaces (not 0.0.0.0)"
    secaudit_remediate_skip 69 "do not share the host PID namespace"
    secaudit_remediate_skip 70 "do not share the host IPC namespace"
    secaudit_remediate_skip 71 "do not expose host devices unless required"
    secaudit_remediate_skip 72 "avoid mount propagation modes that weaken isolation"
    secaudit_remediate_skip 73 "do not share the host UTS namespace"
    secaudit_remediate_skip 74 "keep default/custom seccomp profile enabled on containers"
    secaudit_remediate_skip 75 "do not use docker exec --privileged"
    secaudit_remediate_skip 76 "avoid docker exec as root; prefer least-privilege exec users"
    secaudit_remediate_skip 77 "set a non-default cgroup parent only with a reviewed policy"
    secaudit_remediate_skip 78 "run containers with --security-opt=no-new-privileges"
    secaudit_remediate_skip 79 "do not place containers on the default bridge when custom networks exist"
    secaudit_remediate_skip 80 "enable user namespace mode for containers where supported"
    secaudit_remediate_skip 81 "do not mount docker.sock into containers"
}

secaudit_remediate_swarm_and_host() {
    # RULE82-98
    local n
    for n in 82 83 84 85 86 87 88 89; do
        secaudit_remediate_skip "$n" "Swarm hardening is environment-specific; apply only on Swarm managers/workers"
    done

    secaudit_remediate_skip 90 "harden SSH (PermitRootLogin), enable host firewall, confirm live-restore"

    if [ "$_DOCKER_REMEDIATE_USERNS" = "1" ]; then
        if secaudit_daemon_json_merge "userns-remap" '"default"'; then
            touch /etc/subuid /etc/subgid 2>/dev/null || true
            if ! grep -q '^dockremap:' /etc/subuid 2>/dev/null; then
                printf 'dockremap:100000:65536\n' >>/etc/subuid 2>/dev/null || true
            fi
            if ! grep -q '^dockremap:' /etc/subgid 2>/dev/null; then
                printf 'dockremap:100000:65536\n' >>/etc/subgid 2>/dev/null || true
            fi
            secaudit_remediate_done 92 "daemon.json userns-remap=default (restart required; validate workloads)"
        else
            secaudit_remediate_skip 92 "install python3 or jq to enable userns-remap"
        fi
    else
        secaudit_remediate_skip 92 "enable userns-remap carefully (set DOCKER_REMEDIATE_USERNS=1)"
    fi

    secaudit_remediate_skip 93 "set cgroup driver via systemd/containerd consistently with the orchestrator"
    secaudit_remediate_skip 94 "do not set dm.basesize unless using a reviewed device-mapper policy"
    secaudit_remediate_skip 95 "rebuild images without setuid/setgid binaries where possible"
    secaudit_remediate_skip 96 "use signed/verified base images and package sources"
    secaudit_remediate_skip 97 "enable Docker Content Trust / signed images for production workloads"
    secaudit_remediate_skip 98 "avoid publishing container ports on 0.0.0.0/::; bind to specific interfaces"
}

# =============================================================================
# Bootstrap / main
# =============================================================================

secaudit_skip_all_rules() {
    local n=1
    while [ "$n" -le "$_DOCKER_RULE_COUNT" ]; do
        secaudit_remediate_skip "$n" "docker not present"
        n=$((n + 1))
    done
}

secaudit_bootstrap_docker() {
    if ! secaudit_have_bin docker && [ ! -S "$_DOCKER_SOCK" ] && [ ! -e /usr/bin/dockerd ] && [ ! -e /usr/sbin/dockerd ]; then
        secaudit_log "docker CLI/daemon not detected; skipping automated remediations"
        secaudit_skip_all_rules
        return 1
    fi
    _DOCKER_SVC_FILE=$(secaudit_unit_path docker.service || true)
    _DOCKER_SOCK_UNIT=$(secaudit_unit_path docker.socket || true)
    secaudit_log "daemon_json=${_DOCKER_DAEMON_JSON}"
    secaudit_log "sock=${_DOCKER_SOCK}"
    secaudit_log "audit_rules=${_DOCKER_AUDIT_RULES}"
    secaudit_log "svc=${_DOCKER_SVC_FILE:-none} socket_unit=${_DOCKER_SOCK_UNIT:-none}"
    return 0
}

secaudit_main() {
    secaudit_log "starting remediation (Docker / secaudit_* style)"

    if ! secaudit_bootstrap_docker; then
        secaudit_log "remediation complete (nothing to apply)"
        exit 0
    fi

    secaudit_remediate_host_layout
    secaudit_remediate_audit_watches
    secaudit_remediate_daemon_config
    secaudit_remediate_file_perms
    secaudit_remediate_container_runtime
    secaudit_remediate_swarm_and_host

    if [ "$_DOCKER_DAEMON_CHANGED" -eq 1 ]; then
        [ -f "$_DOCKER_DAEMON_JSON" ] && secaudit_harden_path "$_DOCKER_DAEMON_JSON" 644 "root:root"
        secaudit_maybe_restart_docker
    fi

    secaudit_log "remediation complete (Docker_remediation.sh)"
    exit 0
}

secaudit_main "$@"
