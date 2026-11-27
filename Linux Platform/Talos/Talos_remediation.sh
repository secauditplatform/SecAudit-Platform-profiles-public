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

export LC_ALL=C

if [ -z "${BASH_VERSION:-}" ]; then
    if command -v bash >/dev/null 2>&1; then
        exec bash "$0" "$@"
    fi
    printf '%s\n' "ERROR: bash is required." >&2
    exit 1
fi

set +e

sec_audit_log() { printf '[remediation] %s\n' "$*"; }

sec_audit_remediate_done() { secaudit_rule_enabled "$1" || return 0; printf '[remediation] REMEDIATE RULE%s= applied: %s\n' "$1" "$2"
}

sec_audit_remediate_skip() { secaudit_rule_enabled "$1" || return 0; printf '[remediation] REMEDIATE RULE%s= SKIP: manual step required - %s\n' "$1" "$2"
}

# Talos Linux is an immutable, API-managed OS: every change goes through the
# machine config, so each rule is reported as a manual step with its setting.
sec_audit_remediate_bootloader() {
# RULE1-2
sec_audit_remediate_skip 1 "set installer.secureboot=true and reinstall nodes to enable SecureBoot"
sec_audit_remediate_skip 2 "configure machine.systemDiskEncryption with a KMS or TPM provider"
}

sec_audit_remediate_package_security() {
# RULE3-3
sec_audit_remediate_skip 3 "upgrade nodes with talosctl upgrade to the supported release"
}

sec_audit_remediate_chrony() {
# RULE4-4
sec_audit_remediate_skip 4 "configure machine.time.servers with authorized NTP sources"
}

sec_audit_remediate_unused_services() {
# RULE5-7
sec_audit_remediate_skip 5 "set cluster.allowSchedulingOnControlPlanes=false"
sec_audit_remediate_skip 6 "set the Pod Security Standards defaults to enforce: restricted"
sec_audit_remediate_skip 7 "enable the Kubernetes RBAC admission control plugin"
}

sec_audit_remediate_network_stack() {
# RULE8-16
sec_audit_remediate_skip 8 "set net.ipv4.conf.all.send_redirects=0 and net.ipv4.conf.default.send_redirects=0"
sec_audit_remediate_skip 9 "set net.ipv4.conf.all.accept_source_route=0 and net.ipv4.conf.default.accept_source_route=0"
sec_audit_remediate_skip 10 "set net.ipv4.conf.all.accept_redirects=0 and net.ipv4.conf.default.accept_redirects=0"
sec_audit_remediate_skip 11 "set net.ipv4.conf.all.secure_redirects=0 and net.ipv4.conf.default.secure_redirects=0"
sec_audit_remediate_skip 12 "set net.ipv4.conf.all.log_martians=1 and net.ipv4.conf.default.log_martians=1"
sec_audit_remediate_skip 13 "set net.ipv4.icmp_echo_ignore_broadcasts=1"
sec_audit_remediate_skip 14 "set net.ipv4.icmp_ignore_bogus_error_responses=1"
sec_audit_remediate_skip 15 "set net.ipv4.tcp_syncookies=1"
sec_audit_remediate_skip 16 "set net.ipv4.conf.default.rp_filter=1 when only symmetric routes are used"
}

sec_audit_remediate_firewalld() {
# RULE17-18
sec_audit_remediate_skip 17 "apply an ingress firewall policy to the control plane nodes"
sec_audit_remediate_skip 18 "apply an ingress firewall policy to the worker nodes"
}

sec_audit_remediate_network_stack_2() {
# RULE19-19
sec_audit_remediate_skip 19 "enable machine.kubespan.enabled where network-layer encryption is required"
}

sec_audit_remediate_unused_services_2() {
# RULE20-21
sec_audit_remediate_skip 20 "set machine.kernel.logging to forward kernel logs to a remote service"
sec_audit_remediate_skip 21 "set machine.logging.destinations for service logs"
}

sec_audit_main() {
    sec_audit_log "starting Talos Linux remediation (sec_Talos_Linux_v1.0.0)"
    sec_audit_remediate_bootloader
    sec_audit_remediate_package_security
    sec_audit_remediate_chrony
    sec_audit_remediate_unused_services
    sec_audit_remediate_network_stack
    sec_audit_remediate_firewalld
    sec_audit_remediate_network_stack_2
    sec_audit_remediate_unused_services_2
    sec_audit_log "Talos Linux remediation complete"
    exit 0
}

sec_audit_main "$@"
