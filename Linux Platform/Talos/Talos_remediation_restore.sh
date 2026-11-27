#!/bin/bash
# Talos remediation only prints manual machine-config steps. Nothing on the node is changed.
if [ -z "${BASH_VERSION:-}" ]; then
	if command -v bash >/dev/null 2>&1; then
		exec bash "$0" "$@"
	fi
	printf '%s\n' "ERROR: bash is required." >&2
	exit 1
fi
set -u

sec_audit_log() { printf '[restore] %s\n' "$*"; }

sec_audit_main() {
	sec_audit_log "starting restore (Talos_remediation_restore.sh)"
	sec_audit_log "Talos remediation does not change the node; apply the reverse machine config by hand"
	sec_audit_log "restore complete"
}

sec_audit_main "$@"
