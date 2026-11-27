#!/bin/bash
# Restore files recorded by PSQL_remediation.sh.
# Copies *.secaudit.bak back and deletes paths journaled as created.
# roles and privileges changed in a running cluster
if [ -z "${BASH_VERSION:-}" ]; then
	if command -v bash >/dev/null 2>&1; then
		exec bash "$0" "$@"
	fi
	printf '%s\n' "ERROR: bash is required." >&2
	exit 1
fi
set -u

SECAUDIT_JOURNAL="${SECAUDIT_JOURNAL:-/var/backups/secaudit-psql.journal}"
SECAUDIT_ROOTS="${SECAUDIT_ROOTS:-/etc /usr /var /opt}"

sec_audit_log() { printf '[restore] %s\n' "$*"; }

sec_audit_restore_bak() {
	local bak="$1" dest
	case "$bak" in
		*.secaudit.bak.secaudit.bak) rm -f "$bak"; return 0 ;;
	esac
	dest="${bak%.secaudit.bak}"
	[ -e "$bak" ] || return 0
	cp -a "$bak" "$dest" 2>/dev/null || cp -a "$bak" "$dest"
	rm -f "$bak"
	sec_audit_log "restored $dest"
}

sec_audit_main() {
	local bak kind id
	sec_audit_log "starting restore (PSQL_remediation_restore.sh)"
	while IFS= read -r bak; do
		[ -n "$bak" ] || continue
		sec_audit_restore_bak "$bak"
	done < <(find $SECAUDIT_ROOTS -name '*.secaudit.bak' 2>/dev/null | awk '{ print length, $0 }' | sort -nr | cut -d' ' -f2-)
	if [ -f "$SECAUDIT_JOURNAL" ]; then
		while read -r kind id; do
			case "$kind" in
				""|\#*) continue ;;
				created)
					[ -n "${id:-}" ] || continue
					[ -e "${id}.secaudit.bak" ] && continue
					rm -f "$id" 2>/dev/null || true
					sec_audit_log "removed $id"
					;;
			esac
		done <"$SECAUDIT_JOURNAL"
		rm -f "$SECAUDIT_JOURNAL"
	fi
	sec_audit_log "not restored: roles and privileges changed in a running cluster"
	sec_audit_log "restore complete"
}

sec_audit_main "$@"
