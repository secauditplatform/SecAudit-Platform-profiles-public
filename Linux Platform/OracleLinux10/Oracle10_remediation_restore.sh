#!/bin/bash
# Restore host state recorded by Oracle10_remediation.sh.
# Replays /var/backups/secaudit-oracle10.journal and copies *.secaudit.bak back.
# Does not roll back bootloader kernel args and dnf upgrade.
if [ -z "${BASH_VERSION:-}" ]; then
	if command -v bash >/dev/null 2>&1; then
		exec bash "$0" "$@"
	fi
	printf '%s\n' "ERROR: bash is required." >&2
	exit 1
fi
set -u

SECAUDIT_JOURNAL="${SECAUDIT_JOURNAL:-/var/backups/secaudit-oracle10.journal}"
SECAUDIT_RESTORE_PACKAGES="${SECAUDIT_RESTORE_PACKAGES:-1}"
SECAUDIT_ROOTS="${SECAUDIT_ROOTS:-/etc /boot /usr}"
SECAUDIT_PKG="${SECAUDIT_PKG:-dnf}"

sec_audit_log() { printf '[restore] %s\n' "$*"; }

sec_audit_restore_bak() {
	local bak="$1" dest
	case "$bak" in
		*.secaudit.bak.secaudit.bak) rm -f "$bak"; return 0 ;;
	esac
	dest="${bak%.secaudit.bak}"
	[ -f "$bak" ] || return 0
	cp -p "$bak" "$dest" 2>/dev/null || cp -p "$bak" "$dest"
	rm -f "$bak"
	sec_audit_log "restored $dest"
}

sec_audit_pkg_remove_one() {
	local id="$1"
	case "$SECAUDIT_PKG" in
		apt)
			command -v apt-get >/dev/null 2>&1 || return 0
			timeout 180 apt-get remove -y "$id" >/dev/null 2>&1 || true
			;;
		zypper)
			command -v zypper >/dev/null 2>&1 || return 0
			rpm -q "$id" >/dev/null 2>&1 || return 0
			timeout 180 zypper --non-interactive remove "$id" >/dev/null 2>&1 || true
			;;
		yum)
			command -v yum >/dev/null 2>&1 || return 0
			timeout 180 yum remove -y "$id" >/dev/null 2>&1 || true
			;;
		dnf)
			command -v dnf >/dev/null 2>&1 || return 0
			timeout 180 dnf remove -y "$id" >/dev/null 2>&1 || true
			;;
	esac
}

sec_audit_pkg_install_one() {
	local id="$1" ver="${2:-}"
	case "$SECAUDIT_PKG" in
		apt)
			command -v apt-get >/dev/null 2>&1 || return 0
			if [ -n "$ver" ]; then
				timeout 180 apt-get install -y "${id}=${ver}" >/dev/null 2>&1 || true
			else
				timeout 180 apt-get install -y "$id" >/dev/null 2>&1 || true
			fi
			;;
		zypper)
			command -v zypper >/dev/null 2>&1 || return 0
			if [ -n "$ver" ]; then
				rpm -q "${id}-${ver}" >/dev/null 2>&1 && return 0
				timeout 180 zypper --non-interactive install --oldpackage --no-recommends "${id}=${ver}" >/dev/null 2>&1 || true
			else
				rpm -q "$id" >/dev/null 2>&1 && return 0
				timeout 180 zypper --non-interactive install --no-recommends "$id" >/dev/null 2>&1 || true
			fi
			;;
		yum)
			command -v yum >/dev/null 2>&1 || return 0
			if [ -n "$ver" ]; then
				timeout 180 yum install -y "${id}-${ver}" >/dev/null 2>&1 || true
			else
				timeout 180 yum install -y "$id" >/dev/null 2>&1 || true
			fi
			;;
		dnf)
			command -v dnf >/dev/null 2>&1 || return 0
			if [ -n "$ver" ]; then
				timeout 180 dnf install -y "${id}-${ver}" >/dev/null 2>&1 || true
			else
				timeout 180 dnf install -y "$id" >/dev/null 2>&1 || true
			fi
			;;
	esac
}

sec_audit_replay_journal() {
	local kind id rest mode owner
	[ -f "$SECAUDIT_JOURNAL" ] || return 0
	while read -r kind id rest; do
		[ -n "${kind:-}" ] || continue
		case "$kind" in
			\#*) continue ;;
			created)
				rm -f "$id" "${id}.secaudit.bak"
				sec_audit_log "removed created $id"
				;;
			sysctl)
				[ -n "${rest:-}" ] || continue
				sysctl -w "${id}=${rest}" >/dev/null 2>&1 || true
				;;
			unit)
				command -v systemctl >/dev/null 2>&1 || continue
				case "${rest:-}" in
					enabled)
						systemctl unmask "$id" >/dev/null 2>&1 || true
						systemctl enable "$id" >/dev/null 2>&1 || true
						systemctl start "$id" >/dev/null 2>&1 || true
						;;
					masked)
						systemctl disable --now "$id" >/dev/null 2>&1 || true
						systemctl mask "$id" >/dev/null 2>&1 || true
						;;
					*)
						systemctl unmask "$id" >/dev/null 2>&1 || true
						systemctl disable --now "$id" >/dev/null 2>&1 || true
						;;
				esac
				;;
			pkg_add)
				[ "$SECAUDIT_RESTORE_PACKAGES" = "1" ] || continue
				sec_audit_pkg_remove_one "$id"
				sec_audit_log "removed package $id"
				;;
			pkg_del)
				[ "$SECAUDIT_RESTORE_PACKAGES" = "1" ] || continue
				sec_audit_pkg_install_one "$id" "${rest:-}"
				sec_audit_log "reinstalled package $id ${rest:-}"
				;;
			mount)
				[ -n "${rest:-}" ] || continue
				mountpoint -q "$id" 2>/dev/null || continue
				extra=""
				case ",${rest}," in *,nodev,*) ;; *) extra="${extra},dev" ;; esac
				case ",${rest}," in *,nosuid,*) ;; *) extra="${extra},suid" ;; esac
				case ",${rest}," in *,noexec,*) ;; *) extra="${extra},exec" ;; esac
				mount -o "remount,${rest}${extra}" "$id" >/dev/null 2>&1 || true
				;;
			selinux)
				[ "${id:-}" = "getenforce" ] || continue
				case "${rest:-}" in
					Permissive|permissive) setenforce 0 >/dev/null 2>&1 || true ;;
					Enforcing|enforcing) setenforce 1 >/dev/null 2>&1 || true ;;
				esac
				;;
			crypto)
				[ "${id:-}" = "policy" ] || continue
				[ -n "${rest:-}" ] || continue
				command -v update-crypto-policies >/dev/null 2>&1 || continue
				update-crypto-policies --set "$rest" >/dev/null 2>&1 || true
				;;
			kmod)
				modprobe "$id" >/dev/null 2>&1 || true
				;;
			mode)
				[ -n "${rest:-}" ] || continue
				[ -e "$id" ] || continue
				mode="${rest%% *}"
				owner="${rest#* }"
				chmod "$mode" "$id" 2>/dev/null || true
				[ -n "$owner" ] && chown "$owner" "$id" 2>/dev/null || true
				;;
		esac
	done <"$SECAUDIT_JOURNAL"
}

sec_audit_remount_fstab() {
	local src mp fstype opts freq pass
	[ -f /etc/fstab ] || return 0
	while read -r src mp fstype opts freq pass; do
		case "$src" in
			""|\#*) continue ;;
		esac
		[ -n "${mp:-}" ] && [ -n "${opts:-}" ] || continue
		mountpoint -q "$mp" 2>/dev/null || continue
		mount -o "remount,${opts}" "$mp" >/dev/null 2>&1 || true
	done </etc/fstab
}

sec_audit_main() {
	local bak
	sec_audit_log "starting restore (Oracle10_remediation_restore.sh)"

	while IFS= read -r bak; do
		[ -n "$bak" ] || continue
		sec_audit_restore_bak "$bak"
	done < <(find $SECAUDIT_ROOTS -name '*.secaudit.bak' -type f 2>/dev/null | awk '{ print length, $0 }' | sort -nr | cut -d' ' -f2-)

	sec_audit_replay_journal
	sec_audit_remount_fstab
	rm -f "$SECAUDIT_JOURNAL"

	if command -v systemctl >/dev/null 2>&1; then
		systemctl daemon-reload >/dev/null 2>&1 || true
		systemctl try-reload-or-restart sshd >/dev/null 2>&1 || systemctl try-reload-or-restart ssh >/dev/null 2>&1 || true
		systemctl try-restart systemd-journald >/dev/null 2>&1 || true
	fi
	command -v augenrules >/dev/null 2>&1 && timeout 15 augenrules --load >/dev/null 2>&1 || true

	sec_audit_log "not restored: bootloader kernel args and dnf upgrade"
	sec_audit_log "restore complete"
}

sec_audit_main "$@"
