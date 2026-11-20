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

# --- bootstrap / reporting ---
sec_audit_report_pass() { secaudit_rule_enabled "$1" || return 0; printf 'RULE%s= PASS: %s\n' "$1" "$2"; }
sec_audit_report_fail() { secaudit_rule_enabled "$1" || return 0; printf 'RULE%s= FAIL: %s\n' "$1" "${3:-$2}"; }
sec_audit_report_skip() { secaudit_rule_enabled "$1" || return 0; printf 'RULE%s= SKIP: %s\n' "$1" "$2"; }
sec_audit_report_error() { secaudit_rule_enabled "$1" || return 0; printf 'RULE%s= ERROR: %s\n' "$1" "$2"; }
sec_audit_report_review() { secaudit_rule_enabled "$1" || return 0; printf 'RULE%s= REVIEW: %s\n' "$1" "$2"; }
sec_audit_report_warn() { secaudit_rule_enabled "$1" || return 0; printf 'RULE%s= WARN: %s\n' "$1" "$2"; }

export LC_ALL=C

if (set -o pipefail) >/dev/null 2>&1; then
  set -o pipefail
fi

sec_audit__sanitize() {
  builtin printf '%s' "$1" | tr '\r\n\t' '?? '
}

: "${SCAN_TIMEOUT:=60}"
: "${SCAN_BUDGET:=60}"
: "${SCAN_MAX_RESULTS:=100}"

sec_audit_have_bin() {
  command -v "$1" >/dev/null 2>&1
}

sec_audit_low_impact_find() {
  local timeout_seconds=""
  local cmd=()

  if [[ "${1:-}" == --timeout=* ]]; then
    timeout_seconds="${1#--timeout=}"
    shift
  fi

  if [ -n "$timeout_seconds" ] && sec_audit_have_bin timeout; then
    cmd+=(timeout "$timeout_seconds")
  fi
  if sec_audit_have_bin nice; then
    cmd+=(nice -n 19)
  fi
  if sec_audit_have_bin ionice; then
    cmd+=(ionice -c3)
  fi

  cmd+=(find "$@")
  "${cmd[@]}"
}

sec_audit__scan_local_mounts() {
  local mp rc all=0 quit=(-print -quit) acc="" n=0 total=0 rem lim tmp start=$SECONDS
  _SCAN_TRUNCATED=0
  if [ "${1:-}" = "--all" ]; then
    all=1
    quit=(-print)
    shift
  fi
  sec_audit_have_bin timeout || return 2
  tmp=$(mktemp) || return 3
  while IFS= read -r mp; do
    lim=$(( SCAN_MAX_RESULTS - total ))
    if [ "$lim" -le 0 ]; then
      _SCAN_TRUNCATED=1
      break
    fi
    rem=$(( SCAN_BUDGET - (SECONDS - start) ))
    if [ "$rem" -le 0 ]; then
      rm -f "$tmp"
      [ -n "$acc" ] && break
      return 3
    fi
    [ "$rem" -gt "$SCAN_TIMEOUT" ] && rem=$SCAN_TIMEOUT
    # read one line past the allowance: that extra line proves the list was cut
    sec_audit_low_impact_find --timeout="$rem" "$mp" -xdev "$@" "${quit[@]}" 2>/dev/null | head -n "$((lim + 1))" > "$tmp"
    rc=${PIPESTATUS[0]}
    n=$(wc -l < "$tmp")
    if [ "$n" -gt "$lim" ]; then
      head -n "$lim" "$tmp" > "$tmp.cut"
      mv "$tmp.cut" "$tmp"
      _SCAN_TRUNCATED=1
      n=$lim
    fi
    if [ "$n" -gt 0 ]; then
      if [ "$all" -eq 0 ]; then
        builtin printf '%s' "$(sec_audit__sanitize "$(head -n1 "$tmp")")"
        rm -f "$tmp"
        return 0
      fi
      acc+=" $(tr '\n' ' ' < "$tmp")"
      total=$((total + n))
    fi
    : > "$tmp"
    case "$rc" in
      0) ;;
      141) _SCAN_TRUNCATED=1; break ;;               # result cap stopped the walk
      124) if [ -n "$acc" ]; then break; else rm -f "$tmp"; return 3; fi ;;
      *) if [ -n "$acc" ]; then break; else rm -f "$tmp"; return 3; fi ;;
    esac
  done < <(sec_audit_safe_find_roots)
  rm -f "$tmp"
  if [ -n "$acc" ]; then
    builtin printf '%s' "$(sec_audit__sanitize "${acc# }")"
    [ "$_SCAN_TRUNCATED" -eq 1 ] && builtin printf ' (list limited to %s paths)' "$SCAN_MAX_RESULTS"
    return 0
  fi
  return 1
}

sec_audit_safe_find_roots() {
  if ! sec_audit_have_bin findmnt; then
    builtin printf '%s\n' /
    return 0
  fi

  findmnt -rn -o TARGET,FSTYPE,OPTIONS 2>/dev/null | awk '
    BEGIN {
      skip_fs["proc"]; skip_fs["sysfs"]; skip_fs["devtmpfs"]; skip_fs["devpts"];
      skip_fs["tmpfs"]; skip_fs["cgroup"]; skip_fs["cgroup2"]; skip_fs["pstore"];
      skip_fs["securityfs"]; skip_fs["debugfs"]; skip_fs["tracefs"]; skip_fs["configfs"];
      skip_fs["fusectl"]; skip_fs["mqueue"]; skip_fs["hugetlbfs"]; skip_fs["rpc_pipefs"];
      skip_fs["autofs"]; skip_fs["overlay"]; skip_fs["squashfs"]; skip_fs["iso9660"];
      skip_fs["nfs"]; skip_fs["nfs4"]; skip_fs["cifs"]; skip_fs["smbfs"]; skip_fs["sshfs"];
      skip_fs["fuse.sshfs"]; skip_fs["afs"]; skip_fs["ceph"]; skip_fs["glusterfs"];
    }
    {
      target=$1; fstype=$2; options=$3;
      if (target == "" || fstype == "" || target ~ "^/(proc|sys|dev|run)(/|$)") next;
      if (fstype in skip_fs) next;
      if (options ~ /(^|,)bind(,|$)/) next;
      print target;
    }
  ' | sort -u
}

sec_audit_findmnt_have() {
  sec_audit_have_bin findmnt
}

sec_audit_findmnt_path_resolvable() {
  local mp="${1%/}"
  sec_audit_findmnt_have || return 1
  findmnt -kn -T "$mp" &>/dev/null
}

sec_audit_findmnt_is_explicit_mountpoint() {
  local mp="${1%/}" tgt
  sec_audit_findmnt_have || return 1
  tgt=$(findmnt -kn -T "$mp" -o TARGET --noheadings 2>/dev/null | head -n1)
  tgt="${tgt#"${tgt%%[![:space:]]*}"}"
  tgt="${tgt%"${tgt##*[![:space:]]}"}"
  tgt="${tgt%/}"
  [ -n "$tgt" ] && [ "$tgt" = "$mp" ]
}

sec_audit_findmnt_source_for() {
  local mp="${1%/}" s
  sec_audit_findmnt_have || return 1
  s=$(findmnt -kn -T "$mp" -o SOURCE --noheadings 2>/dev/null | head -n1)
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  builtin printf '%s' "$s"
}

sec_audit_findmnt_fstype_for() {
  local mp="${1%/}" f
  sec_audit_findmnt_have || return 1
  f=$(findmnt -kn -T "$mp" -o FSTYPE --noheadings 2>/dev/null | head -n1)
  f="${f#"${f%%[![:space:]]*}"}"
  f="${f%"${f##*[![:space:]]}"}"
  builtin printf '%s' "$f"
}

sec_audit_findmnt_options_raw() {
  local mp="${1%/}" o
  sec_audit_findmnt_have || return 1
  o=$(findmnt -kn -T "$mp" -o OPTIONS --noheadings 2>/dev/null | head -n1)
  o="${o#"${o%%[![:space:]]*}"}"
  o="${o%"${o##*[![:space:]]}"}"
  builtin printf '%s' "$o"
}

sec_audit_findmnt_has_mnt_option() {
  local mp="$1" want="$2" opts token
  sec_audit_findmnt_have || return 1
  opts=$(sec_audit_findmnt_options_raw "$mp")
  [ -z "$opts" ] && return 1
  local IFS=,
  for token in $opts; do
    token="${token#"${token%%[![:space:]]*}"}"
    token="${token%"${token##*[![:space:]]}"}"
    [ "$token" = "$want" ] && return 0
  done
  return 1
}

sec_audit_findmnt_tmpfs_or_separate_ok() {
  local mp="${1%/}" fst src root_src
  sec_audit_findmnt_have || return 1
  sec_audit_findmnt_is_explicit_mountpoint "$mp" || return 1
  fst=$(sec_audit_findmnt_fstype_for "$mp")
  src=$(sec_audit_findmnt_source_for "$mp")
  root_src=$(sec_audit_findmnt_source_for /)
  [ "$fst" = "tmpfs" ] && return 0
  [ -n "$src" ] && [ -n "$root_src" ] && [ "$src" != "$root_src" ]
}

sec_audit_findmnt_separate_partition_ok() {
  local mp="${1%/}" src root_src
  sec_audit_findmnt_have || return 1
  sec_audit_findmnt_is_explicit_mountpoint "$mp" || return 1
  src=$(sec_audit_findmnt_source_for "$mp")
  root_src=$(sec_audit_findmnt_source_for /)
  [ -n "$src" ] && [ -n "$root_src" ] && [ "$src" != "$root_src" ]
}

sec_audit__emit_mnt_option() {
  local req="$1" mp="$2" opt="$3"
  if sec_audit_findmnt_path_resolvable "$mp" && sec_audit_findmnt_has_mnt_option "$mp" "$opt"; then
    sec_audit_report_pass ${req} "${opt} option is set on ${mp}"
  else
    sec_audit_report_fail ${req} "${opt} option is missing on ${mp}"
  fi
}

sec_audit__emit_separate_partition() {
  local req="$1" mp="$2"
  if sec_audit_findmnt_separate_partition_ok "$mp"; then
    sec_audit_report_pass ${req} "${mp} is mounted on a separate partition"
  else
    sec_audit_report_fail ${req} "${mp} is not mounted on a separate partition (explicit mount with distinct source)"
  fi
}

sec_audit_is_package_installed() {
  local package_name="$1"
  dpkg-query -W -f='${Status}' "$package_name" 2>/dev/null | grep -q '^install ok installed$'
}

sec_audit__pkg_owns_path() {
  local p="$1" alt
  dpkg -S "$p" >/dev/null 2>&1 && return 0
  case "$p" in
    /usr/bin/*|/usr/sbin/*|/usr/lib/*) alt="/${p#/usr/}" ;;
    /bin/*|/sbin/*|/lib/*) alt="/usr${p}" ;;
    *) return 1 ;;
  esac
  dpkg -S "$alt" >/dev/null 2>&1
}

sec_audit_is_service_active() {
  local service_name="$1"
  systemctl is-active "$service_name" 2>/dev/null | grep -q '^active$'
}

sec_audit_is_service_enabled() {
  local service_name="$1"
  systemctl is-enabled "$service_name" 2>/dev/null | grep -qE '^(enabled|enabled-runtime)$'
}

sec_audit_kernel_mod_in_modules_load() {
  local pat="" a
  for a in "$@"; do
    pat+="${pat:+|}${a}"
  done
  grep -rqE "^[[:space:]]*(${pat})([[:space:]]|$)" /etc/modules-load.d /usr/lib/modules-load.d /run/modules-load.d 2>/dev/null
}

sec_audit__modprobe_blocked() {
  local mod="$1" out
  sec_audit_have_bin modprobe || return 1
  if modprobe --showconfig 2>/dev/null | grep -Pq "^\h*(blacklist|install)\h+${mod//-/_}\b"; then
    return 0
  fi
  if modprobe --showconfig 2>/dev/null | grep -Pq "^\h*(blacklist|install)\h+${mod}\b"; then
    return 0
  fi
  out="$(modprobe -n -v "$mod" 2>&1)"
  printf '%s\n' "$out" | grep -qE 'install /bin/(true|false)|Module .* not found'
}

sec_audit__emit_kernel_mod_unavailable() {
  local req="$1" mod="$2" lsname="${2//-/_}"
  if sec_audit_kernel_mod_in_modules_load "$mod" "$lsname"; then
    sec_audit_report_fail ${req} "${mod} kernel module is listed in modules-load.d (auto-load at boot)"
  elif ! sec_audit_low_impact_find --timeout=20 /usr/lib/modules/ /lib/modules/ -xdev -ignore_readdir_race -type f -name "${mod}.ko*" 2>/dev/null | grep -q .; then
    sec_audit_report_pass ${req} "${mod} kernel module is not available (no module object in kernel tree)"
  elif { ! sec_audit_have_bin lsmod || ! lsmod | awk '{print $1}' | grep -qx -- "$lsname"; } && sec_audit__modprobe_blocked "$mod"; then
    sec_audit_report_pass ${req} "${mod} kernel module is disabled and not loaded"
  else
    sec_audit_report_fail ${req} "${mod} kernel module is available, loaded, or not effectively blocked (modprobe blacklist/install)"
  fi
}

sec_audit_sysctl_key_runtime_raw() {
  sec_audit_have_bin sysctl || return 1
  sysctl -n "$1" 2>/dev/null | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

sec_audit_sysctl_runtime_equals() {
  local got
  got=$(sec_audit_sysctl_key_runtime_raw "$1") || return 1
  [[ "$got" == "$2" ]]
}

sec_audit_sysctl_files_last_assignment_value() {
  local key="$1" esc val="" line f name
  esc=${key//./\\.}
  shopt -s nullglob
  local -A picked=()
  for f in /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf /etc/sysctl.d/*.conf; do
    picked["${f##*/}"]="$f"
  done
  local -a order=() names=()
  for name in "${!picked[@]}"; do
    names+=("$name")
  done
  IFS=$'\n' names=($(printf '%s\n' "${names[@]}" | sort)); unset IFS
  for name in "${names[@]}"; do
    order+=("${picked[$name]}")
  done
  [[ -f /etc/sysctl.conf ]] && order+=(/etc/sysctl.conf)
  for f in "${order[@]}"; do
    [[ -f $f ]] || continue
    while IFS= read -r line || [[ -n $line ]]; do
      [[ $line =~ ^[[:space:]]*# ]] && continue
      [[ $line =~ ^[[:space:]]*$ ]] && continue
      if [[ $line =~ ^[[:space:]]*${esc}[[:space:]]*=[[:space:]]*([^#[:space:]]+) ]]; then
        val="${BASH_REMATCH[1]}"
      fi
    done <"$f"
  done
  shopt -u nullglob
  builtin printf '%s' "$val"
}

sec_audit_sysctl_runtime_disk_hint() {
  local key="$1" want="$2" disk got
  got=$(sec_audit_sysctl_key_runtime_raw "$key") || got=""
  disk=$(sec_audit_sysctl_files_last_assignment_value "$key")
  [[ -z $disk ]] && return 0
  if [[ "$got" == "$want" && "$disk" != "$want" ]]; then
    builtin printf '%s' " | note: last on-disk assignment is ${disk} (runtime overrides until reboot)"
  elif [[ "$got" != "$want" && "$disk" == "$want" ]]; then
    builtin printf '%s' " | on-disk last value is ${want} but kernel has '${got:-?}'; run sysctl --system or reboot"
  elif [[ "$got" != "$want" && -n $disk && "$disk" != "$want" ]]; then
    builtin printf '%s' " | on-disk last value is ${disk}, kernel '${got:-?}'"
  fi
}

sec_audit_sysctl_runtime_and_persistent_equals() {
  local key="$1" expected="$2"
  sec_audit_sysctl_runtime_equals "$key" "$expected" || return 1
  local disk
  disk=$(sec_audit_sysctl_files_last_assignment_value "$key")
  [[ -n "$disk" ]] && [[ "$disk" == "$expected" ]]
}

sec_audit_sysctl_runtime_display() {
  local v
  v=$(sec_audit_sysctl_key_runtime_raw "$1")
  builtin printf '%s' "${v:-<unreadable>}"
}

sec_audit_sysctl_files_last_assignment_display() {
  local v
  v=$(sec_audit_sysctl_files_last_assignment_value "$1")
  builtin printf '%s' "${v:-<none>}"
}

_SSHD_T_READY=0
_sshd_t_cache=""

sec_audit__sshd_t_ensure() {
  [ "$_SSHD_T_READY" -eq 1 ] && return 0
  _SSHD_T_READY=1
  if sec_audit_have_bin sshd; then
    _sshd_t_cache=$(sshd -T 2>/dev/null) || _sshd_t_cache=""
  else
    _sshd_t_cache=""
  fi
}

sec_audit_sshd_effective_dump() {
  sec_audit__sshd_t_ensure
  builtin printf '%s\n' "$_sshd_t_cache"
}

sec_audit_sshd_t_awk() {
  sec_audit__sshd_t_ensure
  builtin printf '%s\n' "$_sshd_t_cache" | awk "$@"
}

_AUDITCTL_L_READY=0
_auditctl_l_cache=""

sec_audit__auditctl_l_ensure() {
  [ "$_AUDITCTL_L_READY" -eq 1 ] && return 0
  _AUDITCTL_L_READY=1
  if sec_audit_have_bin auditctl; then
    _auditctl_l_cache=$(auditctl -l 2>/dev/null) || _auditctl_l_cache=""
  else
    _auditctl_l_cache=""
  fi
}

sec_audit_auditctl_rules_grep() {
  sec_audit__auditctl_l_ensure
  builtin printf '%s\n' "$_auditctl_l_cache" | grep "$@"
}

_audit_rules_files_ready=0
_audit_rules_files_cache=""

sec_audit__audit_rules_files_ensure() {
  [ "$_audit_rules_files_ready" -eq 1 ] && return 0
  _audit_rules_files_ready=1
  local files=()
  shopt -s nullglob
  files=(/etc/audit/rules.d/*.rules /etc/audit/audit.rules)
  shopt -u nullglob
  _audit_rules_files_cache=""
  [ "${#files[@]}" -gt 0 ] && _audit_rules_files_cache=$(cat "${files[@]}" 2>/dev/null)
}

sec_audit_audit_rules_files_grep() {
  sec_audit__audit_rules_files_ensure
  builtin printf '%s\n' "$_audit_rules_files_cache" | grep "$@"
}

sec_audit__rule_tokens_match() {
  local line="$1"; shift
  local t
  for t in "$@"; do
    case "$t" in
      *\\b) t="${t%\\b}" ;;
    esac
    case "$line" in
      *"$t"*) : ;;
      *) return 1 ;;
    esac
  done
  return 0
}

sec_audit_audit_rule_on_disk_all() {
  sec_audit__audit_rules_files_ensure
  local line
  while IFS= read -r line; do
    sec_audit__rule_tokens_match "$line" "$@" && return 0
  done <<< "$_audit_rules_files_cache"
  return 1
}

sec_audit_audit_rule_on_disk() {
  sec_audit__audit_rules_files_ensure
  builtin printf '%s\n' "$_audit_rules_files_cache" | grep -q "$@"
}

sec_audit_apparmor_status_output() {
  if sec_audit_have_bin aa-status; then
    aa-status 2>/dev/null
  elif sec_audit_have_bin apparmor_status; then
    apparmor_status 2>/dev/null
  fi
}

sec_audit_apparmor_profiles_all_enforcing_ok() {
  local out complain kill
  out=$(sec_audit_apparmor_status_output) || return 1
  complain=$(echo "$out" | awk '/profiles are in complain mode/{print $1+0}')
  kill=$(echo "$out" | awk '/profiles are in kill mode/{print $1+0}')
  [[ "${complain:-0}" -eq 0 && "${kill:-0}" -eq 0 ]] && echo "$out" | grep -qE '[1-9][0-9]* profiles are in enforce mode'
}

sec_audit__matches_any() {
  local v="$1" alts="$2" a
  [ "$alts" = "-" ] && return 0
  local IFS='|'
  for a in $alts; do
    [ "$v" = "$a" ] && return 0
  done
  return 1
}

sec_audit__perm_of() { stat -Lc '%a' "$1" 2>/dev/null; }

sec_audit__owner_of() { stat -Lc '%U' "$1" 2>/dev/null; }

sec_audit__group_of() { stat -Lc '%G' "$1" 2>/dev/null; }

sec_audit__perm_within() {
  local a="$1" m="$2"
  [[ "$a" =~ ^[0-7]{3,4}$ ]] || return 1
  [ $(( 8#$a & ~ 8#$m & 07777 )) -eq 0 ]
}

sec_audit__path_access_ok() {
  local p="$1" max="$2" want_u="$3" want_g="$4"
  sec_audit__perm_within "$(sec_audit__perm_of "$p")" "$max" || return 1
  sec_audit__matches_any "$(sec_audit__owner_of "$p")" "$want_u" || return 1
  sec_audit__matches_any "$(sec_audit__group_of "$p")" "$want_g" || return 1
  return 0
}

sec_audit__path_access_describe() {
  printf '%s(%s %s:%s)' "$(sec_audit__sanitize "$1")" "$(sec_audit__perm_of "$1")" "$(sec_audit__owner_of "$1")" "$(sec_audit__group_of "$1")"
}

sec_audit__gdm_absent() {
  ! sec_audit_is_package_installed gdm3 && ! sec_audit_is_package_installed gnome-shell && ! sec_audit_is_package_installed gsettings-desktop-schemas
}

sec_audit__dconf_value() {
  local schema="$1" key="$2" v=""
  if sec_audit_have_bin gsettings; then
    v=$(gsettings get "$schema" "$key" 2>/dev/null | tr -d "'\"")
  fi
  v="${v#uint32 }"
  if [ -z "$v" ]; then
    v=$(grep -rPhs -- "^\s*${key}\s*=" /etc/dconf/db/ /etc/gdm3/ /etc/gdm/ 2>/dev/null | tail -n1 | sed 's/.*=[[:space:]]*//' | tr -d "'\"")
    v="${v#uint32 }"
  fi
  printf '%s' "$v"
}

sec_audit__dconf_locked() {
  grep -rqs -- "/$1\$" /etc/dconf/db/ 2>/dev/null
}

sec_audit__unused_modules_report() {
  local m bad="" lsname
  for m in "$@"; do
    lsname="${m//-/_}"
    if sec_audit_kernel_mod_in_modules_load "$m" "$lsname"; then
      bad+=" ${m}"
    elif sec_audit_have_bin lsmod && lsmod | awk '{print $1}' | grep -qx -- "$lsname"; then
      bad+=" ${m}"
    elif sec_audit_low_impact_find --timeout=20 /usr/lib/modules/ /lib/modules/ -xdev -ignore_readdir_race -type f -name "${m}.ko*" 2>/dev/null | grep -q . && ! sec_audit__modprobe_blocked "$m"; then
      bad+=" ${m}"
    fi
  done
  printf '%s' "$bad"
}

sec_audit__sysinfo_leak() {
  local osid hits f out=""
  osid=$(sed -n 's/^ID=//p' /etc/os-release 2>/dev/null | tr -d '"')
  for f in "$@"; do
    [ -e "$f" ] || continue
    hits=$(grep -Psi -- "(\\\\v|\\\\r|\\\\m|\\\\s|\b${osid}\b)" "$f" 2>/dev/null)
    [ -n "$hits" ] && out+=" ${f}"
  done
  printf '%s' "$(sec_audit__sanitize "$out")"
}
sec_audit__suid_sgid_scan() {
  [ "$_SUID_DONE" -eq 1 ] && return "$_SUID_RC"
  _SUID_CACHE=$(sec_audit__scan_local_mounts --all -type f \( -perm -4000 -o -perm -2000 \))
  _SUID_RC=$?
  _SUID_DONE=1
  return "$_SUID_RC"
}
sec_audit__audit_privileged_paths_of() {
  {
    builtin printf '%s\n' "$1" | grep -oE -- '-F path=[^[:space:]]+' | sed 's/^-F path=//'
    builtin printf '%s\n' "$1" | grep -E -- '^-w [^[:space:]]+ .*-p [^[:space:]]*x' | awk '{print $2}'
  } | sort -u
}
sec_audit__audit_privileged_paths() {
  sec_audit__audit_rules_files_ensure
  sec_audit__audit_privileged_paths_of "$_audit_rules_files_cache"
}
sec_audit__audit_privileged_paths_loaded() {
  sec_audit__auditctl_l_ensure
  sec_audit__audit_privileged_paths_of "$_auditctl_l_cache"
}
sec_audit__audit_absent_fail() {
  sec_audit_report_fail $1 "auditd is not installed - access cannot be verified"
}
sec_audit__interactive_users() {
  awk -F: '($1!~/^(halt|sync|shutdown|nfsnobody)$/ && $7!~/(\/sbin\/nologin|\/bin\/false)$/ && $3>=1000){print}' /etc/passwd 2>/dev/null
}

# =============================================================================
# Section runners
# =============================================================================

sec_audit_run_initial_setup() {
if secaudit_rule_enabled 1; then
sec_audit__emit_kernel_mod_unavailable 1 cramfs

fi
if secaudit_rule_enabled 2; then
sec_audit__emit_kernel_mod_unavailable 2 freevxfs

fi
if secaudit_rule_enabled 3; then
sec_audit__emit_kernel_mod_unavailable 3 hfs

fi
if secaudit_rule_enabled 4; then
sec_audit__emit_kernel_mod_unavailable 4 hfsplus

fi
if secaudit_rule_enabled 5; then
sec_audit__emit_kernel_mod_unavailable 5 jffs2

fi
if secaudit_rule_enabled 6; then
sec_audit__emit_kernel_mod_unavailable 6 overlay

fi
if secaudit_rule_enabled 7; then
sec_audit__emit_kernel_mod_unavailable 7 squashfs

fi
if secaudit_rule_enabled 8; then
sec_audit__emit_kernel_mod_unavailable 8 udf

fi
if secaudit_rule_enabled 9; then
sec_audit__emit_kernel_mod_unavailable 9 firewire-core

fi
if secaudit_rule_enabled 10; then
sec_audit__emit_kernel_mod_unavailable 10 usb-storage

fi
if secaudit_rule_enabled 11; then
_bad=$(sec_audit__unused_modules_report cramfs freevxfs hfs hfsplus jffs2 overlay squashfs udf firewire-core usb-storage)
if [ -z "$_bad" ]; then
  sec_audit_report_pass 11 "unused filesystem kernel modules are disabled and not loaded"
else
  sec_audit_report_fail 11 "unused filesystem kernel modules available or loaded:${_bad}"
fi

fi
if secaudit_rule_enabled 12; then
if sec_audit_findmnt_tmpfs_or_separate_ok /tmp; then
  sec_audit_report_pass 12 "/tmp is tmpfs or a separate partition"
else
  sec_audit_report_fail 12 "/tmp does not meet tmpfs or separate-partition requirement"
fi

fi
if secaudit_rule_enabled 13; then
sec_audit__emit_mnt_option 13 /tmp nodev

fi
if secaudit_rule_enabled 14; then
sec_audit__emit_mnt_option 14 /tmp nosuid

fi
if secaudit_rule_enabled 15; then
sec_audit__emit_mnt_option 15 /tmp noexec

fi
if secaudit_rule_enabled 16; then
if sec_audit_findmnt_tmpfs_or_separate_ok /dev/shm; then
  sec_audit_report_pass 16 "/dev/shm is tmpfs or a separate partition"
else
  sec_audit_report_fail 16 "/dev/shm does not meet tmpfs or separate-partition requirement"
fi

fi
if secaudit_rule_enabled 17; then
sec_audit__emit_mnt_option 17 /dev/shm nodev

fi
if secaudit_rule_enabled 18; then
sec_audit__emit_mnt_option 18 /dev/shm nosuid

fi
if secaudit_rule_enabled 19; then
sec_audit__emit_mnt_option 19 /dev/shm noexec

fi
if secaudit_rule_enabled 20; then
sec_audit__emit_separate_partition 20 /home

fi
if secaudit_rule_enabled 21; then
sec_audit__emit_mnt_option 21 /home nodev

fi
if secaudit_rule_enabled 22; then
sec_audit__emit_mnt_option 22 /home nosuid

fi
if secaudit_rule_enabled 23; then
sec_audit__emit_separate_partition 23 /var

fi
if secaudit_rule_enabled 24; then
sec_audit__emit_mnt_option 24 /var nodev

fi
if secaudit_rule_enabled 25; then
sec_audit__emit_mnt_option 25 /var nosuid

fi
if secaudit_rule_enabled 26; then
sec_audit__emit_separate_partition 26 /var/tmp

fi
if secaudit_rule_enabled 27; then
sec_audit__emit_mnt_option 27 /var/tmp nodev

fi
if secaudit_rule_enabled 28; then
sec_audit__emit_mnt_option 28 /var/tmp nosuid

fi
if secaudit_rule_enabled 29; then
sec_audit__emit_mnt_option 29 /var/tmp noexec

fi
if secaudit_rule_enabled 30; then
sec_audit__emit_separate_partition 30 /var/log

fi
if secaudit_rule_enabled 31; then
sec_audit__emit_mnt_option 31 /var/log nodev

fi
if secaudit_rule_enabled 32; then
sec_audit__emit_mnt_option 32 /var/log nosuid

fi
if secaudit_rule_enabled 33; then
sec_audit__emit_mnt_option 33 /var/log noexec

fi
if secaudit_rule_enabled 34; then
sec_audit__emit_separate_partition 34 /var/log/audit

fi
if secaudit_rule_enabled 35; then
sec_audit__emit_mnt_option 35 /var/log/audit nodev

fi
if secaudit_rule_enabled 36; then
sec_audit__emit_mnt_option 36 /var/log/audit nosuid

fi
if secaudit_rule_enabled 37; then
sec_audit__emit_mnt_option 37 /var/log/audit noexec

fi
if secaudit_rule_enabled 38; then
_bad=""
_l_re='^\h*deb(-src)?\h+(\[(?![^\]]*\bSigned-By\b)[^\]]*\]|[^\[])'
[ -f /etc/apt/sources.list ] && grep -Pshq -- "$_l_re" /etc/apt/sources.list 2>/dev/null && _bad+=" /etc/apt/sources.list"
shopt -s nullglob
for _f in /etc/apt/sources.list.d/*.list; do
  grep -Pshq -- "$_l_re" "$_f" 2>/dev/null && _bad+=" ${_f}"
done
for _f in /etc/apt/sources.list.d/*.sources; do
  if ! awk 'BEGIN{RS="";FS="\n"} {u=0;s=0; for(i=1;i<=NF;i++){ if ($i ~ /^[[:space:]]*URIs:/) u=1; if ($i ~ /^[[:space:]]*Signed-By:/) s=1 } if (u && !s) exit 1 }' "$_f" 2>/dev/null; then
    _bad+=" ${_f}"
  fi
done
shopt -u nullglob
if [ -z "$_bad" ]; then
  sec_audit_report_pass 38 "all APT source entries use the Signed-By option"
else
  sec_audit_report_fail 38 "APT source entries without Signed-By:${_bad}"
fi

fi
if secaudit_rule_enabled 39; then
_r=$(apt-config dump 2>/dev/null | awk '$1=="APT::Install-Recommends"{gsub(/[";]/,"",$2);print $2;exit}')
_s=$(apt-config dump 2>/dev/null | awk '$1=="APT::Install-Suggests"{gsub(/[";]/,"",$2);print $2;exit}')
if [ "$_r" = "0" ] && [ "$_s" = "0" ]; then
  sec_audit_report_pass 39 "APT weak dependencies are disabled (Install-Recommends=0, Install-Suggests=0)"
else
  sec_audit_report_fail 39 "APT weak dependencies are not disabled (Install-Recommends='${_r:-unset}', Install-Suggests='${_s:-unset}')"
fi

fi
if secaudit_rule_enabled 40; then
_bad=""
for _d in /usr/share/keyrings /etc/apt/trusted.gpg.d; do
  [ -d "$_d" ] || continue
  while IFS= read -r -d '' _f; do
    sec_audit__path_access_ok "$_f" 644 root root || _bad+=" $(sec_audit__path_access_describe "$_f")"
  done < <(find -L "$_d" -xdev -type f -name '*gpg' -print0 2>/dev/null)
done
if [ -z "$_bad" ]; then
  sec_audit_report_pass 40 "APT gpg key files are 0644 or more restrictive and owned by root:root"
else
  sec_audit_report_fail 40 "insecure APT gpg key files:${_bad}"
fi

fi
if secaudit_rule_enabled 41; then
_bad=""
_missing=""
for _p in /etc/apt/trusted.gpg.d; do
  if [ ! -e "$_p" ]; then
    case "$_p" in
      *\**|*\?*) : ;;
      *) _missing+=" ${_p}" ;;
    esac
    continue
  fi
  sec_audit__path_access_ok "$_p" 755 'root' 'root' || _bad+=" $(sec_audit__path_access_describe "$_p")"
done
if [ -n "$_bad" ]; then
  sec_audit_report_fail 41 "insecure access on:${_bad} (expected 755 root:root or more restrictive)"
elif [ -n "$_missing" ]; then
  sec_audit_report_fail 41 "missing path(s):${_missing}"
else
  sec_audit_report_pass 41 "access is 755 root:root or more restrictive for all checked paths"
fi

fi
if secaudit_rule_enabled 42; then
_bad=""
_missing=""
for _p in /etc/apt/auth.conf.d; do
  if [ ! -e "$_p" ]; then
    case "$_p" in
      *\**|*\?*) : ;;
      *) _missing+=" ${_p}" ;;
    esac
    continue
  fi
  sec_audit__path_access_ok "$_p" 755 'root' 'root' || _bad+=" $(sec_audit__path_access_describe "$_p")"
done
if [ -n "$_bad" ]; then
  sec_audit_report_fail 42 "insecure access on:${_bad} (expected 755 root:root or more restrictive)"
elif [ -n "$_missing" ]; then
  sec_audit_report_fail 42 "missing path(s):${_missing}"
else
  sec_audit_report_pass 42 "access is 755 root:root or more restrictive for all checked paths"
fi

fi
if secaudit_rule_enabled 43; then
_bad=""
_missing=""
for _p in /etc/apt/auth.conf.d/*.conf; do
  if [ ! -e "$_p" ]; then
    case "$_p" in
      *\**|*\?*) : ;;
      *) _missing+=" ${_p}" ;;
    esac
    continue
  fi
  sec_audit__path_access_ok "$_p" 640 'root' 'root' || _bad+=" $(sec_audit__path_access_describe "$_p")"
done
if [ -n "$_bad" ]; then
  sec_audit_report_fail 43 "insecure access on:${_bad} (expected 640 root:root or more restrictive)"
elif [ -n "$_missing" ]; then
  sec_audit_report_fail 43 "missing path(s):${_missing}"
else
  sec_audit_report_pass 43 "access is 640 root:root or more restrictive for all checked paths"
fi

fi
if secaudit_rule_enabled 44; then
_bad=""
_missing=""
for _p in /usr/share/keyrings; do
  if [ ! -e "$_p" ]; then
    case "$_p" in
      *\**|*\?*) : ;;
      *) _missing+=" ${_p}" ;;
    esac
    continue
  fi
  sec_audit__path_access_ok "$_p" 755 'root' 'root' || _bad+=" $(sec_audit__path_access_describe "$_p")"
done
if [ -n "$_bad" ]; then
  sec_audit_report_fail 44 "insecure access on:${_bad} (expected 755 root:root or more restrictive)"
elif [ -n "$_missing" ]; then
  sec_audit_report_fail 44 "missing path(s):${_missing}"
else
  sec_audit_report_pass 44 "access is 755 root:root or more restrictive for all checked paths"
fi

fi
if secaudit_rule_enabled 45; then
_bad=""
_missing=""
for _p in /etc/apt/sources.list.d; do
  if [ ! -e "$_p" ]; then
    case "$_p" in
      *\**|*\?*) : ;;
      *) _missing+=" ${_p}" ;;
    esac
    continue
  fi
  sec_audit__path_access_ok "$_p" 755 'root' 'root' || _bad+=" $(sec_audit__path_access_describe "$_p")"
done
if [ -n "$_bad" ]; then
  sec_audit_report_fail 45 "insecure access on:${_bad} (expected 755 root:root or more restrictive)"
elif [ -n "$_missing" ]; then
  sec_audit_report_fail 45 "missing path(s):${_missing}"
else
  sec_audit_report_pass 45 "access is 755 root:root or more restrictive for all checked paths"
fi

fi
if secaudit_rule_enabled 46; then
_bad=""
_missing=""
for _p in /etc/apt/sources.list.d/*; do
  if [ ! -e "$_p" ]; then
    case "$_p" in
      *\**|*\?*) : ;;
      *) _missing+=" ${_p}" ;;
    esac
    continue
  fi
  sec_audit__path_access_ok "$_p" 644 'root' 'root' || _bad+=" $(sec_audit__path_access_describe "$_p")"
done
if [ -n "$_bad" ]; then
  sec_audit_report_fail 46 "insecure access on:${_bad} (expected 644 root:root or more restrictive)"
elif [ -n "$_missing" ]; then
  sec_audit_report_fail 46 "missing path(s):${_missing}"
else
  sec_audit_report_pass 46 "access is 644 root:root or more restrictive for all checked paths"
fi

fi
if secaudit_rule_enabled 47; then
if grep -Pshq -- '^\s*deb(-src)?\s+(\[[^]]*\]\s+)?http://' /etc/apt/sources.list 2>/dev/null; then
  sec_audit_report_fail 47 "plain HTTP repositories found in /etc/apt/sources.list"
else
  sec_audit_report_pass 47 "no plain HTTP repositories in /etc/apt/sources.list"
fi

fi
if secaudit_rule_enabled 48; then
_bad=""
shopt -s nullglob
for _f in /etc/apt/sources.list.d/*.list; do
  grep -Pshq -- '^\s*deb(-src)?\s+(\[[^]]*\]\s+)?http://' "$_f" 2>/dev/null && _bad+=" ${_f}"
done
for _f in /etc/apt/sources.list.d/*.sources; do
  grep -Pshq -- '^\s*URIs:\s+http://' "$_f" 2>/dev/null && _bad+=" ${_f}"
done
shopt -u nullglob
if [ -z "$_bad" ]; then
  sec_audit_report_pass 48 "no plain HTTP repositories in /etc/apt/sources.list.d"
else
  sec_audit_report_fail 48 "plain HTTP repositories found in:${_bad}"
fi

fi
if secaudit_rule_enabled 49; then
_val=""
if sec_audit_have_bin apt-config; then
  _val=$(apt-config dump 2>/dev/null | awk -v o=Acquire::AllowInsecureRepositories '$1==o {gsub(/[";]/,"",$2); print $2; exit}')
fi
if [ -n "$_val" ] && printf '%s' "$_val" | grep -Eq -- '^0$'; then
  sec_audit_report_pass 49 "APT insecure repositories are disabled (Acquire::AllowInsecureRepositories=${_val})"
else
  sec_audit_report_fail 49 "APT insecure repositories are disabled - Acquire::AllowInsecureRepositories is '${_val:-<unset>}', expected ^0$"
fi

fi
if secaudit_rule_enabled 50; then
_val=""
if sec_audit_have_bin apt-config; then
  _val=$(apt-config dump 2>/dev/null | awk -v o=Acquire::AllowWeakRepositories '$1==o {gsub(/[";]/,"",$2); print $2; exit}')
fi
if [ -n "$_val" ] && printf '%s' "$_val" | grep -Eq -- '^0$'; then
  sec_audit_report_pass 50 "APT weak repositories are disabled (Acquire::AllowWeakRepositories=${_val})"
else
  sec_audit_report_fail 50 "APT weak repositories are disabled - Acquire::AllowWeakRepositories is '${_val:-<unset>}', expected ^0$"
fi

fi
if secaudit_rule_enabled 51; then
_val=""
if sec_audit_have_bin apt-config; then
  _val=$(apt-config dump 2>/dev/null | awk -v o=Acquire::AllowDowngradeToInsecureRepositories '$1==o {gsub(/[";]/,"",$2); print $2; exit}')
fi
if [ -n "$_val" ] && printf '%s' "$_val" | grep -Eq -- '^0$'; then
  sec_audit_report_pass 51 "APT downgrade to insecure repositories is disabled (Acquire::AllowDowngradeToInsecureRepositories=${_val})"
else
  sec_audit_report_fail 51 "APT downgrade to insecure repositories is disabled - Acquire::AllowDowngradeToInsecureRepositories is '${_val:-<unset>}', expected ^0$"
fi

fi
if secaudit_rule_enabled 52; then
_val=""
if sec_audit_have_bin apt-config; then
  _val=$(apt-config dump 2>/dev/null | awk -v o=Acquire::Check-Date '$1==o {gsub(/[";]/,"",$2); print $2; exit}')
fi
if [ -n "$_val" ] && printf '%s' "$_val" | grep -Eq -- '^true$'; then
  sec_audit_report_pass 52 "APT Acquire::Check-Date is enabled (Acquire::Check-Date=${_val})"
else
  sec_audit_report_fail 52 "APT Acquire::Check-Date is enabled - Acquire::Check-Date is '${_val:-<unset>}', expected ^true$"
fi

fi
if secaudit_rule_enabled 53; then
_pending=$(apt-get -s upgrade 2>/dev/null | awk '/^Inst /{c++} END{print c+0}')
_reboot="no"
[ -f /var/run/reboot-required ] && _reboot="yes"
if [ "${_pending:-0}" -eq 0 ] && [ "$_reboot" = "no" ]; then
  sec_audit_report_pass 53 "no pending package updates and no reboot required"
else
  sec_audit_report_fail 53 "pending package updates: ${_pending:-unknown}, reboot required: ${_reboot}"
fi

fi
if secaudit_rule_enabled 54; then
if sec_audit_is_package_installed apparmor; then
  sec_audit_report_pass 54 "AppArmor package is installed"
else
  sec_audit_report_fail 54 "AppArmor package is not installed"
fi

fi
if secaudit_rule_enabled 55; then
_bad=""
grep -qs -- 'apparmor=0' /proc/cmdline && _bad+=" apparmor=0 in kernel cmdline"
if sec_audit_is_package_installed apparmor; then
  sec_audit_is_service_enabled apparmor.service || _bad+=" apparmor.service is not enabled"
  sec_audit_is_service_active apparmor.service || _bad+=" apparmor.service is not active"
  sec_audit_apparmor_status_output | grep -qE '[1-9][0-9]* profiles are loaded' || _bad+=" no AppArmor profiles are loaded"
else
  _bad+=" apparmor package is not installed"
fi
if [ -z "$_bad" ]; then
  sec_audit_report_pass 55 "AppArmor is enabled, active and profiles are loaded"
else
  sec_audit_report_fail 55 "AppArmor is not fully enabled:${_bad}"
fi

fi
if secaudit_rule_enabled 56; then
if sec_audit_apparmor_profiles_all_enforcing_ok; then
  sec_audit_report_pass 56 "all AppArmor profiles are in enforce mode"
else
  sec_audit_report_fail 56 "some AppArmor profiles are not in enforce mode (complain/kill/unconfined present)"
fi

fi
if secaudit_rule_enabled 57; then
_sr=$(sec_audit_sysctl_key_runtime_raw kernel.apparmor_restrict_unprivileged_unconfined)
if sec_audit_sysctl_runtime_equals kernel.apparmor_restrict_unprivileged_unconfined 1; then
  sec_audit_report_pass 57 "kernel.apparmor_restrict_unprivileged_unconfined=1 in kernel$(sec_audit_sysctl_runtime_disk_hint kernel.apparmor_restrict_unprivileged_unconfined 1)"
else
  sec_audit_report_fail 57 "kernel kernel.apparmor_restrict_unprivileged_unconfined is '${_sr:-<unreadable>}', expected 1$(sec_audit_sysctl_runtime_disk_hint kernel.apparmor_restrict_unprivileged_unconfined 1)"
fi

fi
if secaudit_rule_enabled 58; then
if grep -qE '^\s*set\s+superusers=' /boot/grub/grub.cfg 2>/dev/null &&     grep -qE '^\s*GRUB2_PASSWORD=grub\.pbkdf2\.sha512\.' /boot/grub/user.cfg 2>/dev/null; then
  sec_audit_report_pass 58 "bootloader superuser and hashed GRUB password are configured"
else
  sec_audit_report_fail 58 "bootloader superuser or hashed password configuration is missing"
fi

fi
if secaudit_rule_enabled 59; then
if stat -Lc '%a %U %G' /boot/grub/grub.cfg 2>/dev/null | grep -qE '^600 root root$'; then
  sec_audit_report_pass 59 "grub.cfg permissions are 600 and owner/group are root"
else
  sec_audit_report_fail 59 "grub.cfg permissions or ownership are incorrect"
fi

fi
if secaudit_rule_enabled 60; then
if sec_audit_sysctl_runtime_and_persistent_equals fs.protected_hardlinks 1; then
  sec_audit_report_pass 60 "fs.protected_hardlinks=1 in kernel and persistent configuration"
else
  sec_audit_report_fail 60 "fs.protected_hardlinks is '$(sec_audit_sysctl_runtime_display fs.protected_hardlinks)' (last on-disk value '$(sec_audit_sysctl_files_last_assignment_display fs.protected_hardlinks)'), expected 1 in both"
fi

fi
if secaudit_rule_enabled 61; then
if sec_audit_sysctl_runtime_and_persistent_equals fs.protected_symlinks 1; then
  sec_audit_report_pass 61 "fs.protected_symlinks=1 in kernel and persistent configuration"
else
  sec_audit_report_fail 61 "fs.protected_symlinks is '$(sec_audit_sysctl_runtime_display fs.protected_symlinks)' (last on-disk value '$(sec_audit_sysctl_files_last_assignment_display fs.protected_symlinks)'), expected 1 in both"
fi

fi
if secaudit_rule_enabled 62; then
if sec_audit_sysctl_runtime_and_persistent_equals kernel.yama.ptrace_scope 1; then
  sec_audit_report_pass 62 "kernel.yama.ptrace_scope=1 in kernel and persistent configuration"
else
  sec_audit_report_fail 62 "kernel.yama.ptrace_scope is '$(sec_audit_sysctl_runtime_display kernel.yama.ptrace_scope)' (last on-disk value '$(sec_audit_sysctl_files_last_assignment_display kernel.yama.ptrace_scope)'), expected 1 in both"
fi

fi
if secaudit_rule_enabled 63; then
if sec_audit_sysctl_runtime_and_persistent_equals fs.suid_dumpable 0; then
  sec_audit_report_pass 63 "fs.suid_dumpable=0 in kernel and persistent configuration"
else
  sec_audit_report_fail 63 "fs.suid_dumpable is '$(sec_audit_sysctl_runtime_display fs.suid_dumpable)' (last on-disk value '$(sec_audit_sysctl_files_last_assignment_display fs.suid_dumpable)'), expected 0 in both"
fi

fi
if secaudit_rule_enabled 64; then
if sec_audit_sysctl_runtime_and_persistent_equals kernel.dmesg_restrict 1; then
  sec_audit_report_pass 64 "kernel.dmesg_restrict=1 in kernel and persistent configuration"
else
  sec_audit_report_fail 64 "kernel.dmesg_restrict is '$(sec_audit_sysctl_runtime_display kernel.dmesg_restrict)' (last on-disk value '$(sec_audit_sysctl_files_last_assignment_display kernel.dmesg_restrict)'), expected 1 in both"
fi

fi
if secaudit_rule_enabled 65; then
_present=""
for _p in prelink; do
  sec_audit_is_package_installed "$_p" && _present+=" ${_p}"
done
if [ -z "$_present" ]; then
  sec_audit_report_pass 65 "package(s) not installed: prelink"
else
  sec_audit_report_fail 65 "unwanted package(s) installed:${_present}"
fi

fi
if secaudit_rule_enabled 66; then
if ! systemctl is-enabled apport 2>/dev/null | grep -q '^enabled' || grep -q 'enabled=0' /etc/default/apport 2>/dev/null; then
  sec_audit_report_pass 66 "Apport automatic error reporting is disabled"
else
  sec_audit_report_fail 66 "Apport automatic error reporting is enabled"
fi

fi
if secaudit_rule_enabled 67; then
_re='^(1|2)$'
_sr=$(sec_audit_sysctl_key_runtime_raw kernel.kptr_restrict)
_sd=$(sec_audit_sysctl_files_last_assignment_value kernel.kptr_restrict)
if [ -n "$_sr" ] && printf '%s' "$_sr" | grep -Eq -- "$_re" && [ -n "$_sd" ] && printf '%s' "$_sd" | grep -Eq -- "$_re"; then
  sec_audit_report_pass 67 "kernel.kptr_restrict=${_sr} (persistent ${_sd}) matches ^(1|2)$"
else
  sec_audit_report_fail 67 "kernel.kptr_restrict is '${_sr:-<unreadable>}' (last on-disk value '${_sd:-<none>}'), expected to match ^(1|2)$"
fi

fi
if secaudit_rule_enabled 68; then
if sec_audit_sysctl_runtime_and_persistent_equals "kernel.randomize_va_space" "2"; then
  sec_audit_report_pass 68 "ASLR is enabled kernel.randomize_va_space = 2"
else
  sec_audit_report_fail 68 "ASLR is disabled or not fully enabled"
fi

fi
if secaudit_rule_enabled 69; then
_bad=""
grep -Psiq -- '^\h*\*\h+hard\h+core\h+0\b' /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null || _bad+=" no '* hard core 0' entry"
if grep -Psi -- '^\h*\*\h+hard\h+core\h+([1-9][0-9]*|unlimited)\b' /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null | grep -q .; then
  _bad+=" core limit greater than 0 configured"
fi
if [ -z "$_bad" ]; then
  sec_audit_report_pass 69 "hard core file size limit is 0 for all users"
else
  sec_audit_report_fail 69 "core file size is not restricted:${_bad}"
fi

fi
if secaudit_rule_enabled 70; then
_val=""
if sec_audit_have_bin systemd-analyze; then
  _val=$(systemd-analyze cat-config systemd/coredump.conf 2>/dev/null | awk -F= '/^[[:space:]]*ProcessSizeMax[[:space:]]*=/{gsub(/[[:space:]]/,"",$2);v=$2} END{print v}')
fi
[ -z "$_val" ] && _val=$(awk -F= '/^[[:space:]]*ProcessSizeMax[[:space:]]*=/{gsub(/[[:space:]]/,"",$2);v=$2} END{print v}' /etc/systemd/coredump.conf /etc/systemd/coredump.conf.d/*.conf /usr/lib/systemd/coredump.conf 2>/dev/null)
if [ "$_val" = "0" ]; then
  sec_audit_report_pass 70 "systemd-coredump ProcessSizeMax is 0"
else
  sec_audit_report_fail 70 "systemd-coredump ProcessSizeMax is '${_val:-<unset>}', expected 0"
fi

fi
if secaudit_rule_enabled 71; then
_val=""
if sec_audit_have_bin systemd-analyze; then
  _val=$(systemd-analyze cat-config systemd/coredump.conf 2>/dev/null | awk -F= '/^[[:space:]]*Storage[[:space:]]*=/{gsub(/[[:space:]]/,"",$2);v=$2} END{print v}')
fi
[ -z "$_val" ] && _val=$(awk -F= '/^[[:space:]]*Storage[[:space:]]*=/{gsub(/[[:space:]]/,"",$2);v=$2} END{print v}' /etc/systemd/coredump.conf /etc/systemd/coredump.conf.d/*.conf /usr/lib/systemd/coredump.conf 2>/dev/null)
if [ "$_val" = "none" ]; then
  sec_audit_report_pass 71 "systemd-coredump Storage is none"
else
  sec_audit_report_fail 71 "systemd-coredump Storage is '${_val:-<unset>}', expected none"
fi

fi
if secaudit_rule_enabled 72; then
_bad=$(sec_audit__sysinfo_leak /etc/motd /etc/motd.d/*)
if [ -z "$_bad" ]; then
  sec_audit_report_pass 72 "MOTD files do not disclose system information"
else
  sec_audit_report_fail 72 "system information disclosed in:${_bad}"
fi

fi
if secaudit_rule_enabled 73; then
_bad=$(sec_audit__sysinfo_leak /etc/issue /usr/lib/issue.d/* /etc/issue.d/* /run/issue.d/*)
if [ -z "$_bad" ]; then
  sec_audit_report_pass 73 "issue files do not disclose system information"
else
  sec_audit_report_fail 73 "system information disclosed in:${_bad}"
fi

fi
if secaudit_rule_enabled 74; then
_bad=$(sec_audit__sysinfo_leak /etc/issue.net)
if [ -z "$_bad" ]; then
  sec_audit_report_pass 74 "/etc/issue.net does not disclose system information"
else
  sec_audit_report_fail 74 "system information disclosed in:${_bad}"
fi

fi
if secaudit_rule_enabled 75; then
_bad=""
for _f in /etc/pam.d/sshd /etc/pam.d/login /etc/pam.d/su /etc/pam.d/gdm-password /usr/lib/pam.d/sshd /usr/lib/pam.d/login /usr/lib/pam.d/su /usr/lib/pam.d/gdm-password; do
  [ -f "$_f" ] || continue
  if grep -Psiq -- '^\h*session\h+.*pam_motd\.so' "$_f" 2>/dev/null       && ! grep -Psiq -- '^\h*session\h+.*pam_motd\.so.*\bmotd=' "$_f" 2>/dev/null; then
    _bad+=" ${_f}"
  fi
done
if [ -z "$_bad" ]; then
  sec_audit_report_pass 75 "pam_motd is configured with an explicit motd= argument"
else
  sec_audit_report_fail 75 "pam_motd without an explicit motd= argument in:${_bad}"
fi

fi
if secaudit_rule_enabled 76; then
_banner=$(sec_audit_sshd_t_awk '$1=="banner" {print $2; exit}')
if [ -z "$_banner" ] || [ "$_banner" = "none" ]; then
  sec_audit_report_fail 76 "sshd warning banner is not configured"
elif [ ! -e "$_banner" ]; then
  sec_audit_report_fail 76 "sshd warning banner file ${_banner} does not exist"
else
  _bad=$(sec_audit__sysinfo_leak "$_banner")
  if [ -z "$_bad" ]; then
    sec_audit_report_pass 76 "sshd warning banner ${_banner} does not disclose system information"
  else
    sec_audit_report_fail 76 "system information disclosed in ${_banner}"
  fi
fi

fi
if secaudit_rule_enabled 77; then
if [ ! -e /etc/motd ]; then
  sec_audit_report_pass 77 "/etc/motd does not exist (nothing to verify)"
elif stat -Lc '%a %U %G' /etc/motd 2>/dev/null | grep -qE '^6[04][04] root root$|^[0-5][0-4][04] root root$'; then
  sec_audit_report_pass 77 "/etc/motd permissions are correctly set root-owned"
else
  sec_audit_report_fail 77 "/etc/motd permissions or ownership are incorrect"
fi

fi
if secaudit_rule_enabled 78; then
if stat -Lc '%a %U %G' /etc/issue 2>/dev/null | grep -qE '^6[04][04] root root$|^[0-5][0-4][04] root root$'; then
  sec_audit_report_pass 78 "/etc/issue permissions are correctly set root-owned"
else
  sec_audit_report_fail 78 "/etc/issue permissions or ownership are incorrect"
fi

fi
if secaudit_rule_enabled 79; then
if stat -Lc '%a %U %G' /etc/issue.net 2>/dev/null | grep -qE '^6[04][04] root root$|^[0-5][0-4][04] root root$'; then
  sec_audit_report_pass 79 "/etc/issue.net permissions are correctly set root-owned"
else
  sec_audit_report_fail 79 "/etc/issue.net permissions or ownership are incorrect"
fi

fi
if secaudit_rule_enabled 80; then
_paths=$(grep -hPo 'motd=\K\S+' /etc/pam.d/* 2>/dev/null | tr -d '"' | sort -u)
_bad=""
for _p in $_paths; do
  [ -e "$_p" ] || continue
  sec_audit__path_access_ok "$_p" 644 root root || _bad+=" $(sec_audit__path_access_describe "$_p")"
done
if [ -z "$_bad" ]; then
  sec_audit_report_pass 80 "pam_motd files have 0644 root:root or more restrictive access"
else
  sec_audit_report_fail 80 "insecure pam_motd files:${_bad}"
fi

fi
if secaudit_rule_enabled 81; then
_banner=$(sec_audit_sshd_t_awk '$1=="banner" {print $2; exit}')
if [ -z "$_banner" ] || [ "$_banner" = "none" ]; then
  sec_audit_report_pass 81 "no sshd warning banner file configured (nothing to verify)"
elif [ ! -e "$_banner" ]; then
  sec_audit_report_fail 81 "sshd warning banner file ${_banner} does not exist"
elif sec_audit__path_access_ok "$_banner" 644 root root; then
  sec_audit_report_pass 81 "$(sec_audit__path_access_describe "$_banner") is 0644 root:root or more restrictive"
else
  sec_audit_report_fail 81 "$(sec_audit__path_access_describe "$_banner") is not 0644 root:root or more restrictive"
fi

fi
if secaudit_rule_enabled 82; then
_ubad=""
sec_audit_is_service_active update-notifier-motd.service && _ubad+=" update-notifier-motd.service is active"
sec_audit_is_service_enabled update-notifier-motd.service && _ubad+=" update-notifier-motd.service is enabled"
if [ -z "$_ubad" ]; then
  sec_audit_report_pass 82 "update-notifier-motd.service is not in use"
else
  sec_audit_report_fail 82 "unit in use:${_ubad}"
fi

fi
if secaudit_rule_enabled 83; then
_ubad=""
sec_audit_is_service_active update-notifier-motd.timer && _ubad+=" update-notifier-motd.timer is active"
sec_audit_is_service_enabled update-notifier-motd.timer && _ubad+=" update-notifier-motd.timer is enabled"
if [ -z "$_ubad" ]; then
  sec_audit_report_pass 83 "update-notifier-motd.timer is not in use"
else
  sec_audit_report_fail 83 "unit in use:${_ubad}"
fi

fi
if secaudit_rule_enabled 84; then
if ! dpkg-query -W -f='${Status}' gdm3 2>/dev/null | grep -q 'install ok installed' || grep -qr 'banner-message-enable=true' /etc/gdm3/ /etc/dconf/db/ 2>/dev/null; then
  sec_audit_report_pass 84 "GDM login banner message is enabled"
else
  sec_audit_report_fail 84 "GDM login banner message is not configured"
fi

fi
if secaudit_rule_enabled 85; then
if sec_audit__gdm_absent; then
  sec_audit_report_pass 85 "GDM user list is disabled on the login screen - GNOME/GDM is not installed"
else
  _dv=$(sec_audit__dconf_value org.gnome.login-screen disable-user-list)
  _dlock="unlocked"
  sec_audit__dconf_locked "org.gnome.login-screen/disable-user-list" && _dlock="locked"
  if [ -n "$_dv" ] && printf '%s' "$_dv" | grep -Eq -- '^true$' && [ "$_dlock" = "locked" ]; then
    sec_audit_report_pass 85 "GDM user list is disabled on the login screen (disable-user-list=${_dv}, locked)"
  else
    sec_audit_report_fail 85 "GDM user list is disabled on the login screen - disable-user-list is '${_dv:-<unset>}' (${_dlock}), expected ^true$ and locked"
  fi
fi

fi
if secaudit_rule_enabled 86; then
if sec_audit__gdm_absent; then
  sec_audit_report_pass 86 "GDM screen lock - GNOME/GDM is not installed"
else
  _idle=$(sec_audit__dconf_value org.gnome.desktop.session idle-delay)
  _lock=$(sec_audit__dconf_value org.gnome.desktop.screensaver lock-delay)
  _lockv=$(sec_audit__dconf_value org.gnome.desktop.screensaver lock-enabled)
  _l1="unlocked"; _l2="unlocked"
  sec_audit__dconf_locked org.gnome.desktop.session/idle-delay && _l1="locked"
  sec_audit__dconf_locked org.gnome.desktop.screensaver/lock-delay && _l2="locked"
  if [ -n "$_idle" ] && [ "$_idle" -le 900 ] 2>/dev/null       && [ -n "$_lock" ] && [ "$_lock" -le 5 ] 2>/dev/null       && [ "$_l1" = "locked" ] && [ "$_l2" = "locked" ]; then
    sec_audit_report_pass 86 "GDM screen lock is configured and locked (idle-delay=${_idle}, lock-delay=${_lock}, lock-enabled=${_lockv:-unset})"
  else
    sec_audit_report_fail 86 "GDM screen lock is not configured or not locked (idle-delay=${_idle:-unset}, lock-delay=${_lock:-unset}, lock-enabled=${_lockv:-unset}, locks: ${_l1}/${_l2})"
  fi
fi

fi
if secaudit_rule_enabled 87; then
if sec_audit__gdm_absent; then
  sec_audit_report_pass 87 "GDM automount - GNOME/GDM is not installed"
else
  _am=$(sec_audit__dconf_value org.gnome.desktop.media-handling automount)
  _amo=$(sec_audit__dconf_value org.gnome.desktop.media-handling automount-open)
  _l1="unlocked"; _l2="unlocked"
  sec_audit__dconf_locked org.gnome.desktop.media-handling/automount && _l1="locked"
  sec_audit__dconf_locked org.gnome.desktop.media-handling/automount-open && _l2="locked"
  if [ "$_am" = "false" ] && [ "$_amo" = "false" ] && [ "$_l1" = "locked" ] && [ "$_l2" = "locked" ]; then
    sec_audit_report_pass 87 "GDM automount and automount-open are disabled and locked"
  else
    sec_audit_report_fail 87 "GDM automount is not configured/locked (automount=${_am:-unset}/${_l1}, automount-open=${_amo:-unset}/${_l2})"
  fi
fi

fi
if secaudit_rule_enabled 88; then
if sec_audit__gdm_absent; then
  sec_audit_report_pass 88 "GDM autorun-never is enabled - GNOME/GDM is not installed"
else
  _dv=$(sec_audit__dconf_value org.gnome.desktop.media-handling autorun-never)
  _dlock="unlocked"
  sec_audit__dconf_locked "org.gnome.desktop.media-handling/autorun-never" && _dlock="locked"
  if [ -n "$_dv" ] && printf '%s' "$_dv" | grep -Eq -- '^true$' && [ "$_dlock" = "locked" ]; then
    sec_audit_report_pass 88 "GDM autorun-never is enabled (autorun-never=${_dv}, locked)"
  else
    sec_audit_report_fail 88 "GDM autorun-never is enabled - autorun-never is '${_dv:-<unset>}' (${_dlock}), expected ^true$ and locked"
  fi
fi

fi
if secaudit_rule_enabled 89; then
if ! grep -qE '^Enable=true' /etc/gdm3/custom.conf 2>/dev/null; then
  sec_audit_report_pass 89 "XDMCP is not enabled in GDM"
else
  sec_audit_report_fail 89 "XDMCP is enabled in GDM configuration"
fi

fi
if secaudit_rule_enabled 90; then
if sec_audit__gdm_absent; then
  sec_audit_report_pass 90 "Xwayland - GNOME/GDM is not installed"
else
  _found=""
  for _f in /etc/gdm3/custom.conf /etc/gdm3/daemon.conf /etc/gdm/custom.conf /etc/gdm/daemon.conf; do
    [ -e "$_f" ] || continue
    grep -Piq '^\h*WaylandEnable\h*=\h*false\b' "$_f" 2>/dev/null && _found="$_f"
  done
  if [ -n "$_found" ]; then
    sec_audit_report_pass 90 "Xwayland is disabled (WaylandEnable=false in ${_found})"
  else
    sec_audit_report_fail 90 "WaylandEnable=false is not configured in the GDM configuration"
  fi
fi

fi
}

sec_audit_run_services() {
if secaudit_rule_enabled 91; then
if ! (sec_audit_is_package_installed autofs && sec_audit_is_service_active autofs); then
  sec_audit_report_pass 91 "autofs service is not installed or not running"
else
  sec_audit_report_fail 91 "autofs service is installed and running"
fi

fi
if secaudit_rule_enabled 92; then
if ! (sec_audit_is_package_installed avahi-daemon && sec_audit_is_service_active avahi-daemon); then
  sec_audit_report_pass 92 "avahi-daemon service is not installed or not running"
else
  sec_audit_report_fail 92 "avahi-daemon service is installed and running"
fi

fi
if secaudit_rule_enabled 93; then
if ! dpkg-query -W -f='${Status}' isc-dhcp-server 2>/dev/null | grep -q 'install ok installed'; then
  sec_audit_report_pass 93 "DHCP server isc-dhcp-server is not installed"
else
  sec_audit_report_fail 93 "DHCP server is installed"
fi

fi
if secaudit_rule_enabled 94; then
if ! dpkg-query -W -f='${Status}' bind9 2>/dev/null | grep -q 'install ok installed'; then
  sec_audit_report_pass 94 "DNS server bind9 is not installed"
else
  sec_audit_report_fail 94 "DNS server bind9 is installed"
fi

fi
if secaudit_rule_enabled 95; then
if ! (sec_audit_is_package_installed dnsmasq && sec_audit_is_service_active dnsmasq); then
  sec_audit_report_pass 95 "dnsmasq service is not installed or not running"
else
  sec_audit_report_fail 95 "dnsmasq service is installed and running"
fi

fi
if secaudit_rule_enabled 96; then
if ! dpkg-query -W -f='${Status}' vsftpd 2>/dev/null | grep -q 'install ok installed' && ! dpkg-query -W -f='${Status}' proftpd-basic 2>/dev/null | grep -q 'install ok installed'; then
  sec_audit_report_pass 96 "FTP server vsftpd/proftpd is not installed"
else
  sec_audit_report_fail 96 "FTP server is installed"
fi

fi
if secaudit_rule_enabled 97; then
if ! dpkg-query -W -f='${Status}' slapd 2>/dev/null | grep -q 'install ok installed'; then
  sec_audit_report_pass 97 "LDAP server slapd is not installed"
else
  sec_audit_report_fail 97 "LDAP server slapd is installed"
fi

fi
if secaudit_rule_enabled 98; then
if ! dpkg-query -W -f='${Status}' dovecot-imapd 2>/dev/null | grep -q 'install ok installed' && ! dpkg-query -W -f='${Status}' dovecot-pop3d 2>/dev/null | grep -q 'install ok installed'; then
  sec_audit_report_pass 98 "IMAP/POP3 server dovecot is not installed"
else
  sec_audit_report_fail 98 "IMAP/POP3 server dovecot is installed"
fi

fi
if secaudit_rule_enabled 99; then
if ! dpkg-query -W -f='${Status}' nfs-kernel-server 2>/dev/null | grep -q 'install ok installed'; then
  sec_audit_report_pass 99 "NFS server is not installed"
else
  sec_audit_report_fail 99 "NFS server is installed"
fi

fi
if secaudit_rule_enabled 100; then
if ! dpkg-query -W -f='${Status}' nis 2>/dev/null | grep -q 'install ok installed'; then
  sec_audit_report_pass 100 "NIS server is not installed"
else
  sec_audit_report_fail 100 "NIS server is installed"
fi

fi
if secaudit_rule_enabled 101; then
if ! (sec_audit_is_package_installed cups && { sec_audit_is_service_active cups || sec_audit_is_service_active cups.socket \
     || sec_audit_is_service_enabled cups || sec_audit_is_service_enabled cups.socket; }); then
  sec_audit_report_pass 101 "print server CUPS is not installed, not running and not enabled"
else
  sec_audit_report_fail 101 "print server CUPS is installed and running or enabled"
fi

fi
if secaudit_rule_enabled 102; then
if ! (sec_audit_is_package_installed rpcbind && sec_audit_is_service_active rpcbind); then
  sec_audit_report_pass 102 "rpcbind service is not installed or not running"
else
  sec_audit_report_fail 102 "rpcbind service is installed and running"
fi

fi
if secaudit_rule_enabled 103; then
if ! (sec_audit_is_package_installed rsync && sec_audit_is_service_active rsync); then
  sec_audit_report_pass 103 "rsync daemon is not installed or not running"
else
  sec_audit_report_fail 103 "rsync daemon is installed and running"
fi

fi
if secaudit_rule_enabled 104; then
if ! dpkg-query -W -f='${Status}' samba 2>/dev/null | grep -q 'install ok installed'; then
  sec_audit_report_pass 104 "Samba file server is not installed"
else
  sec_audit_report_fail 104 "Samba file server is installed"
fi

fi
if secaudit_rule_enabled 105; then
if ! dpkg-query -W -f='${Status}' snmpd 2>/dev/null | grep -q 'install ok installed'; then
  sec_audit_report_pass 105 "SNMP daemon is not installed"
else
  sec_audit_report_fail 105 "SNMP daemon is installed"
fi

fi
if secaudit_rule_enabled 106; then
_ubad=""
if sec_audit_is_package_installed telnetd; then
  sec_audit_is_service_active inetd && _ubad+=" inetd is active"
  sec_audit_is_service_enabled inetd && _ubad+=" inetd is enabled"
fi
if [ -z "$_ubad" ]; then
  sec_audit_report_pass 106 "telnetd is not installed or not in use"
else
  sec_audit_report_fail 106 "service in use:${_ubad}"
fi

fi
if secaudit_rule_enabled 107; then
if ! dpkg-query -W -f='${Status}' tftpd-hpa 2>/dev/null | grep -q 'install ok installed'; then
  sec_audit_report_pass 107 "TFTP server is not installed"
else
  sec_audit_report_fail 107 "TFTP server is installed"
fi

fi
if secaudit_rule_enabled 108; then
if ! (sec_audit_is_package_installed squid && sec_audit_is_service_active squid); then
  sec_audit_report_pass 108 "web proxy squid is not installed or not running"
else
  sec_audit_report_fail 108 "web proxy squid is installed and running"
fi

fi
if secaudit_rule_enabled 109; then
if ! dpkg-query -W -f='${Status}' apache2 2>/dev/null | grep -q 'install ok installed' && ! dpkg-query -W -f='${Status}' nginx 2>/dev/null | grep -q 'install ok installed'; then
  sec_audit_report_pass 109 "web server apache2/nginx is not installed"
else
  sec_audit_report_fail 109 "web server apache2/nginx is installed"
fi

fi
if secaudit_rule_enabled 110; then
if ! dpkg-query -W -f='${Status}' xinetd 2>/dev/null | grep -q 'install ok installed'; then
  sec_audit_report_pass 110 "xinetd is not installed"
else
  sec_audit_report_fail 110 "xinetd is installed"
fi

fi
if secaudit_rule_enabled 111; then
if ! dpkg-query -W -f='${Status}' xserver-xorg-core 2>/dev/null | grep -q 'install ok installed'; then
  sec_audit_report_pass 111 "X Window server is not installed"
else
  sec_audit_report_fail 111 "X Window server is installed"
fi

fi
if secaudit_rule_enabled 112; then
if ! sec_audit_have_bin ss; then
  sec_audit_report_fail 112 "MTA listeners could not be enumerated (ss is not available)"
else
  _bad=""
  for _p in 25 465 587; do
    if ss -plntu 2>/dev/null | grep -P -- ":${_p}\h" | grep -Pvq -- '\h+(127\.0\.0\.1|\[?::1\]?):'"${_p}"'\b'; then
      _bad+=" port ${_p}"
    fi
  done
  if [ -z "$_bad" ]; then
    sec_audit_report_pass 112 "mail transfer agent is not listening on a non-loopback interface"
  else
    sec_audit_report_fail 112 "MTA listening on non-loopback:${_bad}"
  fi
fi

fi
if secaudit_rule_enabled 113; then
if ! sec_audit_have_bin ss; then
  sec_audit_report_fail 113 "listening sockets could not be enumerated (ss is not available)"
else
  _l=$(ss -plntu 2>/dev/null | awk 'NR>1 {print $1"/"$5}' | sort | tr '\n' ' ')
  _bad=""
  _n=0
  while IFS= read -r _ln; do
    [ -n "$_ln" ] || continue
    _n=$((_n + 1))
    _pid=$(printf '%s' "$_ln" | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p')
    if [ -z "$_pid" ]; then
      _bad+=" unidentified-listener"
      continue
    fi
    _exe=$(readlink -f "/proc/$_pid/exe" 2>/dev/null)
    if [ -z "$_exe" ] || ! sec_audit__pkg_owns_path "$_exe"; then
      _bad+=" ${_exe:-pid:$_pid}"
    fi
  done < <(ss -plntu 2>/dev/null | tail -n +2)
  if [ "$_n" -eq 0 ]; then
    sec_audit_report_pass 113 "no services are listening on network interfaces"
  elif [ -z "$_bad" ]; then
    sec_audit_report_pass 113 "all ${_n} listeners belong to installed packages | listeners: $(sec_audit__sanitize "$_l")"
  else
    sec_audit_report_fail 113 "listeners not provided by an installed package:${_bad} | listeners: $(sec_audit__sanitize "$_l")"
  fi
fi

fi
if secaudit_rule_enabled 114; then
if ! dpkg-query -W -f='${Status}' nis 2>/dev/null | grep -q 'install ok installed'; then
  sec_audit_report_pass 114 "NIS client is not installed"
else
  sec_audit_report_fail 114 "NIS client is installed"
fi

fi
if secaudit_rule_enabled 115; then
if ! dpkg-query -W -f='${Status}' rsh-client 2>/dev/null | grep -q 'install ok installed'; then
  sec_audit_report_pass 115 "rsh client is not installed"
else
  sec_audit_report_fail 115 "rsh client is installed"
fi

fi
if secaudit_rule_enabled 116; then
if ! dpkg-query -W -f='${Status}' talk 2>/dev/null | grep -q 'install ok installed'; then
  sec_audit_report_pass 116 "talk client is not installed"
else
  sec_audit_report_fail 116 "talk client is installed"
fi

fi
if secaudit_rule_enabled 117; then
if ! dpkg-query -W -f='${Status}' telnet 2>/dev/null | grep -q 'install ok installed'; then
  sec_audit_report_pass 117 "telnet client is not installed"
else
  sec_audit_report_fail 117 "telnet client is installed"
fi

fi
if secaudit_rule_enabled 118; then
if ! dpkg-query -W -f='${Status}' ldap-utils 2>/dev/null | grep -q 'install ok installed'; then
  sec_audit_report_pass 118 "LDAP client ldap-utils is not installed"
else
  sec_audit_report_fail 118 "LDAP client ldap-utils is installed"
fi

fi
if secaudit_rule_enabled 119; then
if ! dpkg-query -W -f='${Status}' ftp 2>/dev/null | grep -q 'install ok installed'; then
  sec_audit_report_pass 119 "FTP client is not installed"
else
  sec_audit_report_fail 119 "FTP client is installed"
fi

fi
if secaudit_rule_enabled 120; then
_ts_active=0
for _u in chrony systemd-timesyncd ntp openntpd; do
  if sec_audit_is_package_installed "$_u" && systemctl is-active "$_u" 2>/dev/null | grep -q '^active$'; then
    _ts_active=1
  fi
done
if [ "$_ts_active" -eq 1 ]; then
  sec_audit_report_pass 120 "a time synchronization service is installed and running"
else
  sec_audit_report_fail 120 "no time synchronization service is installed and running"
fi

fi
if secaudit_rule_enabled 121; then
_chrony_active="$(systemctl is-active chrony 2>/dev/null)"
_timesyncd_active="$(systemctl is-active systemd-timesyncd 2>/dev/null)"
if [ "$(printf '%s\n' "$_chrony_active" "$_timesyncd_active" | grep -c '^active$')" -eq 1 ]; then
  sec_audit_report_pass 121 "exactly one time synchronization daemon is active"
else
  sec_audit_report_fail 121 "zero or multiple time synchronization daemons are active"
fi

fi
if secaudit_rule_enabled 122; then
if grep -qE '^NTP=' /etc/systemd/timesyncd.conf 2>/dev/null || grep -rqE '^NTP=' /etc/systemd/timesyncd.conf.d/ 2>/dev/null; then
  sec_audit_report_pass 122 "systemd-timesyncd NTP server is configured"
else
  sec_audit_report_fail 122 "systemd-timesyncd NTP server is not configured"
fi

fi
if secaudit_rule_enabled 123; then
if systemctl is-active systemd-timesyncd 2>/dev/null | grep -q '^active' && systemctl is-enabled systemd-timesyncd 2>/dev/null | grep -q '^enabled'; then
  sec_audit_report_pass 123 "systemd-timesyncd is enabled and running"
else
  sec_audit_report_fail 123 "systemd-timesyncd is not enabled or not running"
fi

fi
if secaudit_rule_enabled 124; then
if ! sec_audit_is_package_installed chrony; then
  sec_audit_report_pass 124 "chrony is not in use (nothing to verify)"
else
  _srv=$(grep -rPhs -- '^\h*(server|pool)\h+\S+' /etc/chrony/chrony.conf /etc/chrony/conf.d/ /etc/chrony/sources.d/ 2>/dev/null | head -n1)
  if [ -n "$_srv" ]; then
    sec_audit_report_pass 124 "chrony is configured with an authorized timeserver"
  else
    sec_audit_report_fail 124 "chrony has no server or pool entries configured"
  fi
fi

fi
if secaudit_rule_enabled 125; then
if ! sec_audit_is_package_installed chrony; then
  sec_audit_report_pass 125 "chrony is not in use (nothing to verify)"
elif ps -u _chrony -o pid= 2>/dev/null | grep -q .; then
  sec_audit_report_pass 125 "chronyd is running as user _chrony"
else
  sec_audit_report_fail 125 "chronyd is not running as user _chrony"
fi

fi
if secaudit_rule_enabled 126; then
if ! sec_audit_is_package_installed chrony; then
  sec_audit_report_pass 126 "chrony is not in use (nothing to verify)"
elif systemctl is-active chrony 2>/dev/null | grep -q '^active' && systemctl is-enabled chrony 2>/dev/null | grep -q '^enabled'; then
  sec_audit_report_pass 126 "chrony is enabled and running"
else
  sec_audit_report_fail 126 "chrony is not enabled or not running"
fi

fi
if secaudit_rule_enabled 127; then
if systemctl is-active cron 2>/dev/null | grep -q '^active' && systemctl is-enabled cron 2>/dev/null | grep -q '^enabled'; then
  sec_audit_report_pass 127 "cron daemon is enabled and running"
else
  sec_audit_report_fail 127 "cron daemon is not enabled or not running"
fi

fi
if secaudit_rule_enabled 128; then
if ! sec_audit_is_package_installed cron; then
  sec_audit_report_pass 128 "cron is not installed (nothing to verify)"
else
  _bad=""
  _missing=""
  for _p in /etc/crontab; do
    if [ ! -e "$_p" ]; then
      case "$_p" in
        *\**|*\?*) : ;;
        *) _missing+=" ${_p}" ;;
      esac
      continue
    fi
    sec_audit__path_access_ok "$_p" 600 'root' 'root' || _bad+=" $(sec_audit__path_access_describe "$_p")"
  done
  if [ -n "$_bad" ]; then
    sec_audit_report_fail 128 "insecure access on:${_bad} (expected 600 root:root or more restrictive)"
  elif [ -n "$_missing" ]; then
    sec_audit_report_fail 128 "missing path(s):${_missing}"
  else
    sec_audit_report_pass 128 "access is 600 root:root or more restrictive for all checked paths"
  fi
fi

fi
if secaudit_rule_enabled 129; then
if ! sec_audit_is_package_installed cron; then
  sec_audit_report_pass 129 "cron is not installed (nothing to verify)"
else
  _bad=""
  _missing=""
  for _p in /etc/cron.hourly; do
    if [ ! -e "$_p" ]; then
      case "$_p" in
        *\**|*\?*) : ;;
        *) _missing+=" ${_p}" ;;
      esac
      continue
    fi
    sec_audit__path_access_ok "$_p" 700 'root' 'root' || _bad+=" $(sec_audit__path_access_describe "$_p")"
  done
  if [ -n "$_bad" ]; then
    sec_audit_report_fail 129 "insecure access on:${_bad} (expected 700 root:root or more restrictive)"
  elif [ -n "$_missing" ]; then
    sec_audit_report_fail 129 "missing path(s):${_missing}"
  else
    sec_audit_report_pass 129 "access is 700 root:root or more restrictive for all checked paths"
  fi
fi

fi
if secaudit_rule_enabled 130; then
if ! sec_audit_is_package_installed cron; then
  sec_audit_report_pass 130 "cron is not installed (nothing to verify)"
else
  _bad=""
  _missing=""
  for _p in /etc/cron.daily; do
    if [ ! -e "$_p" ]; then
      case "$_p" in
        *\**|*\?*) : ;;
        *) _missing+=" ${_p}" ;;
      esac
      continue
    fi
    sec_audit__path_access_ok "$_p" 700 'root' 'root' || _bad+=" $(sec_audit__path_access_describe "$_p")"
  done
  if [ -n "$_bad" ]; then
    sec_audit_report_fail 130 "insecure access on:${_bad} (expected 700 root:root or more restrictive)"
  elif [ -n "$_missing" ]; then
    sec_audit_report_fail 130 "missing path(s):${_missing}"
  else
    sec_audit_report_pass 130 "access is 700 root:root or more restrictive for all checked paths"
  fi
fi

fi
if secaudit_rule_enabled 131; then
if ! sec_audit_is_package_installed cron; then
  sec_audit_report_pass 131 "cron is not installed (nothing to verify)"
else
  _bad=""
  _missing=""
  for _p in /etc/cron.weekly; do
    if [ ! -e "$_p" ]; then
      case "$_p" in
        *\**|*\?*) : ;;
        *) _missing+=" ${_p}" ;;
      esac
      continue
    fi
    sec_audit__path_access_ok "$_p" 700 'root' 'root' || _bad+=" $(sec_audit__path_access_describe "$_p")"
  done
  if [ -n "$_bad" ]; then
    sec_audit_report_fail 131 "insecure access on:${_bad} (expected 700 root:root or more restrictive)"
  elif [ -n "$_missing" ]; then
    sec_audit_report_fail 131 "missing path(s):${_missing}"
  else
    sec_audit_report_pass 131 "access is 700 root:root or more restrictive for all checked paths"
  fi
fi

fi
if secaudit_rule_enabled 132; then
if ! sec_audit_is_package_installed cron; then
  sec_audit_report_pass 132 "cron is not installed (nothing to verify)"
else
  _bad=""
  _missing=""
  for _p in /etc/cron.monthly; do
    if [ ! -e "$_p" ]; then
      case "$_p" in
        *\**|*\?*) : ;;
        *) _missing+=" ${_p}" ;;
      esac
      continue
    fi
    sec_audit__path_access_ok "$_p" 700 'root' 'root' || _bad+=" $(sec_audit__path_access_describe "$_p")"
  done
  if [ -n "$_bad" ]; then
    sec_audit_report_fail 132 "insecure access on:${_bad} (expected 700 root:root or more restrictive)"
  elif [ -n "$_missing" ]; then
    sec_audit_report_fail 132 "missing path(s):${_missing}"
  else
    sec_audit_report_pass 132 "access is 700 root:root or more restrictive for all checked paths"
  fi
fi

fi
if secaudit_rule_enabled 133; then
if ! sec_audit_is_package_installed cron; then
  sec_audit_report_pass 133 "cron is not installed (nothing to verify)"
else
  _bad=""
  _missing=""
  for _p in /etc/cron.yearly; do
    if [ ! -e "$_p" ]; then
      case "$_p" in
        *\**|*\?*) : ;;
        *) _missing+=" ${_p}" ;;
      esac
      continue
    fi
    sec_audit__path_access_ok "$_p" 700 'root' 'root' || _bad+=" $(sec_audit__path_access_describe "$_p")"
  done
  if [ -n "$_bad" ]; then
    sec_audit_report_fail 133 "insecure access on:${_bad} (expected 700 root:root or more restrictive)"
  elif [ -n "$_missing" ]; then
    sec_audit_report_pass 133 "/etc/cron.yearly does not exist (nothing to verify)"
  else
    sec_audit_report_pass 133 "access is 700 root:root or more restrictive for all checked paths"
  fi
fi

fi
if secaudit_rule_enabled 134; then
if ! sec_audit_is_package_installed cron; then
  sec_audit_report_pass 134 "cron is not installed (nothing to verify)"
else
  _bad=""
  _missing=""
  for _p in /etc/cron.d; do
    if [ ! -e "$_p" ]; then
      case "$_p" in
        *\**|*\?*) : ;;
        *) _missing+=" ${_p}" ;;
      esac
      continue
    fi
    sec_audit__path_access_ok "$_p" 700 'root' 'root' || _bad+=" $(sec_audit__path_access_describe "$_p")"
  done
  if [ -n "$_bad" ]; then
    sec_audit_report_fail 134 "insecure access on:${_bad} (expected 700 root:root or more restrictive)"
  elif [ -n "$_missing" ]; then
    sec_audit_report_fail 134 "missing path(s):${_missing}"
  else
    sec_audit_report_pass 134 "access is 700 root:root or more restrictive for all checked paths"
  fi
fi

fi
if secaudit_rule_enabled 135; then
if ! sec_audit_is_package_installed cron; then
  sec_audit_report_pass 135 "cron is not installed (nothing to verify)"
else
  _bad=""
  _missing=""
  for _p in /etc/cron.allow; do
    if [ ! -e "$_p" ]; then
      case "$_p" in
        *\**|*\?*) : ;;
        *) _missing+=" ${_p}" ;;
      esac
      continue
    fi
    sec_audit__path_access_ok "$_p" 640 'root' 'root|crontab' || _bad+=" $(sec_audit__path_access_describe "$_p")"
  done
  if [ -n "$_bad" ]; then
    sec_audit_report_fail 135 "insecure access on:${_bad} (expected 640 root:root|crontab or more restrictive)"
  elif [ -n "$_missing" ]; then
    sec_audit_report_fail 135 "missing path(s):${_missing}"
  else
    sec_audit_report_pass 135 "access is 640 root:root|crontab or more restrictive for all checked paths"
  fi
fi

fi
if secaudit_rule_enabled 136; then
if ! sec_audit_is_package_installed at; then
  sec_audit_report_pass 136 "at is not installed (nothing to verify)"
else
  _bad=""
  _missing=""
  for _p in /etc/at.allow; do
    if [ ! -e "$_p" ]; then
      case "$_p" in
        *\**|*\?*) : ;;
        *) _missing+=" ${_p}" ;;
      esac
      continue
    fi
    sec_audit__path_access_ok "$_p" 640 'root' 'root|daemon' || _bad+=" $(sec_audit__path_access_describe "$_p")"
  done
  if [ -n "$_bad" ]; then
    sec_audit_report_fail 136 "insecure access on:${_bad} (expected 640 root:root|daemon or more restrictive)"
  elif [ -n "$_missing" ]; then
    sec_audit_report_fail 136 "missing path(s):${_missing}"
  else
    sec_audit_report_pass 136 "access is 640 root:root|daemon or more restrictive for all checked paths"
  fi
fi

fi
}

sec_audit_run_network() {
if secaudit_rule_enabled 137; then
if grep -qs -- '^\h*0\b' /sys/module/ipv6/parameters/disable     || { sec_audit_sysctl_runtime_equals net.ipv6.conf.all.disable_ipv6 1 && sec_audit_sysctl_runtime_equals net.ipv6.conf.default.disable_ipv6 1; }; then
  sec_audit_report_pass 137 "IPv6 status identified: disabled"
else
  sec_audit_report_pass 137 "IPv6 status identified: enabled"
fi

fi
if secaudit_rule_enabled 138; then
_bad=""
for _m in $(lsmod 2>/dev/null | awk 'NR>1 && $1 ~ /^(cfg80211|mac80211|ath|iwlwifi|rtl|brcm|mt76)/ {print $1}'); do
  _bad+=" ${_m} is loaded"
done
for _i in /sys/class/net/*; do
  [ -e "$_i/wireless" ] && _bad+=" ${_i##*/} is a wireless interface"
done
if [ -z "$_bad" ]; then
  sec_audit_report_pass 138 "no wireless interfaces are available"
else
  sec_audit_report_fail 138 "wireless interfaces/modules in use:${_bad}"
fi

fi
if secaudit_rule_enabled 139; then
if ! (dpkg-query -W -f='${Status}' bluez 2>/dev/null | grep -q 'install ok installed' && systemctl is-active bluetooth 2>/dev/null | grep -q '^active'); then
  sec_audit_report_pass 139 "Bluetooth service is not installed or not running"
else
  sec_audit_report_fail 139 "Bluetooth service is installed and running"
fi

fi
if secaudit_rule_enabled 140; then
sec_audit__emit_kernel_mod_unavailable 140 atm

fi
if secaudit_rule_enabled 141; then
sec_audit__emit_kernel_mod_unavailable 141 can

fi
if secaudit_rule_enabled 142; then
sec_audit__emit_kernel_mod_unavailable 142 dccp

fi
if secaudit_rule_enabled 143; then
sec_audit__emit_kernel_mod_unavailable 143 rds

fi
if secaudit_rule_enabled 144; then
sec_audit__emit_kernel_mod_unavailable 144 sctp

fi
if secaudit_rule_enabled 145; then
sec_audit__emit_kernel_mod_unavailable 145 tipc

fi
if secaudit_rule_enabled 146; then
_bad=$(sec_audit__unused_modules_report atm can dccp rds sctp tipc)
if [ -z "$_bad" ]; then
  sec_audit_report_pass 146 "unneeded network protocol kernel modules are disabled and not loaded"
else
  sec_audit_report_fail 146 "unneeded network protocol kernel modules available or loaded:${_bad}"
fi

fi
if secaudit_rule_enabled 147; then
if sec_audit_sysctl_runtime_and_persistent_equals net.ipv4.ip_forward 0; then
  sec_audit_report_pass 147 "net.ipv4.ip_forward=0 in kernel and persistent configuration"
else
  sec_audit_report_fail 147 "net.ipv4.ip_forward is '$(sec_audit_sysctl_runtime_display net.ipv4.ip_forward)' (last on-disk value '$(sec_audit_sysctl_files_last_assignment_display net.ipv4.ip_forward)'), expected 0 in both"
fi

fi
if secaudit_rule_enabled 148; then
if sec_audit_sysctl_runtime_and_persistent_equals net.ipv4.conf.all.forwarding 0; then
  sec_audit_report_pass 148 "net.ipv4.conf.all.forwarding=0 in kernel and persistent configuration"
else
  sec_audit_report_fail 148 "net.ipv4.conf.all.forwarding is '$(sec_audit_sysctl_runtime_display net.ipv4.conf.all.forwarding)' (last on-disk value '$(sec_audit_sysctl_files_last_assignment_display net.ipv4.conf.all.forwarding)'), expected 0 in both"
fi

fi
if secaudit_rule_enabled 149; then
if sec_audit_sysctl_runtime_and_persistent_equals net.ipv4.conf.default.forwarding 0; then
  sec_audit_report_pass 149 "net.ipv4.conf.default.forwarding=0 in kernel and persistent configuration"
else
  sec_audit_report_fail 149 "net.ipv4.conf.default.forwarding is '$(sec_audit_sysctl_runtime_display net.ipv4.conf.default.forwarding)' (last on-disk value '$(sec_audit_sysctl_files_last_assignment_display net.ipv4.conf.default.forwarding)'), expected 0 in both"
fi

fi
if secaudit_rule_enabled 150; then
if sec_audit_sysctl_runtime_and_persistent_equals net.ipv4.conf.all.send_redirects 0; then
  sec_audit_report_pass 150 "net.ipv4.conf.all.send_redirects=0 in kernel and persistent configuration"
else
  sec_audit_report_fail 150 "net.ipv4.conf.all.send_redirects is '$(sec_audit_sysctl_runtime_display net.ipv4.conf.all.send_redirects)' (last on-disk value '$(sec_audit_sysctl_files_last_assignment_display net.ipv4.conf.all.send_redirects)'), expected 0 in both"
fi

fi
if secaudit_rule_enabled 151; then
if sec_audit_sysctl_runtime_and_persistent_equals net.ipv4.conf.default.send_redirects 0; then
  sec_audit_report_pass 151 "net.ipv4.conf.default.send_redirects=0 in kernel and persistent configuration"
else
  sec_audit_report_fail 151 "net.ipv4.conf.default.send_redirects is '$(sec_audit_sysctl_runtime_display net.ipv4.conf.default.send_redirects)' (last on-disk value '$(sec_audit_sysctl_files_last_assignment_display net.ipv4.conf.default.send_redirects)'), expected 0 in both"
fi

fi
if secaudit_rule_enabled 152; then
if sec_audit_sysctl_runtime_and_persistent_equals net.ipv4.icmp_ignore_bogus_error_responses 1; then
  sec_audit_report_pass 152 "net.ipv4.icmp_ignore_bogus_error_responses=1 in kernel and persistent configuration"
else
  sec_audit_report_fail 152 "net.ipv4.icmp_ignore_bogus_error_responses is '$(sec_audit_sysctl_runtime_display net.ipv4.icmp_ignore_bogus_error_responses)' (last on-disk value '$(sec_audit_sysctl_files_last_assignment_display net.ipv4.icmp_ignore_bogus_error_responses)'), expected 1 in both"
fi

fi
if secaudit_rule_enabled 153; then
if sec_audit_sysctl_runtime_and_persistent_equals net.ipv4.icmp_echo_ignore_broadcasts 1; then
  sec_audit_report_pass 153 "net.ipv4.icmp_echo_ignore_broadcasts=1 in kernel and persistent configuration"
else
  sec_audit_report_fail 153 "net.ipv4.icmp_echo_ignore_broadcasts is '$(sec_audit_sysctl_runtime_display net.ipv4.icmp_echo_ignore_broadcasts)' (last on-disk value '$(sec_audit_sysctl_files_last_assignment_display net.ipv4.icmp_echo_ignore_broadcasts)'), expected 1 in both"
fi

fi
if secaudit_rule_enabled 154; then
if sec_audit_sysctl_runtime_and_persistent_equals net.ipv4.conf.all.accept_redirects 0; then
  sec_audit_report_pass 154 "net.ipv4.conf.all.accept_redirects=0 in kernel and persistent configuration"
else
  sec_audit_report_fail 154 "net.ipv4.conf.all.accept_redirects is '$(sec_audit_sysctl_runtime_display net.ipv4.conf.all.accept_redirects)' (last on-disk value '$(sec_audit_sysctl_files_last_assignment_display net.ipv4.conf.all.accept_redirects)'), expected 0 in both"
fi

fi
if secaudit_rule_enabled 155; then
if sec_audit_sysctl_runtime_and_persistent_equals net.ipv4.conf.default.accept_redirects 0; then
  sec_audit_report_pass 155 "net.ipv4.conf.default.accept_redirects=0 in kernel and persistent configuration"
else
  sec_audit_report_fail 155 "net.ipv4.conf.default.accept_redirects is '$(sec_audit_sysctl_runtime_display net.ipv4.conf.default.accept_redirects)' (last on-disk value '$(sec_audit_sysctl_files_last_assignment_display net.ipv4.conf.default.accept_redirects)'), expected 0 in both"
fi

fi
if secaudit_rule_enabled 156; then
if sec_audit_sysctl_runtime_and_persistent_equals net.ipv4.conf.all.secure_redirects 0; then
  sec_audit_report_pass 156 "net.ipv4.conf.all.secure_redirects=0 in kernel and persistent configuration"
else
  sec_audit_report_fail 156 "net.ipv4.conf.all.secure_redirects is '$(sec_audit_sysctl_runtime_display net.ipv4.conf.all.secure_redirects)' (last on-disk value '$(sec_audit_sysctl_files_last_assignment_display net.ipv4.conf.all.secure_redirects)'), expected 0 in both"
fi

fi
if secaudit_rule_enabled 157; then
if sec_audit_sysctl_runtime_and_persistent_equals net.ipv4.conf.default.secure_redirects 0; then
  sec_audit_report_pass 157 "net.ipv4.conf.default.secure_redirects=0 in kernel and persistent configuration"
else
  sec_audit_report_fail 157 "net.ipv4.conf.default.secure_redirects is '$(sec_audit_sysctl_runtime_display net.ipv4.conf.default.secure_redirects)' (last on-disk value '$(sec_audit_sysctl_files_last_assignment_display net.ipv4.conf.default.secure_redirects)'), expected 0 in both"
fi

fi
if secaudit_rule_enabled 158; then
if sec_audit_sysctl_runtime_and_persistent_equals net.ipv4.conf.all.rp_filter 1; then
  sec_audit_report_pass 158 "net.ipv4.conf.all.rp_filter=1 in kernel and persistent configuration"
else
  sec_audit_report_fail 158 "net.ipv4.conf.all.rp_filter is '$(sec_audit_sysctl_runtime_display net.ipv4.conf.all.rp_filter)' (last on-disk value '$(sec_audit_sysctl_files_last_assignment_display net.ipv4.conf.all.rp_filter)'), expected 1 in both"
fi

fi
if secaudit_rule_enabled 159; then
if sec_audit_sysctl_runtime_and_persistent_equals net.ipv4.conf.default.rp_filter 1; then
  sec_audit_report_pass 159 "net.ipv4.conf.default.rp_filter=1 in kernel and persistent configuration"
else
  sec_audit_report_fail 159 "net.ipv4.conf.default.rp_filter is '$(sec_audit_sysctl_runtime_display net.ipv4.conf.default.rp_filter)' (last on-disk value '$(sec_audit_sysctl_files_last_assignment_display net.ipv4.conf.default.rp_filter)'), expected 1 in both"
fi

fi
if secaudit_rule_enabled 160; then
if sec_audit_sysctl_runtime_and_persistent_equals net.ipv4.conf.all.accept_source_route 0; then
  sec_audit_report_pass 160 "net.ipv4.conf.all.accept_source_route=0 in kernel and persistent configuration"
else
  sec_audit_report_fail 160 "net.ipv4.conf.all.accept_source_route is '$(sec_audit_sysctl_runtime_display net.ipv4.conf.all.accept_source_route)' (last on-disk value '$(sec_audit_sysctl_files_last_assignment_display net.ipv4.conf.all.accept_source_route)'), expected 0 in both"
fi

fi
if secaudit_rule_enabled 161; then
if sec_audit_sysctl_runtime_and_persistent_equals net.ipv4.conf.default.accept_source_route 0; then
  sec_audit_report_pass 161 "net.ipv4.conf.default.accept_source_route=0 in kernel and persistent configuration"
else
  sec_audit_report_fail 161 "net.ipv4.conf.default.accept_source_route is '$(sec_audit_sysctl_runtime_display net.ipv4.conf.default.accept_source_route)' (last on-disk value '$(sec_audit_sysctl_files_last_assignment_display net.ipv4.conf.default.accept_source_route)'), expected 0 in both"
fi

fi
if secaudit_rule_enabled 162; then
if sec_audit_sysctl_runtime_and_persistent_equals net.ipv4.conf.all.log_martians 1; then
  sec_audit_report_pass 162 "net.ipv4.conf.all.log_martians=1 in kernel and persistent configuration"
else
  sec_audit_report_fail 162 "net.ipv4.conf.all.log_martians is '$(sec_audit_sysctl_runtime_display net.ipv4.conf.all.log_martians)' (last on-disk value '$(sec_audit_sysctl_files_last_assignment_display net.ipv4.conf.all.log_martians)'), expected 1 in both"
fi

fi
if secaudit_rule_enabled 163; then
if sec_audit_sysctl_runtime_and_persistent_equals net.ipv4.conf.default.log_martians 1; then
  sec_audit_report_pass 163 "net.ipv4.conf.default.log_martians=1 in kernel and persistent configuration"
else
  sec_audit_report_fail 163 "net.ipv4.conf.default.log_martians is '$(sec_audit_sysctl_runtime_display net.ipv4.conf.default.log_martians)' (last on-disk value '$(sec_audit_sysctl_files_last_assignment_display net.ipv4.conf.default.log_martians)'), expected 1 in both"
fi

fi
if secaudit_rule_enabled 164; then
if sec_audit_sysctl_runtime_and_persistent_equals net.ipv4.tcp_syncookies 1; then
  sec_audit_report_pass 164 "net.ipv4.tcp_syncookies=1 in kernel and persistent configuration"
else
  sec_audit_report_fail 164 "net.ipv4.tcp_syncookies is '$(sec_audit_sysctl_runtime_display net.ipv4.tcp_syncookies)' (last on-disk value '$(sec_audit_sysctl_files_last_assignment_display net.ipv4.tcp_syncookies)'), expected 1 in both"
fi

fi
if secaudit_rule_enabled 165; then
if sec_audit_sysctl_runtime_and_persistent_equals net.ipv4.conf.all.route_localnet 0; then
  sec_audit_report_pass 165 "net.ipv4.conf.all.route_localnet=0 in kernel and persistent configuration"
else
  sec_audit_report_fail 165 "net.ipv4.conf.all.route_localnet is '$(sec_audit_sysctl_runtime_display net.ipv4.conf.all.route_localnet)' (last on-disk value '$(sec_audit_sysctl_files_last_assignment_display net.ipv4.conf.all.route_localnet)'), expected 0 in both"
fi

fi
if secaudit_rule_enabled 166; then
if sec_audit_sysctl_runtime_and_persistent_equals net.ipv6.conf.all.forwarding 0; then
  sec_audit_report_pass 166 "net.ipv6.conf.all.forwarding=0 in kernel and persistent configuration"
else
  sec_audit_report_fail 166 "net.ipv6.conf.all.forwarding is '$(sec_audit_sysctl_runtime_display net.ipv6.conf.all.forwarding)' (last on-disk value '$(sec_audit_sysctl_files_last_assignment_display net.ipv6.conf.all.forwarding)'), expected 0 in both"
fi

fi
if secaudit_rule_enabled 167; then
if sec_audit_sysctl_runtime_and_persistent_equals net.ipv6.conf.default.forwarding 0; then
  sec_audit_report_pass 167 "net.ipv6.conf.default.forwarding=0 in kernel and persistent configuration"
else
  sec_audit_report_fail 167 "net.ipv6.conf.default.forwarding is '$(sec_audit_sysctl_runtime_display net.ipv6.conf.default.forwarding)' (last on-disk value '$(sec_audit_sysctl_files_last_assignment_display net.ipv6.conf.default.forwarding)'), expected 0 in both"
fi

fi
if secaudit_rule_enabled 168; then
if sec_audit_sysctl_runtime_and_persistent_equals net.ipv6.conf.all.accept_redirects 0; then
  sec_audit_report_pass 168 "net.ipv6.conf.all.accept_redirects=0 in kernel and persistent configuration"
else
  sec_audit_report_fail 168 "net.ipv6.conf.all.accept_redirects is '$(sec_audit_sysctl_runtime_display net.ipv6.conf.all.accept_redirects)' (last on-disk value '$(sec_audit_sysctl_files_last_assignment_display net.ipv6.conf.all.accept_redirects)'), expected 0 in both"
fi

fi
if secaudit_rule_enabled 169; then
if sec_audit_sysctl_runtime_and_persistent_equals net.ipv6.conf.default.accept_redirects 0; then
  sec_audit_report_pass 169 "net.ipv6.conf.default.accept_redirects=0 in kernel and persistent configuration"
else
  sec_audit_report_fail 169 "net.ipv6.conf.default.accept_redirects is '$(sec_audit_sysctl_runtime_display net.ipv6.conf.default.accept_redirects)' (last on-disk value '$(sec_audit_sysctl_files_last_assignment_display net.ipv6.conf.default.accept_redirects)'), expected 0 in both"
fi

fi
if secaudit_rule_enabled 170; then
if sec_audit_sysctl_runtime_and_persistent_equals net.ipv6.conf.all.accept_source_route 0; then
  sec_audit_report_pass 170 "net.ipv6.conf.all.accept_source_route=0 in kernel and persistent configuration"
else
  sec_audit_report_fail 170 "net.ipv6.conf.all.accept_source_route is '$(sec_audit_sysctl_runtime_display net.ipv6.conf.all.accept_source_route)' (last on-disk value '$(sec_audit_sysctl_files_last_assignment_display net.ipv6.conf.all.accept_source_route)'), expected 0 in both"
fi

fi
if secaudit_rule_enabled 171; then
if sec_audit_sysctl_runtime_and_persistent_equals net.ipv6.conf.default.accept_source_route 0; then
  sec_audit_report_pass 171 "net.ipv6.conf.default.accept_source_route=0 in kernel and persistent configuration"
else
  sec_audit_report_fail 171 "net.ipv6.conf.default.accept_source_route is '$(sec_audit_sysctl_runtime_display net.ipv6.conf.default.accept_source_route)' (last on-disk value '$(sec_audit_sysctl_files_last_assignment_display net.ipv6.conf.default.accept_source_route)'), expected 0 in both"
fi

fi
if secaudit_rule_enabled 172; then
if sec_audit_sysctl_runtime_and_persistent_equals net.ipv6.conf.all.accept_ra 0; then
  sec_audit_report_pass 172 "net.ipv6.conf.all.accept_ra=0 in kernel and persistent configuration"
else
  sec_audit_report_fail 172 "net.ipv6.conf.all.accept_ra is '$(sec_audit_sysctl_runtime_display net.ipv6.conf.all.accept_ra)' (last on-disk value '$(sec_audit_sysctl_files_last_assignment_display net.ipv6.conf.all.accept_ra)'), expected 0 in both"
fi

fi
if secaudit_rule_enabled 173; then
if sec_audit_sysctl_runtime_and_persistent_equals net.ipv6.conf.default.accept_ra 0; then
  sec_audit_report_pass 173 "net.ipv6.conf.default.accept_ra=0 in kernel and persistent configuration"
else
  sec_audit_report_fail 173 "net.ipv6.conf.default.accept_ra is '$(sec_audit_sysctl_runtime_display net.ipv6.conf.default.accept_ra)' (last on-disk value '$(sec_audit_sysctl_files_last_assignment_display net.ipv6.conf.default.accept_ra)'), expected 0 in both"
fi

fi
}

sec_audit_run_logging_and_auditing() {
if secaudit_rule_enabled 174; then
if dpkg-query -W -f='${Status}' ufw 2>/dev/null | grep -q 'install ok installed'; then
  sec_audit_report_pass 174 "UFW is installed"
else
  sec_audit_report_fail 174 "UFW is not installed"
fi

fi
if secaudit_rule_enabled 175; then
if ! sec_audit_is_package_installed ufw; then
  sec_audit_report_fail 175 "ufw is not installed"
elif sec_audit_is_service_enabled ufw && sec_audit_is_service_active ufw && ufw status 2>/dev/null | grep -q '^Status: active'; then
  sec_audit_report_pass 175 "ufw service is enabled, active and the firewall is running"
else
  sec_audit_report_fail 175 "ufw service is not enabled/active or the firewall is not running"
fi

fi
if secaudit_rule_enabled 176; then
if ! sec_audit_is_package_installed ufw; then
  sec_audit_report_fail 176 "ufw is not installed"
else
  _p=$(ufw status verbose 2>/dev/null | awk -F',' '$1 ~ /Default/ {print $1}' | sed 's/.*:[[:space:]]*//;s/^[[:space:]]*//;s/[[:space:]]*(.*$//')
  case "$_p" in
    deny|reject) sec_audit_report_pass 176 "ufw default incoming policy is ${_p}" ;;
    *) sec_audit_report_fail 176 "ufw default incoming policy is '${_p:-unknown}', expected deny or reject" ;;
  esac
fi

fi
if secaudit_rule_enabled 177; then
if ! sec_audit_is_package_installed ufw; then
  sec_audit_report_fail 177 "ufw is not installed"
else
  _p=$(ufw status verbose 2>/dev/null | awk -F',' '$1 ~ /Default/ {print $2}' | sed 's/.*:[[:space:]]*//;s/^[[:space:]]*//;s/[[:space:]]*(.*$//')
  case "$_p" in
    deny|reject) sec_audit_report_pass 177 "ufw default outgoing policy is ${_p}" ;;
    *) sec_audit_report_fail 177 "ufw default outgoing policy is '${_p:-unknown}', expected deny or reject" ;;
  esac
fi

fi
if secaudit_rule_enabled 178; then
if ! sec_audit_is_package_installed ufw; then
  sec_audit_report_fail 178 "ufw is not installed"
elif ufw status verbose 2>/dev/null | grep -q 'deny (routed)'; then
  sec_audit_report_pass 178 "ufw default routed policy is deny"
else
  _f=$(grep -i '^DEFAULT_FORWARD_POLICY' /etc/default/ufw 2>/dev/null | cut -d'"' -f2)
  case "$_f" in
    DROP|REJECT) sec_audit_report_pass 178 "ufw default routed policy is ${_f}" ;;
    *) sec_audit_report_fail 178 "ufw default routed policy is not deny (found '${_f:-unknown}')" ;;
  esac
fi

fi
}

sec_audit_run_access_control() {
if secaudit_rule_enabled 179; then
_bad=""
[ -e /etc/ssh/sshd_config ] && { sec_audit__path_access_ok /etc/ssh/sshd_config 600 root root || _bad+=" $(sec_audit__path_access_describe /etc/ssh/sshd_config)"; }
shopt -s nullglob
for _f in /etc/ssh/sshd_config.d/*.conf; do
  sec_audit__path_access_ok "$_f" 600 root root || _bad+=" $(sec_audit__path_access_describe "$_f")"
done
shopt -u nullglob
if [ -z "$_bad" ]; then
  sec_audit_report_pass 179 "/etc/ssh/sshd_config and included .conf files are 0600 root:root or more restrictive"
else
  sec_audit_report_fail 179 "insecure sshd configuration files:${_bad}"
fi

fi
if secaudit_rule_enabled 180; then
if [ ! -e /etc/ssh/sshd_config.d ]; then
  sec_audit_report_fail 180 "/etc/ssh/sshd_config.d does not exist"
elif sec_audit__path_access_ok /etc/ssh/sshd_config.d 700 root root; then
  sec_audit_report_pass 180 "$(sec_audit__path_access_describe /etc/ssh/sshd_config.d) is 700 root:root or more restrictive"
else
  sec_audit_report_fail 180 "$(sec_audit__path_access_describe /etc/ssh/sshd_config.d) is not 700 root:root or more restrictive"
fi

fi
if secaudit_rule_enabled 181; then
_bad=""
for _f in /etc/ssh/ssh_host_*_key; do
  [ -e "$_f" ] || continue
  case "$_f" in *.pub) continue ;; esac
  sec_audit__path_access_ok "$_f" 600 root root || _bad+=" $(sec_audit__path_access_describe "$_f")"
done
if [ -z "$_bad" ]; then
  sec_audit_report_pass 181 "SSH private host keys are 0600 root:root or more restrictive"
else
  sec_audit_report_fail 181 "insecure SSH private host keys:${_bad}"
fi

fi
if secaudit_rule_enabled 182; then
_bad=""
for _f in /etc/ssh/ssh_host_*_key.pub; do
  [ -e "$_f" ] || continue
  sec_audit__path_access_ok "$_f" 644 root root || _bad+=" $(sec_audit__path_access_describe "$_f")"
done
if [ -z "$_bad" ]; then
  sec_audit_report_pass 182 "SSH public host keys are 0644 root:root or more restrictive"
else
  sec_audit_report_fail 182 "insecure SSH public host keys:${_bad}"
fi

fi
if secaudit_rule_enabled 183; then
if sec_audit_sshd_effective_dump | grep -qiE '^(allowusers|allowgroups|denyusers|denygroups)[[:space:]]+\S+'; then
  sec_audit_report_pass 183 "SSH access is restricted via AllowUsers/AllowGroups/DenyUsers/DenyGroups"
else
  sec_audit_report_fail 183 "SSH access is not restricted by user or group directives"
fi

fi
if secaudit_rule_enabled 184; then
if sec_audit_sshd_effective_dump | grep -i '^banner ' | grep -qv 'none'; then
  sec_audit_report_pass 184 "SSH banner is configured"
else
  sec_audit_report_fail 184 "SSH banner is not configured"
fi

fi
if secaudit_rule_enabled 185; then
if sec_audit_sshd_effective_dump | grep -i '^ciphers ' >/dev/null &&     ! sec_audit_sshd_effective_dump | grep -i '^ciphers ' | grep -qE 'arcfour|3des|blowfish|cast128|aes128-cbc|aes192-cbc|aes256-cbc'; then
  sec_audit_report_pass 185 "SSH is configured to use only strong ciphers"
else
  sec_audit_report_fail 185 "SSH ciphers are weak or directive is not explicitly configured"
fi

fi
if secaudit_rule_enabled 186; then
if sec_audit_sshd_effective_dump | awk '
  /^clientaliveinterval / {i=$2}
  /^clientalivecountmax / {c=$2}
  END {exit !(i+0>0 && i+0<=900 && c+0>0 && c+0<=3)}
'; then
  sec_audit_report_pass 186 "SSH ClientAliveInterval and ClientAliveCountMax are configured"
else
  sec_audit_report_fail 186 "SSH idle timeout settings are missing or exceed  limits"
fi

fi
if secaudit_rule_enabled 187; then
if sec_audit_sshd_effective_dump | grep -i '^disableforwarding' | grep -qi 'yes'; then
  sec_audit_report_pass 187 "SSH DisableForwarding is enabled"
else
  sec_audit_report_fail 187 "SSH DisableForwarding is not enabled"
fi

fi
if secaudit_rule_enabled 188; then
if sec_audit_sshd_effective_dump | grep -i '^gssapiauthentication' | grep -qi 'no'; then
  sec_audit_report_pass 188 "SSH GSSAPIAuthentication is disabled"
else
  sec_audit_report_fail 188 "SSH GSSAPIAuthentication is enabled"
fi

fi
if secaudit_rule_enabled 189; then
if sec_audit_sshd_effective_dump | grep -i '^hostbasedauthentication' | grep -qi 'no'; then
  sec_audit_report_pass 189 "SSH HostbasedAuthentication is disabled"
else
  sec_audit_report_fail 189 "SSH HostbasedAuthentication is enabled"
fi

fi
if secaudit_rule_enabled 190; then
if sec_audit_sshd_effective_dump | grep -i '^ignorerhosts' | grep -qi 'yes'; then
  sec_audit_report_pass 190 "SSH IgnoreRhosts is enabled"
else
  sec_audit_report_fail 190 "SSH IgnoreRhosts is disabled"
fi

fi
if secaudit_rule_enabled 191; then
if sec_audit_sshd_effective_dump | grep -i '^kexalgorithms ' >/dev/null &&     ! sec_audit_sshd_effective_dump | grep -i '^kexalgorithms ' | grep -qE 'diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1'; then
  sec_audit_report_pass 191 "SSH KexAlgorithms contain only strong algorithms"
else
  sec_audit_report_fail 191 "SSH KexAlgorithms include weak algorithms or directive is not explicitly configured"
fi

fi
if secaudit_rule_enabled 192; then
_kex=$(sec_audit_sshd_t_awk '$1=="kexalgorithms" {print $2; exit}')
_bad=""
printf '%s' "$_kex" | grep -q 'sntrup761x25519-sha512' || _bad+=" sntrup761x25519-sha512"
_ver=$(sshd -V 2>&1 | grep -oiE 'openssh_[0-9]+\.[0-9]+' | head -n1 | sed -E 's/.*_//')
if [ -n "$_ver" ] && awk -v v="$_ver" 'BEGIN{split(v,a,"."); exit !(a[1]>9 || (a[1]==9 && a[2]>=9))}'; then
  printf '%s' "$_kex" | grep -q 'mlkem768x25519-sha256' || _bad+=" mlkem768x25519-sha256"
fi
if [ -z "$_bad" ]; then
  sec_audit_report_pass 192 "post-quantum key exchange algorithms are available in sshd"
else
  sec_audit_report_fail 192 "missing post-quantum kex algorithm(s):${_bad}"
fi

fi
if secaudit_rule_enabled 193; then
if sec_audit_sshd_effective_dump | grep -i '^logingracetime' | awk '{if($2+0>0 && $2+0<=60) exit 0; exit 1}'; then
  sec_audit_report_pass 193 "SSH LoginGraceTime is set to 60 seconds or less"
else
  sec_audit_report_fail 193 "SSH LoginGraceTime is not configured or too long"
fi

fi
if secaudit_rule_enabled 194; then
if sec_audit_sshd_effective_dump | grep -i '^loglevel' | grep -qiE 'VERBOSE|INFO'; then
  sec_audit_report_pass 194 "SSH LogLevel is set to VERBOSE or INFO"
else
  sec_audit_report_fail 194 "SSH LogLevel is not set to VERBOSE or INFO"
fi

fi
if secaudit_rule_enabled 195; then
if sec_audit_sshd_effective_dump | grep -i '^macs ' >/dev/null &&     ! sec_audit_sshd_effective_dump | grep -i '^macs ' | grep -qE 'hmac-md5|hmac-sha1|hmac-ripemd|umac-64@|umac-64-etm@'; then
  sec_audit_report_pass 195 "SSH MACs contain only strong algorithms"
else
  sec_audit_report_fail 195 "SSH MACs include weak algorithms or directive is not explicitly configured"
fi

fi
if secaudit_rule_enabled 196; then
if sec_audit_sshd_effective_dump | grep -i '^maxauthtries' | awk '{if($2+0>0 && $2+0<=4) exit 0; exit 1}'; then
  sec_audit_report_pass 196 "SSH MaxAuthTries is set to 4 or less"
else
  sec_audit_report_fail 196 "SSH MaxAuthTries is not configured or set too high"
fi

fi
if secaudit_rule_enabled 197; then
if sec_audit_sshd_effective_dump | grep -i '^maxsessions' | awk '{print $2}' | awk '{if($1<=10) exit 0; else exit 1}'; then
  sec_audit_report_pass 197 "SSH MaxSessions is set to 10 or less"
else
  sec_audit_report_fail 197 "SSH MaxSessions is not configured or set too high"
fi

fi
if secaudit_rule_enabled 198; then
if sec_audit_sshd_effective_dump | awk '
  /^maxstartups / {
    split($2,a,":");
    found = 1;
    ok = (length(a)==3 && a[1]+0<=10 && a[2]+0<=30 && a[3]+0<=60);
  }
  END {exit !(found && ok)}
'; then
  sec_audit_report_pass 198 "SSH MaxStartups is configured"
else
  sec_audit_report_fail 198 "SSH MaxStartups is missing or too permissive"
fi

fi
if secaudit_rule_enabled 199; then
if sec_audit_sshd_effective_dump | grep -i '^permitemptypasswords' | grep -qi 'no'; then
  sec_audit_report_pass 199 "SSH PermitEmptyPasswords is disabled"
else
  sec_audit_report_fail 199 "SSH PermitEmptyPasswords is enabled"
fi

fi
if secaudit_rule_enabled 200; then
if sec_audit_sshd_effective_dump | grep -i '^permitrootlogin' | grep -qi 'no'; then
  sec_audit_report_pass 200 "SSH PermitRootLogin is disabled"
else
  sec_audit_report_fail 200 "SSH PermitRootLogin is enabled"
fi

fi
if secaudit_rule_enabled 201; then
if sec_audit_sshd_effective_dump | grep -i '^permituserenvironment' | grep -qi 'no'; then
  sec_audit_report_pass 201 "SSH PermitUserEnvironment is disabled"
else
  sec_audit_report_fail 201 "SSH PermitUserEnvironment is enabled"
fi

fi
if secaudit_rule_enabled 202; then
if sec_audit_sshd_effective_dump | grep -i '^usepam' | grep -qi 'yes'; then
  sec_audit_report_pass 202 "SSH UsePAM is enabled"
else
  sec_audit_report_fail 202 "SSH UsePAM is disabled"
fi

fi
if secaudit_rule_enabled 203; then
if dpkg-query -W -f='${Status}' sudo 2>/dev/null | grep -q 'install ok installed'; then
  sec_audit_report_pass 203 "sudo is installed"
else
  sec_audit_report_fail 203 "sudo is not installed"
fi

fi
if secaudit_rule_enabled 204; then
if grep -rqE '^[[:space:]]*Defaults([[:space:]]+[^#]*)?[[:space:]]+use_pty([[:space:]]|$)' /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
  sec_audit_report_pass 204 "sudo is configured to use pty use_pty in Defaults"
else
  sec_audit_report_fail 204 "sudo is not configured to use pty"
fi

fi
if secaudit_rule_enabled 205; then
if grep -rqE '^[[:space:]]*Defaults([[:space:]]+[^#]*)?[[:space:]]+logfile="?/[^",[:space:]]+"?([[:space:]]|$)' /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
  sec_audit_report_pass 205 "sudo log file is configured logfile= in Defaults"
else
  sec_audit_report_fail 205 "sudo log file is not configured"
fi

fi
if secaudit_rule_enabled 206; then
if [ ! -e /etc/sudoers ]; then
  sec_audit_report_pass 206 "sudo is not installed (nothing to verify)"
elif [ ! -r /etc/sudoers ]; then
  sec_audit_report_fail 206 "/etc/sudoers is not readable (run as root)"
else
  _hits=$(grep -rPi -- '^\s*[^#].*\bNOPASSWD\s*:' /etc/sudoers /etc/sudoers.d/ 2>/dev/null)
  if [ -z "$_hits" ]; then
    sec_audit_report_pass 206 "no NOPASSWD entries in sudoers configuration"
  else
    sec_audit_report_fail 206 "NOPASSWD entries found in sudoers configuration"
  fi
fi

fi
if secaudit_rule_enabled 207; then
if [ ! -e /etc/sudoers ]; then
  sec_audit_report_pass 207 "sudo is not installed (nothing to verify)"
elif [ ! -r /etc/sudoers ]; then
  sec_audit_report_fail 207 "/etc/sudoers is not readable (run as root)"
elif ! grep -rqE '^Defaults.*!authenticate' /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
  sec_audit_report_pass 207 "re-authentication is not globally disabled in sudoers"
else
  sec_audit_report_fail 207 "re-authentication is globally disabled in sudoers !authenticate"
fi

fi
if secaudit_rule_enabled 208; then
_v=$(grep -rPhs -- '^\h*Defaults\h+([^#\n\r]+,\h*)?timestamp_timeout\h*=\h*[-0-9]+' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | sed 's/.*=//' | tail -n1)
if [ -z "$_v" ]; then
  sec_audit_report_fail 208 "sudo timestamp_timeout is not explicitly configured"
elif [ "$_v" -lt 0 ] 2>/dev/null || [ "$_v" -gt 15 ] 2>/dev/null; then
  sec_audit_report_fail 208 "sudo timestamp_timeout is ${_v} (must be between 0 and 15)"
else
  sec_audit_report_pass 208 "sudo timestamp_timeout is ${_v}"
fi

fi
if secaudit_rule_enabled 209; then
_line=$(grep -Pi -- '^\s*auth\s+(required|requisite)\s+pam_wheel\.so.*\buse_uid\b.*\bgroup=\S+' /etc/pam.d/su 2>/dev/null | head -n1)
[ -z "$_line" ] && _line=$(grep -Pi -- '^\s*auth\s+(required|requisite)\s+pam_wheel\.so.*\bgroup=\S+.*\buse_uid\b' /etc/pam.d/su 2>/dev/null | head -n1)
if [ -z "$_line" ]; then
  sec_audit_report_fail 209 "pam_wheel.so with use_uid and group= is not configured in /etc/pam.d/su"
else
  _grp=$(printf '%s' "$_line" | sed -n 's/.*group=\([^ ]*\).*/\1/p')
  _mem=$(getent group "$_grp" 2>/dev/null | awk -F: '{print $4}')
  if [ -z "$_mem" ]; then
    sec_audit_report_pass 209 "su is restricted to group ${_grp} which has no members"
  else
    sec_audit_report_fail 209 "group ${_grp} used for su contains members: ${_mem}"
  fi
fi

fi
if secaudit_rule_enabled 210; then
if dpkg-query -W -f='${Status}' libpam-runtime 2>/dev/null | grep -q 'install ok installed'; then
  sec_audit_report_pass 210 "libpam-runtime PAM is installed"
else
  sec_audit_report_fail 210 "libpam-runtime PAM is not installed"
fi

fi
if secaudit_rule_enabled 211; then
if dpkg-query -W -f='${Status}' libpam-modules 2>/dev/null | grep -q 'install ok installed'; then
  sec_audit_report_pass 211 "libpam-modules is installed"
else
  sec_audit_report_fail 211 "libpam-modules is not installed"
fi

fi
if secaudit_rule_enabled 212; then
if dpkg-query -W -f='${Status}' libpam-pwquality 2>/dev/null | grep -q 'install ok installed'; then
  sec_audit_report_pass 212 "libpam-pwquality is installed"
else
  sec_audit_report_fail 212 "libpam-pwquality is not installed"
fi

fi
if secaudit_rule_enabled 213; then
_missing=""
for _p in cracklib-runtime; do
  sec_audit_is_package_installed "$_p" || _missing+=" ${_p}"
done
if [ -z "$_missing" ]; then
  sec_audit_report_pass 213 "package(s) installed: cracklib-runtime"
else
  sec_audit_report_fail 213 "package(s) not installed:${_missing}"
fi

fi
if secaudit_rule_enabled 214; then
if grep -qE 'pam_unix\.so' /etc/pam.d/common-auth 2>/dev/null; then
  sec_audit_report_pass 214 "pam_unix module is present in /etc/pam.d/common-auth"
else
  sec_audit_report_fail 214 "pam_unix module is missing from /etc/pam.d/common-auth"
fi

fi
if secaudit_rule_enabled 215; then
if grep -qE 'pam_faillock\.so' /etc/pam.d/common-auth 2>/dev/null; then
  sec_audit_report_pass 215 "pam_faillock module is present in /etc/pam.d/common-auth"
else
  sec_audit_report_fail 215 "pam_faillock module is missing from /etc/pam.d/common-auth"
fi

fi
if secaudit_rule_enabled 216; then
if grep -qE 'pam_pwquality\.so' /etc/pam.d/common-password 2>/dev/null; then
  sec_audit_report_pass 216 "pam_pwquality module is present in /etc/pam.d/common-password"
else
  sec_audit_report_fail 216 "pam_pwquality module is missing from /etc/pam.d/common-password"
fi

fi
if secaudit_rule_enabled 217; then
if grep -qE 'pam_pwhistory\.so' /etc/pam.d/common-password 2>/dev/null; then
  sec_audit_report_pass 217 "pam_pwhistory module is present in /etc/pam.d/common-password"
else
  sec_audit_report_fail 217 "pam_pwhistory module is missing from /etc/pam.d/common-password"
fi

fi
if secaudit_rule_enabled 218; then
if grep -qE '^deny\s*=' /etc/security/faillock.conf 2>/dev/null && awk -F'[[:space:]]*=[[:space:]]*' '/^deny[[:space:]]*=/{if($2+0>0 && $2+0<=5) exit 0; exit 1}' /etc/security/faillock.conf; then
  sec_audit_report_pass 218 "faillock deny threshold is configured max 5 attempts"
else
  sec_audit_report_fail 218 "faillock deny threshold is not configured or set too high"
fi

fi
if secaudit_rule_enabled 219; then
if grep -qE '^unlock_time\s*=' /etc/security/faillock.conf 2>/dev/null && awk -F'[[:space:]]*=[[:space:]]*' '/^unlock_time[[:space:]]*=/{if($2+0>=900) exit 0; exit 1}' /etc/security/faillock.conf; then
  sec_audit_report_pass 219 "faillock unlock_time is configured minimum 900 seconds"
else
  sec_audit_report_fail 219 "faillock unlock_time is not configured or set too low"
fi

fi
if secaudit_rule_enabled 220; then
if grep -qE '^even_deny_root' /etc/security/faillock.conf 2>/dev/null; then
  sec_audit_report_pass 220 "faillock even_deny_root is enabled"
else
  sec_audit_report_fail 220 "faillock even_deny_root is not enabled"
fi

fi
if secaudit_rule_enabled 221; then
if grep -qE '^difok\s*=' /etc/security/pwquality.conf 2>/dev/null && awk -F= '/^difok/{gsub(/ /,"",$2); if($2+0>=2) exit 0; exit 1}' /etc/security/pwquality.conf; then
  sec_audit_report_pass 221 "pwquality difok is configured minimum 2 changed characters"
else
  sec_audit_report_fail 221 "pwquality difok is not configured or set too low"
fi

fi
if secaudit_rule_enabled 222; then
_m=$(grep -rPhs -- '^\h*minlen\h*=\h*[0-9]+' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null | sed 's/.*=[[:space:]]*//' | tail -n1)
_o=$(grep -Psi -- '^\h*password\h+(requisite|required|sufficient)\h+pam_pwquality\.so\h+([^#\n\r]+\h+)?minlen\h*=\h*([0-9]|1[0-3])\b' /etc/pam.d/common-password 2>/dev/null)
if [ -n "$_o" ]; then
  sec_audit_report_fail 222 "pam_pwquality overrides minlen with a value below 14 in /etc/pam.d/common-password"
elif [ -z "$_m" ]; then
  sec_audit_report_fail 222 "minlen is not configured in the pwquality configuration"
elif [ "$_m" -ge 14 ] 2>/dev/null; then
  sec_audit_report_pass 222 "minimum password length is ${_m}"
else
  sec_audit_report_fail 222 "minimum password length is ${_m}, expected 14 or more"
fi

fi
if secaudit_rule_enabled 223; then
_cfg=$(grep -rPhs -- '^\h*(minclass|[dulo]credit)\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null)
_ok=0
printf '%s' "$_cfg" | grep -Pq '^\s*minclass\s*=\s*[3-9]' && _ok=1
if [ "$_ok" -eq 0 ] && [ -n "$_cfg" ] && ! printf '%s' "$_cfg" | grep -Pq '^\s*[dulo]credit\s*=\s*[1-9]'; then
  _ok=1
fi
if [ "$_ok" -eq 1 ]; then
  sec_audit_report_pass 223 "password complexity requirements are configured"
else
  sec_audit_report_fail 223 "password complexity is not configured (minclass >= 3 or negative credits expected)"
fi

fi
if secaudit_rule_enabled 224; then
if grep -qE '^maxrepeat\s*=' /etc/security/pwquality.conf 2>/dev/null && awk -F= '/^maxrepeat/{gsub(/ /,"",$2); if($2+0>0 && $2+0<=3) exit 0; exit 1}' /etc/security/pwquality.conf; then
  sec_audit_report_pass 224 "pwquality maxrepeat is configured max 3 consecutive identical characters"
else
  sec_audit_report_fail 224 "pwquality maxrepeat is not configured"
fi

fi
if secaudit_rule_enabled 225; then
if grep -qE '^maxsequence\s*=' /etc/security/pwquality.conf 2>/dev/null && awk -F= '/^maxsequence/{gsub(/ /,"",$2); if($2+0>0 && $2+0<=3) exit 0; exit 1}' /etc/security/pwquality.conf; then
  sec_audit_report_pass 225 "pwquality maxsequence is configured max 3 sequential characters"
else
  sec_audit_report_fail 225 "pwquality maxsequence is not configured"
fi

fi
if secaudit_rule_enabled 226; then
if grep -qE '^dictcheck\s*=\s*[^0]' /etc/security/pwquality.conf 2>/dev/null; then
  sec_audit_report_pass 226 "pwquality dictionary check dictcheck is enabled"
else
  sec_audit_report_fail 226 "pwquality dictionary check is disabled"
fi

fi
if secaudit_rule_enabled 227; then
if grep -qE 'pam_pwquality\.so.*enforce_for_root|enforce_for_root' /etc/pam.d/common-password 2>/dev/null || grep -qE '^enforce_for_root' /etc/security/pwquality.conf 2>/dev/null; then
  sec_audit_report_pass 227 "pwquality checking is enforced enforce_for_root or equivalent"
else
  sec_audit_report_fail 227 "pwquality checking is not enforced"
fi

fi
if secaudit_rule_enabled 228; then
if grep -qE '^enforce_for_root' /etc/security/pwquality.conf 2>/dev/null; then
  sec_audit_report_pass 228 "pwquality is enforced for the root user"
else
  sec_audit_report_fail 228 "pwquality is not enforced for the root user"
fi

fi
if secaudit_rule_enabled 229; then
_rem=$(grep -hoE 'remember=[0-9]+' /etc/pam.d/common-password 2>/dev/null | sed 's/.*=//' | sort -n | tail -n1)
[ -z "$_rem" ] && _rem=$(awk -F= '/^[[:space:]]*remember[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); v=$2} END{print v}' /etc/security/pwhistory.conf 2>/dev/null)
if [ -n "$_rem" ] && [ "$_rem" -ge 24 ] 2>/dev/null; then
  sec_audit_report_pass 229 "password history remember is ${_rem} (24 or more)"
else
  sec_audit_report_fail 229 "password history remember is '${_rem:-<unset>}', expected 24 or more"
fi

fi
if secaudit_rule_enabled 230; then
if grep -qE '^enforce_for_root' /etc/security/pwhistory.conf 2>/dev/null; then
  sec_audit_report_pass 230 "pwhistory enforce_for_root is enabled"
else
  sec_audit_report_fail 230 "pwhistory enforce_for_root is not enabled"
fi

fi
if secaudit_rule_enabled 231; then
if grep -qE 'pam_pwhistory\.so.*use_authtok' /etc/pam.d/common-password 2>/dev/null; then
  sec_audit_report_pass 231 "pam_pwhistory includes use_authtok"
else
  sec_audit_report_fail 231 "pam_pwhistory is missing use_authtok"
fi

fi
if secaudit_rule_enabled 232; then
if ! grep -qE 'pam_unix\.so.*nullok' /etc/pam.d/common-auth /etc/pam.d/common-account /etc/pam.d/common-password /etc/pam.d/common-session 2>/dev/null; then
  sec_audit_report_pass 232 "pam_unix does not include nullok parameter"
else
  sec_audit_report_fail 232 "pam_unix includes nullok parameter empty passwords permitted"
fi

fi
if secaudit_rule_enabled 233; then
if ! grep -qE 'pam_unix\.so.*remember' /etc/pam.d/common-password 2>/dev/null; then
  sec_audit_report_pass 233 "pam_unix does not include remember parameter"
else
  sec_audit_report_fail 233 "pam_unix includes remember parameter deprecated"
fi

fi
if secaudit_rule_enabled 234; then
if grep -qE 'pam_unix\.so.*(sha512|yescrypt|bcrypt)' /etc/pam.d/common-password 2>/dev/null; then
  sec_audit_report_pass 234 "pam_unix uses a strong hashing algorithm yescrypt/sha512/bcrypt"
else
  sec_audit_report_fail 234 "pam_unix is not configured to use a strong hashing algorithm"
fi

fi
if secaudit_rule_enabled 235; then
if grep -qE 'pam_unix\.so.*use_authtok' /etc/pam.d/common-password 2>/dev/null; then
  sec_audit_report_pass 235 "pam_unix includes use_authtok"
else
  sec_audit_report_fail 235 "pam_unix is missing use_authtok"
fi

fi
if secaudit_rule_enabled 236; then
if awk '($1=="PASS_MAX_DAYS"){if($2+0<=365 && $2+0>0) exit 0; exit 1}' /etc/login.defs 2>/dev/null; then
  sec_audit_report_pass 236 "PASS_MAX_DAYS is set to 365 or less in /etc/login.defs"
else
  sec_audit_report_fail 236 "PASS_MAX_DAYS is not configured or exceeds 365 days"
fi

fi
if secaudit_rule_enabled 237; then
if [ ! -e /etc/shadow ]; then
  sec_audit_report_fail 237 "/etc/shadow is missing"
elif [ ! -r /etc/shadow ]; then
  sec_audit_report_fail 237 "/etc/shadow is not readable (run as root)"
  _d=""
else
  _d=$(awk '/^[[:space:]]*PASS_MIN_DAYS[[:space:]]+[0-9]+/ {print $2}' /etc/login.defs 2>/dev/null | tail -n1)
  _bad=$(awk -F: '($2 ~ /^\$.+\$/) {if ($4 < 1) print $1}' /etc/shadow 2>/dev/null | tr '\n' ' ')
  if [ -n "$_d" ] && [ "$_d" -ge 1 ] 2>/dev/null && [ -z "$_bad" ]; then
    sec_audit_report_pass 237 "PASS_MIN_DAYS=${_d} and all password users comply"
  else
    sec_audit_report_fail 237 "PASS_MIN_DAYS='${_d:-unset}' or users with less than 1 day: ${_bad:-none}"
  fi
fi

fi
if secaudit_rule_enabled 238; then
if awk '($1=="PASS_WARN_AGE"){if($2+0>=7) exit 0; exit 1}' /etc/login.defs 2>/dev/null; then
  sec_audit_report_pass 238 "PASS_WARN_AGE is set to 7 or more days in /etc/login.defs"
else
  sec_audit_report_fail 238 "PASS_WARN_AGE is not configured or set below 7 days"
fi

fi
if secaudit_rule_enabled 239; then
if grep -qiE '^ENCRYPT_METHOD\s+(SHA512|yescrypt)' /etc/login.defs 2>/dev/null; then
  sec_audit_report_pass 239 "ENCRYPT_METHOD is SHA512 or yescrypt in /etc/login.defs"
else
  sec_audit_report_fail 239 "ENCRYPT_METHOD is not set to a strong algorithm"
fi

fi
if secaudit_rule_enabled 240; then
if useradd -D 2>/dev/null | grep -qE '^INACTIVE=[0-9]' && useradd -D 2>/dev/null | awk -F= '/INACTIVE/{if($2+0>0 && $2+0<=30) exit 0; exit 1}'; then
  sec_audit_report_pass 240 "INACTIVE password lock period is configured 1-30 days"
else
  sec_audit_report_fail 240 "INACTIVE password lock period is not configured or out of range"
fi

fi
if secaudit_rule_enabled 241; then
if [ ! -e /etc/shadow ]; then
  sec_audit_report_fail 241 "/etc/shadow is missing"
elif [ ! -r /etc/shadow ]; then
  sec_audit_report_fail 241 "/etc/shadow is not readable (run as root)"
elif [ "$(awk -F: '($2~/^\$/ && $3!~/^!/ && $3+0>0){today=int(systime()/86400); if($3+0>today) print $1}' /etc/shadow 2>/dev/null | wc -l)" -eq 0 ]; then
  sec_audit_report_pass 241 "all user password change dates are in the past"
else
  sec_audit_report_fail 241 "one or more users have a future password change date"
fi

fi
if secaudit_rule_enabled 242; then
if [ $(awk -F: '($3==0){print $1}' /etc/passwd | wc -l) -eq 1 ] && awk -F: '($3==0){print $1}' /etc/passwd | grep -q '^root$'; then
  sec_audit_report_pass 242 "root is the only account with UID 0"
else
  sec_audit_report_fail 242 "one or more non-root accounts have UID 0"
fi

fi
if secaudit_rule_enabled 243; then
if [ $(awk -F: '($4==0){print $1}' /etc/passwd | grep -v '^root$' | wc -l) -eq 0 ]; then
  sec_audit_report_pass 243 "only root has GID 0 as primary group"
else
  sec_audit_report_fail 243 "one or more non-root users have GID 0 as primary group"
fi

fi
if secaudit_rule_enabled 244; then
if [ $(awk -F: '($3==0){print $1}' /etc/group | wc -l) -eq 1 ] && awk -F: '($3==0){print $1}' /etc/group | grep -q '^root$'; then
  sec_audit_report_pass 244 "root is the only group with GID 0"
else
  sec_audit_report_fail 244 "one or more non-root groups have GID 0"
fi

fi
if secaudit_rule_enabled 245; then
if passwd -S root 2>/dev/null | grep -qE '^root (L|LK) '; then
  sec_audit_report_pass 245 "root account is locked no direct password login"
else
  sec_audit_report_fail 245 "root account is not locked"
fi

fi
if secaudit_rule_enabled 246; then
if ! echo "$PATH" | grep -qE '(^|:)(\.|:|$)' && ! find -L $(echo "$PATH" | tr ':' ' ') -maxdepth 0 \( -perm -o+w -o ! -user root \) 2>/dev/null | grep -q .; then
  sec_audit_report_pass 246 "root PATH does not contain dot or world-writable directories"
else
  sec_audit_report_fail 246 "root PATH contains dot or world-writable directories"
fi

fi
if secaudit_rule_enabled 247; then
if grep -qE '^\s*umask\s+0[027]7' /root/.bash_profile /root/.bashrc /root/.profile 2>/dev/null; then
  sec_audit_report_pass 247 "root umask is set to 027 or stricter"
else
  sec_audit_report_fail 247 "root umask is not configured or too permissive"
fi

fi
if secaudit_rule_enabled 248; then
if ! awk -F: '($1!~/^(root|sync|shutdown|halt|nfsnobody)$/ && $3<1000 && $7!~/(\/sbin\/nologin|\/bin\/false)$/){print $1}' /etc/passwd 2>/dev/null | grep -q .; then
  sec_audit_report_pass 248 "all system accounts UID < 1000 have nologin or false as shell"
else
  sec_audit_report_fail 248 "one or more system accounts have a valid interactive shell"
fi

fi
if secaudit_rule_enabled 249; then
_req207_fail=$(awk -F: '($7~/\/sbin\/nologin|\/bin\/false/){print $1}' /etc/passwd 2>/dev/null | while read u; do passwd -S "$u" 2>/dev/null | grep -qE '^'"$u"' (L|LK) ' || echo "UNLOCKED"; done | grep -c 'UNLOCKED' 2>/dev/null)
if [ "${_req207_fail:-0}" -eq 0 ]; then
  sec_audit_report_pass 249 "all accounts with nologin/false shell are locked"
else
  sec_audit_report_fail 249 "one or more nologin/false-shell accounts are not locked"
fi

fi
if secaudit_rule_enabled 250; then
if ! grep -q 'nologin' /etc/shells 2>/dev/null; then
  sec_audit_report_pass 250 "nologin is not listed in /etc/shells"
else
  sec_audit_report_fail 250 "nologin is listed in /etc/shells"
fi

fi
if secaudit_rule_enabled 251; then
_tm=$(grep -rhoE '\bTMOUT=[0-9]+' /etc/profile /etc/profile.d/*.sh /etc/bash.bashrc 2>/dev/null | sed 's/.*=//' | sort -n | tail -n1)
if [ -n "$_tm" ] && [ "$_tm" -le 900 ] 2>/dev/null && grep -rqE 'readonly TMOUT|export TMOUT' /etc/profile /etc/profile.d/*.sh /etc/bash.bashrc 2>/dev/null; then
  sec_audit_report_pass 251 "TMOUT shell timeout is ${_tm} seconds (900 or less) and exported/readonly"
else
  sec_audit_report_fail 251 "TMOUT shell timeout is '${_tm:-<unset>}', expected 1-900 and exported/readonly"
fi

fi
if secaudit_rule_enabled 252; then
if grep -rqE '^\s*umask\s+(0[027]7|[027]7)' /etc/profile /etc/profile.d/*.sh /etc/bash.bashrc /etc/login.defs 2>/dev/null; then
  sec_audit_report_pass 252 "default umask is set to 027 or stricter in system profiles"
else
  sec_audit_report_fail 252 "default umask is not configured or too permissive"
fi

fi
}

sec_audit_run_system_maintenance() {
if secaudit_rule_enabled 253; then
if systemctl is-active systemd-journald 2>/dev/null | grep -q '^active' && systemctl is-enabled systemd-journald 2>/dev/null | grep -qE '^(enabled|static)'; then
  sec_audit_report_pass 253 "systemd-journald is enabled and running"
else
  sec_audit_report_fail 253 "systemd-journald is not enabled or not running"
fi

fi
if secaudit_rule_enabled 254; then
_jr_active=0
_jr_enabled=0
systemctl is-active systemd-journal-remote.service systemd-journal-remote.socket 2>/dev/null | grep -qE '^active$' && _jr_active=1
systemctl is-enabled systemd-journal-remote.service systemd-journal-remote.socket 2>/dev/null | grep -qE '^(enabled|enabled-runtime)$' && _jr_enabled=1
if [ "$_jr_active" -eq 0 ] && [ "$_jr_enabled" -eq 0 ]; then
  sec_audit_report_pass 254 "systemd-journal-remote service and socket are not active and not enabled"
else
  sec_audit_report_fail 254 "systemd-journal-remote service or socket is active or enabled unexpectedly"
fi

fi
if secaudit_rule_enabled 255; then
if sec_audit_is_service_active rsyslog &&     (grep -qE '^[[:space:]]*ForwardToSyslog[[:space:]]*=[[:space:]]*yes[[:space:]]*$' /etc/systemd/journald.conf 2>/dev/null ||      grep -rqE '^[[:space:]]*ForwardToSyslog[[:space:]]*=[[:space:]]*yes[[:space:]]*$' /etc/systemd/journald.conf.d/ 2>/dev/null); then
  sec_audit_report_pass 255 "journald ForwardToSyslog is set to yes forwarding to rsyslog"
else
  sec_audit_report_fail 255 "journald ForwardToSyslog is not set to yes"
fi

fi
if secaudit_rule_enabled 256; then
_bad=""
while IFS= read -r _f; do
  [ -e "$_f" ] || continue
  sec_audit__path_access_ok "$_f" 640 root root || _bad+=" $(sec_audit__path_access_describe "$_f")"
done < <(grep -rhs -- '^[[:space:]]*f[[:space:]]' /etc/tmpfiles.d/systemd.conf /usr/lib/tmpfiles.d/systemd.conf 2>/dev/null | awk '{print $2}' | grep -E '/var/log/journal')
if [ -z "$_bad" ]; then
  sec_audit_report_pass 256 "journald log files are 0640 or more restrictive"
else
  sec_audit_report_fail 256 "journald log files with insufficient access restrictions:${_bad}"
fi

fi
if secaudit_rule_enabled 257; then
_c=$(grep -rPhs -- '^\s*(SystemMaxUse|SystemKeepFree|RuntimeMaxUse|RuntimeKeepFree|MaxFileSec)\s*=\s*\S+' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/ 2>/dev/null | head -n1)
if [ -n "$_c" ]; then
  sec_audit_report_pass 257 "journald rotation parameter is configured: $(sec_audit__sanitize "$(printf '%s' "$_c" | sed 's/^[[:space:]]*//')")"
else
  sec_audit_report_fail 257 "no journald rotation parameters (SystemMaxUse/SystemKeepFree/RuntimeMaxUse/RuntimeKeepFree/MaxFileSec) are configured"
fi

fi
if secaudit_rule_enabled 258; then
if grep -qE '^Storage=persistent' /etc/systemd/journald.conf 2>/dev/null || grep -rqE '^Storage=persistent' /etc/systemd/journald.conf.d/ 2>/dev/null; then
  sec_audit_report_pass 258 "journald Storage is set to persistent"
else
  sec_audit_report_fail 258 "journald Storage is not set to persistent"
fi

fi
if secaudit_rule_enabled 259; then
if grep -qE '^Compress=yes' /etc/systemd/journald.conf 2>/dev/null || grep -rqE '^Compress=yes' /etc/systemd/journald.conf.d/ 2>/dev/null; then
  sec_audit_report_pass 259 "journald Compress is set to yes"
else
  sec_audit_report_fail 259 "journald Compress is not set to yes"
fi

fi
if secaudit_rule_enabled 260; then
if dpkg-query -W -f='${Status}' rsyslog 2>/dev/null | grep -q 'install ok installed'; then
  sec_audit_report_pass 260 "rsyslog is installed"
else
  sec_audit_report_fail 260 "rsyslog is not installed"
fi

fi
if secaudit_rule_enabled 261; then
if systemctl is-active rsyslog 2>/dev/null | grep -q '^active' && systemctl is-enabled rsyslog 2>/dev/null | grep -q '^enabled'; then
  sec_audit_report_pass 261 "rsyslog service is enabled and running"
else
  sec_audit_report_fail 261 "rsyslog service is not enabled or not running"
fi

fi
if secaudit_rule_enabled 262; then
if grep -qE '^\$FileCreateMode 06[04]0' /etc/rsyslog.conf 2>/dev/null || grep -rqE '^\$FileCreateMode 06[04]0' /etc/rsyslog.d/ 2>/dev/null; then
  sec_audit_report_pass 262 "rsyslog FileCreateMode is set to 0640 or stricter"
else
  sec_audit_report_fail 262 "rsyslog FileCreateMode is not configured or too permissive"
fi

fi
if secaudit_rule_enabled 263; then
_c=$(grep -rhsE -- '^[[:space:]]*[^#$[:space:]][^[:space:]]*\.[^[:space:]]*[[:space:]]+(-?/|@@?|action\()' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | head -n1)
if [ -n "$_c" ]; then
  sec_audit_report_pass 263 "rsyslog has logging rules: $(sec_audit__sanitize "$(printf '%s' "$_c" | sed 's/^[[:space:]]*//')")"
else
  sec_audit_report_fail 263 "rsyslog has no logging rules (no selector with a file/remote/action destination)"
fi

fi
if secaudit_rule_enabled 264; then
if grep -rPsi -- '^\h*\*\.\*\h+@{1,2}\H+' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -q .     || grep -rPsz -- 'action\(([^#]*\s+)?\btarget=' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -q .; then
  sec_audit_report_pass 264 "rsyslog forwards logs to a remote log host"
else
  sec_audit_report_fail 264 "rsyslog is not configured to send logs to a remote log host"
fi

fi
if secaudit_rule_enabled 265; then
if ! grep -qE '^(module|input).*imtcp|^(module|input).*imudp' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null; then
  sec_audit_report_pass 265 "rsyslog is not configured to receive logs from remote clients"
else
  sec_audit_report_fail 265 "rsyslog is configured to receive remote logs imtcp/imudp active"
fi

fi
if secaudit_rule_enabled 266; then
if [ ! -f /etc/logrotate.conf ]; then
  sec_audit_report_fail 266 "/etc/logrotate.conf is missing"
elif grep -qE '^[[:space:]]*include[[:space:]]+/etc/logrotate\.d' /etc/logrotate.conf 2>/dev/null; then
  _n=$(ls /etc/logrotate.d/ 2>/dev/null | wc -l)
  sec_audit_report_pass 266 "/etc/logrotate.conf includes /etc/logrotate.d (drop-ins: ${_n})"
else
  sec_audit_report_fail 266 "/etc/logrotate.conf does not include /etc/logrotate.d drop-ins"
fi

fi
if secaudit_rule_enabled 267; then
_missing=""
for _p in rsyslog-gnutls; do
  sec_audit_is_package_installed "$_p" || _missing+=" ${_p}"
done
if [ -z "$_missing" ]; then
  sec_audit_report_pass 267 "package(s) installed: rsyslog-gnutls"
else
  sec_audit_report_fail 267 "package(s) not installed:${_missing}"
fi

fi
if secaudit_rule_enabled 268; then
if grep -rPsi -- '^[^#]*StreamDriver\s*=\s*"?gtls"?' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -q .; then
  sec_audit_report_pass 268 "rsyslog forwarding uses the gtls stream driver"
else
  sec_audit_report_fail 268 "rsyslog forwarding does not use gtls"
fi

fi
if secaudit_rule_enabled 269; then
_found=$(grep -rPhso -- '(DefaultNetstreamDriverCAFile|StreamDriver\.CAFile)\s*=\s*"?[^"]+"?' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | head -n1)
if [ -z "$_found" ]; then
  sec_audit_report_fail 269 "rsyslog CA certificate is not configured"
else
  _path=$(printf '%s' "$_found" | sed 's/.*=[[:space:]]*//' | tr -d '"')
  if [ -r "$_path" ]; then
    sec_audit_report_pass 269 "rsyslog CA certificate is configured (${_path})"
  else
    sec_audit_report_fail 269 "rsyslog CA certificate ${_path} is not readable"
  fi
fi

fi
if secaudit_rule_enabled 270; then
_f_out=$(sec_audit_low_impact_find --timeout=60 /var/log -type f -perm /037 \
           ! \( -path /var/log/wtmp -o -path /var/log/btmp -o -path /var/log/lastlog \) 2>/dev/null)
_f_rc=$?
_d_out=$(sec_audit_low_impact_find --timeout=60 /var/log -type d -perm /026 2>/dev/null)
_d_rc=$?
if [ "$_f_rc" -ne 0 ] || [ "$_d_rc" -ne 0 ]; then
  sec_audit_report_fail 270 "/var/log could not be scanned completely (permission denied or timeout), result unknown"
elif [ -n "$_f_out$_d_out" ]; then
  sec_audit_report_fail 270 "one or more log files have overly permissive access: $(sec_audit__sanitize "$(printf '%s %s' "$_f_out" "$_d_out" | tr '\n' ' ' | cut -c1-300)")"
else
  sec_audit_report_pass 270 "all files in /var/log have restricted permissions"
fi

fi
if secaudit_rule_enabled 271; then
if sec_audit_is_package_installed auditd; then
  sec_audit_report_pass 271 "auditd package is installed"
else
  sec_audit_report_fail 271 "auditd package is not installed"
fi

fi
if secaudit_rule_enabled 272; then
if systemctl is-active auditd 2>/dev/null | grep -q '^active' && systemctl is-enabled auditd 2>/dev/null | grep -q '^enabled'; then
  sec_audit_report_pass 272 "auditd service is enabled and running"
else
  sec_audit_report_fail 272 "auditd service is not enabled or not running"
fi

fi
if secaudit_rule_enabled 273; then
if grep -qE 'audit=1' /proc/cmdline; then
  sec_audit_report_pass 273 "audit=1 is present in kernel boot parameters"
else
  sec_audit_report_fail 273 "audit=1 is missing from kernel boot parameters"
fi

fi
if secaudit_rule_enabled 274; then
_missing=0
if [ -r /proc/cmdline ]; then
  grep -q 'audit_backlog_limit=[0-9]\+' /proc/cmdline || _missing=1
fi
if sec_audit_have_bin find; then
  _f=$(find /boot -type f -name 'grub.cfg' 2>/dev/null | head -n1)
  if [ -n "$_f" ]; then
    grep -Ph -- '^\h*linux' "$_f" 2>/dev/null | grep -Pv 'audit_backlog_limit=\d+\b' | grep -q . && _missing=1
  fi
fi
if [ "$_missing" -eq 0 ]; then
  sec_audit_report_pass 274 "audit_backlog_limit is configured on the kernel command line"
else
  sec_audit_report_fail 274 "audit_backlog_limit is missing from the kernel command line"
fi

fi
if secaudit_rule_enabled 275; then
if grep -qE '^max_log_file\s*=\s*[0-9]+' /etc/audit/auditd.conf 2>/dev/null; then
  sec_audit_report_pass 275 "auditd max_log_file size is configured"
else
  sec_audit_report_fail 275 "auditd max_log_file is not configured"
fi

fi
if secaudit_rule_enabled 276; then
if grep -qE '^max_log_file_action\s*=\s*keep_logs' /etc/audit/auditd.conf 2>/dev/null; then
  sec_audit_report_pass 276 "auditd max_log_file_action is set to keep_logs"
else
  sec_audit_report_fail 276 "auditd max_log_file_action is not set to keep_logs"
fi

fi
if secaudit_rule_enabled 277; then
if grep -qE '^space_left_action\s*=\s*(email|exec|single|halt)' /etc/audit/auditd.conf 2>/dev/null && grep -qE '^admin_space_left_action\s*=\s*(single|halt)' /etc/audit/auditd.conf 2>/dev/null; then
  sec_audit_report_pass 277 "auditd is configured to halt or notify when disk is full"
else
  sec_audit_report_fail 277 "auditd is not configured to halt or notify when disk is full"
fi

fi
if secaudit_rule_enabled 278; then
if grep -qE '^space_left\s*=\s*[0-9]+' /etc/audit/auditd.conf 2>/dev/null && grep -qE '^space_left_action\s*=\s*email' /etc/audit/auditd.conf 2>/dev/null; then
  sec_audit_report_pass 278 "auditd space_left_action is set to email"
else
  sec_audit_report_fail 278 "auditd space_left_action is not configured"
fi

fi
if secaudit_rule_enabled 279; then
_ok=1
sec_audit_audit_rule_on_disk -E -- '-a always,exit -F path=/etc/sudoers -F perm=wa' || _ok=0
sec_audit_audit_rule_on_disk -E -- '-a always,exit -F dir=/etc/sudoers\.d -F perm=wa' || _ok=0
if sec_audit_have_bin auditctl; then
  sec_audit_auditctl_rules_grep -q -E -- '-a always,exit -F path=/etc/sudoers -F perm=wa' || _ok=0
  sec_audit_auditctl_rules_grep -q -E -- '-a always,exit -F dir=/etc/sudoers\.d -F perm=wa' || _ok=0
fi
if [ "$_ok" -eq 1 ]; then
  sec_audit_report_pass 279 "changes to /etc/sudoers are collected"
else
  sec_audit_report_fail 279 "changes to /etc/sudoers are collected - audit rule missing or not loaded"
fi

fi
if secaudit_rule_enabled 280; then
if sec_audit_audit_rule_on_disk_all -a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve; then
  sec_audit_report_pass 280 "audit rules collect execve calls with UID change user emulation"
else
  sec_audit_report_fail 280 "audit rules for actions as another user are missing"
fi

fi
if secaudit_rule_enabled 281; then
if sec_audit_audit_rules_files_grep -q -E -- -w.*sudo.log; then
  sec_audit_report_pass 281 "audit rules monitor modifications to the sudo log file"
else
  sec_audit_report_fail 281 "audit rules for sudo log file modifications are missing"
fi

fi
if secaudit_rule_enabled 282; then
if sec_audit_audit_rule_on_disk_all -a always,exit -F arch=b64 -S adjtimex; then
  sec_audit_report_pass 282 "audit rules collect date and time modification syscalls"
else
  sec_audit_report_fail 282 "audit rules for date/time modification are missing"
fi

fi
if secaudit_rule_enabled 283; then
_ok=1
sec_audit_audit_rule_on_disk -E -- '-a always,exit .*-S sethostname,setdomainname' || _ok=0
if sec_audit_have_bin auditctl; then
  sec_audit_auditctl_rules_grep -q -E -- '-a always,exit .*-S sethostname,setdomainname' || _ok=0
fi
if [ "$_ok" -eq 1 ]; then
  sec_audit_report_pass 283 "sethostname and setdomainname calls are collected"
else
  sec_audit_report_fail 283 "sethostname and setdomainname calls are collected - audit rule missing or not loaded"
fi

fi
if secaudit_rule_enabled 284; then
_ok=1
sec_audit_audit_rule_on_disk -E -- '-a always,exit -F path=/etc/issue -F perm=wa' || _ok=0
sec_audit_audit_rule_on_disk -E -- '-a always,exit -F path=/etc/issue\.net -F perm=wa' || _ok=0
if sec_audit_have_bin auditctl; then
  sec_audit_auditctl_rules_grep -q -E -- '-a always,exit -F path=/etc/issue -F perm=wa' || _ok=0
  sec_audit_auditctl_rules_grep -q -E -- '-a always,exit -F path=/etc/issue\.net -F perm=wa' || _ok=0
fi
if [ "$_ok" -eq 1 ]; then
  sec_audit_report_pass 284 "changes to /etc/issue and /etc/issue.net are collected"
else
  sec_audit_report_fail 284 "changes to /etc/issue and /etc/issue.net are collected - audit rule missing or not loaded"
fi

fi
if secaudit_rule_enabled 285; then
_ok=1
sec_audit_audit_rule_on_disk -E -- '-a always,exit -F path=/etc/hosts -F perm=wa' || _ok=0
sec_audit_audit_rule_on_disk -E -- '-a always,exit -F path=/etc/hostname -F perm=wa' || _ok=0
if sec_audit_have_bin auditctl; then
  sec_audit_auditctl_rules_grep -q -E -- '-a always,exit -F path=/etc/hosts -F perm=wa' || _ok=0
  sec_audit_auditctl_rules_grep -q -E -- '-a always,exit -F path=/etc/hostname -F perm=wa' || _ok=0
fi
if [ "$_ok" -eq 1 ]; then
  sec_audit_report_pass 285 "changes to /etc/hosts and /etc/hostname are collected"
else
  sec_audit_report_fail 285 "changes to /etc/hosts and /etc/hostname are collected - audit rule missing or not loaded"
fi

fi
if secaudit_rule_enabled 286; then
_ok=1
sec_audit_audit_rule_on_disk -E -- '-a always,exit -F path=/etc/network/interfaces -F perm=wa' || _ok=0
sec_audit_audit_rule_on_disk -E -- '-a always,exit -F dir=/etc/network/interfaces\.d -F perm=wa' || _ok=0
sec_audit_audit_rule_on_disk -E -- '-a always,exit -F dir=/etc/netplan/ -F perm=wa' || _ok=0
if sec_audit_have_bin auditctl; then
  sec_audit_auditctl_rules_grep -q -E -- '-a always,exit -F path=/etc/network/interfaces -F perm=wa' || _ok=0
  sec_audit_auditctl_rules_grep -q -E -- '-a always,exit -F dir=/etc/network/interfaces\.d -F perm=wa' || _ok=0
  sec_audit_auditctl_rules_grep -q -E -- '-a always,exit -F dir=/etc/netplan/ -F perm=wa' || _ok=0
fi
if [ "$_ok" -eq 1 ]; then
  sec_audit_report_pass 286 "changes to the network environment are collected"
else
  sec_audit_report_fail 286 "changes to the network environment are collected - audit rule missing or not loaded"
fi

fi
if secaudit_rule_enabled 287; then
_ok=1
sec_audit_audit_rule_on_disk -E -- '-a always,exit -F dir=/etc/NetworkManager/ -F perm=wa' || _ok=0
if sec_audit_have_bin auditctl; then
  sec_audit_auditctl_rules_grep -q -E -- '-a always,exit -F dir=/etc/NetworkManager/ -F perm=wa' || _ok=0
fi
if [ "$_ok" -eq 1 ]; then
  sec_audit_report_pass 287 "changes to /etc/NetworkManager are collected"
else
  sec_audit_report_fail 287 "changes to /etc/NetworkManager are collected - audit rule missing or not loaded"
fi
fi

_SUID_DONE=0
_SUID_CACHE=""
_SUID_RC=0

if secaudit_rule_enabled 288; then
sec_audit__suid_sgid_scan
_suid_rc=$?
_suid_list=$_SUID_CACHE
_suid_trunc=0
case "$_suid_list" in
  *" (list limited to "*) _suid_trunc=1; _suid_list="${_suid_list%% (list limited to *}" ;;
esac
if [ "$_suid_rc" -eq 3 ]; then
  sec_audit_report_fail 288 "privileged commands could not be enumerated (filesystem scan incomplete)"
elif [ "$_suid_rc" -eq 2 ] || [ "$_suid_trunc" -eq 1 ]; then
  sec_audit_report_fail 288 "privileged commands could not be enumerated (scan unavailable or truncated)"
elif [ -z "$_suid_list" ]; then
  sec_audit_report_pass 288 "no setuid/setgid commands found to cover"
else
  _cov=$(sec_audit__audit_privileged_paths)
  _cov_loaded=""
  _need_loaded=0
  if sec_audit_have_bin auditctl; then
    _need_loaded=1
    _cov_loaded=$(sec_audit__audit_privileged_paths_loaded)
  fi
  _missing=""
  _count=0
  for _b in $_suid_list; do
    _count=$((_count + 1))
    if ! builtin printf '%s\n' "$_cov" | grep -qxF -- "$_b"; then
      _missing+=" $_b(disk)"
    elif [ "$_need_loaded" -eq 1 ] && ! builtin printf '%s\n' "$_cov_loaded" | grep -qxF -- "$_b"; then
      _missing+=" $_b(not loaded)"
    fi
  done
  if [ -z "$_missing" ]; then
    sec_audit_report_pass 288 "audit rules cover all ${_count} setuid/setgid commands (on disk and loaded)"
  else
    sec_audit_report_fail 288 "audit rules for privileged commands are incomplete (first uncovered):$(printf '%s' "$_missing" | tr ' ' '\n' | head -n 5 | tr '\n' ' ')"
  fi
fi

fi
if secaudit_rule_enabled 289; then
if sec_audit_audit_rule_on_disk_all -a always,exit -F arch=b64 open exit=-EACCES || sec_audit_audit_rule_on_disk_all -a always,exit -F arch=b64 open exit=-EPERM; then
  sec_audit_report_pass 289 "audit rules collect failed file access attempts EACCES/EPERM"
else
  sec_audit_report_fail 289 "audit rules for failed file access attempts are missing"
fi

fi
if secaudit_rule_enabled 290; then
_ok=1
sec_audit_audit_rule_on_disk -E -- '-a always,exit -F path=/etc/group -F perm=wa' || _ok=0
if sec_audit_have_bin auditctl; then
  sec_audit_auditctl_rules_grep -q -E -- '-a always,exit -F path=/etc/group -F perm=wa' || _ok=0
fi
if [ "$_ok" -eq 1 ]; then
  sec_audit_report_pass 290 "changes to /etc/group information are collected"
else
  sec_audit_report_fail 290 "changes to /etc/group information are collected - audit rule missing or not loaded"
fi

fi
if secaudit_rule_enabled 291; then
_ok=1
sec_audit_audit_rule_on_disk -E -- '-a always,exit -F path=/etc/passwd -F perm=wa' || _ok=0
if sec_audit_have_bin auditctl; then
  sec_audit_auditctl_rules_grep -q -E -- '-a always,exit -F path=/etc/passwd -F perm=wa' || _ok=0
fi
if [ "$_ok" -eq 1 ]; then
  sec_audit_report_pass 291 "changes to /etc/passwd information are collected"
else
  sec_audit_report_fail 291 "changes to /etc/passwd information are collected - audit rule missing or not loaded"
fi

fi
if secaudit_rule_enabled 292; then
_ok=1
sec_audit_audit_rule_on_disk -E -- '-a always,exit -F path=/etc/shadow -F perm=wa' || _ok=0
sec_audit_audit_rule_on_disk -E -- '-a always,exit -F path=/etc/gshadow -F perm=wa' || _ok=0
if sec_audit_have_bin auditctl; then
  sec_audit_auditctl_rules_grep -q -E -- '-a always,exit -F path=/etc/shadow -F perm=wa' || _ok=0
  sec_audit_auditctl_rules_grep -q -E -- '-a always,exit -F path=/etc/gshadow -F perm=wa' || _ok=0
fi
if [ "$_ok" -eq 1 ]; then
  sec_audit_report_pass 292 "changes to /etc/shadow and /etc/gshadow are collected"
else
  sec_audit_report_fail 292 "changes to /etc/shadow and /etc/gshadow are collected - audit rule missing or not loaded"
fi

fi
if secaudit_rule_enabled 293; then
_ok=1
sec_audit_audit_rule_on_disk -E -- '-a always,exit -F path=/etc/security/opasswd -F perm=wa' || _ok=0
if sec_audit_have_bin auditctl; then
  sec_audit_auditctl_rules_grep -q -E -- '-a always,exit -F path=/etc/security/opasswd -F perm=wa' || _ok=0
fi
if [ "$_ok" -eq 1 ]; then
  sec_audit_report_pass 293 "changes to /etc/security/opasswd are collected"
else
  sec_audit_report_fail 293 "changes to /etc/security/opasswd are collected - audit rule missing or not loaded"
fi

fi
if secaudit_rule_enabled 294; then
_ok=1
sec_audit_audit_rule_on_disk -E -- '-a always,exit -F path=/etc/nsswitch\.conf -F perm=wa' || _ok=0
if sec_audit_have_bin auditctl; then
  sec_audit_auditctl_rules_grep -q -E -- '-a always,exit -F path=/etc/nsswitch\.conf -F perm=wa' || _ok=0
fi
if [ "$_ok" -eq 1 ]; then
  sec_audit_report_pass 294 "changes to /etc/nsswitch.conf are collected"
else
  sec_audit_report_fail 294 "changes to /etc/nsswitch.conf are collected - audit rule missing or not loaded"
fi

fi
if secaudit_rule_enabled 295; then
_ok=1
sec_audit_audit_rule_on_disk -E -- '-a always,exit -F path=/etc/pam\.conf -F perm=wa' || _ok=0
sec_audit_audit_rule_on_disk -E -- '-a always,exit -F dir=/etc/pam\.d -F perm=wa' || _ok=0
if sec_audit_have_bin auditctl; then
  sec_audit_auditctl_rules_grep -q -E -- '-a always,exit -F path=/etc/pam\.conf -F perm=wa' || _ok=0
  sec_audit_auditctl_rules_grep -q -E -- '-a always,exit -F dir=/etc/pam\.d -F perm=wa' || _ok=0
fi
if [ "$_ok" -eq 1 ]; then
  sec_audit_report_pass 295 "changes to /etc/pam.conf and /etc/pam.d are collected"
else
  sec_audit_report_fail 295 "changes to /etc/pam.conf and /etc/pam.d are collected - audit rule missing or not loaded"
fi

fi
if secaudit_rule_enabled 296; then
_ok=1
sec_audit_audit_rule_on_disk -E -- '-a always,exit .*-S .*chmod.*fchmodat2?' || _ok=0
if sec_audit_have_bin auditctl; then
  sec_audit_auditctl_rules_grep -q -E -- '-a always,exit .*-S .*chmod.*fchmodat2?' || _ok=0
fi
if [ "$_ok" -eq 1 ]; then
  sec_audit_report_pass 296 "DAC permission modification events (chmod family) are collected"
else
  sec_audit_report_fail 296 "DAC permission modification events (chmod family) are collected - audit rule missing or not loaded"
fi

fi
if secaudit_rule_enabled 297; then
_ok=1
sec_audit_audit_rule_on_disk -E -- '-a always,exit .*-S .*chown.*fchownat?' || _ok=0
if sec_audit_have_bin auditctl; then
  sec_audit_auditctl_rules_grep -q -E -- '-a always,exit .*-S .*chown.*fchownat?' || _ok=0
fi
if [ "$_ok" -eq 1 ]; then
  sec_audit_report_pass 297 "DAC permission modification events (chown family) are collected"
else
  sec_audit_report_fail 297 "DAC permission modification events (chown family) are collected - audit rule missing or not loaded"
fi

fi
if secaudit_rule_enabled 298; then
if ! sec_audit_audit_rule_on_disk -E -- '(-a always,exit|-w).*(setxattr|lsetxattr|fsetxattr|removexattr|lremovexattr|fremovexattr)'; then
  sec_audit_report_fail 298 "extended attribute modification syscalls are collected - rule missing from /etc/audit/rules.d"
elif sec_audit_have_bin auditctl && ! sec_audit_auditctl_rules_grep -q -E -- '(-a always,exit|-w).*(setxattr|lsetxattr|fsetxattr|removexattr|lremovexattr|fremovexattr)'; then
  sec_audit_report_fail 298 "extended attribute modification syscalls are collected - rule present on disk but not loaded in the running configuration"
else
  sec_audit_report_pass 298 "extended attribute modification syscalls are collected"
fi

fi
if secaudit_rule_enabled 299; then
if sec_audit_audit_rule_on_disk_all -a always,exit -F arch=b64 -S mount; then
  sec_audit_report_pass 299 "audit rules collect successful filesystem mount events"
else
  sec_audit_report_fail 299 "audit rules for filesystem mounts are missing"
fi

fi
if secaudit_rule_enabled 300; then
if sec_audit_audit_rule_on_disk_all -w /var/run/utmp && sec_audit_audit_rule_on_disk_all -w /var/log/wtmp; then
  sec_audit_report_pass 300 "audit rules monitor /var/run/utmp, /var/log/wtmp session files"
else
  sec_audit_report_fail 300 "audit rules for session initiation files are missing"
fi

fi
if secaudit_rule_enabled 301; then
if sec_audit_audit_rule_on_disk_all -w /var/log/faillog && sec_audit_audit_rule_on_disk_all -w /var/log/lastlog; then
  sec_audit_report_pass 301 "audit rules monitor /var/log/faillog and lastlog for login events"
else
  sec_audit_report_fail 301 "audit rules for login/logout events are missing"
fi

fi
if secaudit_rule_enabled 302; then
_ok=1
sec_audit_audit_rule_on_disk -E -- '-a always,exit .*-S unlink,unlinkat' || _ok=0
if sec_audit_have_bin auditctl; then
  sec_audit_auditctl_rules_grep -q -E -- '-a always,exit .*-S unlink,unlinkat' || _ok=0
fi
if [ "$_ok" -eq 1 ]; then
  sec_audit_report_pass 302 "unlink file deletion events are collected"
else
  sec_audit_report_fail 302 "unlink file deletion events are collected - audit rule missing or not loaded"
fi

fi
if secaudit_rule_enabled 303; then
_ok=1
sec_audit_audit_rule_on_disk -E -- '-a always,exit .*-S .*rename(,|$).*' || _ok=0
if sec_audit_have_bin auditctl; then
  sec_audit_auditctl_rules_grep -q -E -- '-a always,exit .*-S .*rename(,|$).*' || _ok=0
fi
if [ "$_ok" -eq 1 ]; then
  sec_audit_report_pass 303 "rename file deletion events are collected"
else
  sec_audit_report_fail 303 "rename file deletion events are collected - audit rule missing or not loaded"
fi

fi
if secaudit_rule_enabled 304; then
_ok=1
sec_audit_audit_rule_on_disk -E -- '-a always,exit -F dir=/etc/apparmor -F perm=wa' || _ok=0
sec_audit_audit_rule_on_disk -E -- '-a always,exit -F dir=/etc/apparmor\.d -F perm=wa' || _ok=0
if sec_audit_have_bin auditctl; then
  sec_audit_auditctl_rules_grep -q -E -- '-a always,exit -F dir=/etc/apparmor -F perm=wa' || _ok=0
  sec_audit_auditctl_rules_grep -q -E -- '-a always,exit -F dir=/etc/apparmor\.d -F perm=wa' || _ok=0
fi
if [ "$_ok" -eq 1 ]; then
  sec_audit_report_pass 304 "changes to Mandatory Access Controls are collected"
else
  sec_audit_report_fail 304 "changes to Mandatory Access Controls are collected - audit rule missing or not loaded"
fi

fi
if secaudit_rule_enabled 305; then
_ok=1
sec_audit_audit_rule_on_disk -E -- '-a always,exit -F path=/usr/bin/chcon -F perm=x' || _ok=0
if sec_audit_have_bin auditctl; then
  sec_audit_auditctl_rules_grep -q -E -- '-a always,exit -F path=/usr/bin/chcon -F perm=x' || _ok=0
fi
if [ "$_ok" -eq 1 ]; then
  sec_audit_report_pass 305 "use of the chcon command is collected"
else
  sec_audit_report_fail 305 "use of the chcon command is collected - audit rule missing or not loaded"
fi

fi
if secaudit_rule_enabled 306; then
_ok=1
sec_audit_audit_rule_on_disk -E -- '-a always,exit -F path=/usr/bin/setfacl -F perm=x' || _ok=0
if sec_audit_have_bin auditctl; then
  sec_audit_auditctl_rules_grep -q -E -- '-a always,exit -F path=/usr/bin/setfacl -F perm=x' || _ok=0
fi
if [ "$_ok" -eq 1 ]; then
  sec_audit_report_pass 306 "use of the setfacl command is collected"
else
  sec_audit_report_fail 306 "use of the setfacl command is collected - audit rule missing or not loaded"
fi

fi
if secaudit_rule_enabled 307; then
_ok=1
sec_audit_audit_rule_on_disk -E -- '-a always,exit -F path=/usr/bin/chacl -F perm=x' || _ok=0
if sec_audit_have_bin auditctl; then
  sec_audit_auditctl_rules_grep -q -E -- '-a always,exit -F path=/usr/bin/chacl -F perm=x' || _ok=0
fi
if [ "$_ok" -eq 1 ]; then
  sec_audit_report_pass 307 "use of the chacl command is collected"
else
  sec_audit_report_fail 307 "use of the chacl command is collected - audit rule missing or not loaded"
fi

fi
if secaudit_rule_enabled 308; then
_ok=1
sec_audit_audit_rule_on_disk -E -- '-a always,exit -F path=/usr/sbin/usermod -F perm=x' || _ok=0
if sec_audit_have_bin auditctl; then
  sec_audit_auditctl_rules_grep -q -E -- '-a always,exit -F path=/usr/sbin/usermod -F perm=x' || _ok=0
fi
if [ "$_ok" -eq 1 ]; then
  sec_audit_report_pass 308 "use of the usermod command is collected"
else
  sec_audit_report_fail 308 "use of the usermod command is collected - audit rule missing or not loaded"
fi

fi
if secaudit_rule_enabled 309; then
if sec_audit_audit_rule_on_disk_all -a always,exit -F arch=b64 -S init_module && sec_audit_audit_rule_on_disk_all -w /sbin/insmod; then
  sec_audit_report_pass 309 "audit rules monitor kernel module load, unload, and modification"
else
  sec_audit_report_fail 309 "audit rules for kernel module operations are missing"
fi

fi
if secaudit_rule_enabled 310; then
_ok=1
sec_audit_audit_rule_on_disk -E -- '-a always,exit .*-S init_module,finit_module' || _ok=0
if sec_audit_have_bin auditctl; then
  sec_audit_auditctl_rules_grep -q -E -- '-a always,exit .*-S init_module,finit_module' || _ok=0
fi
if [ "$_ok" -eq 1 ]; then
  sec_audit_report_pass 310 "init_module and finit_module loading is collected"
else
  sec_audit_report_fail 310 "init_module and finit_module loading is collected - audit rule missing or not loaded"
fi

fi
if secaudit_rule_enabled 311; then
_ok=1
sec_audit_audit_rule_on_disk -E -- '-a always,exit .*-S .*delete_module' || _ok=0
if sec_audit_have_bin auditctl; then
  sec_audit_auditctl_rules_grep -q -E -- '-a always,exit .*-S .*delete_module' || _ok=0
fi
if [ "$_ok" -eq 1 ]; then
  sec_audit_report_pass 311 "delete_module loading is collected"
else
  sec_audit_report_fail 311 "delete_module loading is collected - audit rule missing or not loaded"
fi

fi
if secaudit_rule_enabled 312; then
if grep -Ph -- '^\h*-c\b' /etc/audit/rules.d/*.rules /etc/audit/audit.rules 2>/dev/null | tail -1 | grep -q .; then
  sec_audit_report_pass 312 "audit configuration is loaded regardless of errors (-c rule present)"
else
  sec_audit_report_fail 312 "the -c audit rule is not configured"
fi

fi
if secaudit_rule_enabled 313; then
if sec_audit_audit_rules_files_grep -q -E -- '^-e[[:space:]]+2\b' && sec_audit_auditctl_rules_grep -q -E -- '^-e[[:space:]]+2\b'; then
  sec_audit_report_pass 313 "audit configuration is immutable (-e 2 on disk and loaded)"
else
  sec_audit_report_fail 313 "audit configuration is not immutable (-e 2 missing on disk or in loaded rules)"
fi

fi
if secaudit_rule_enabled 314; then
_audit_log_dir="$(awk -F= '/^\s*log_file\s*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' /etc/audit/auditd.conf 2>/dev/null | xargs dirname 2>/dev/null)"
[ -n "$_audit_log_dir" ] || _audit_log_dir="/var/log/audit"
if sec_audit_have_bin augenrules; then
  _out=$(augenrules --check 2>&1)
  if printf '%s' "$_out" | grep -qi 'no change'; then
    sec_audit_report_pass 314 "running and on-disk audit configuration are the same"
  else
    sec_audit_report_fail 314 "audit configuration drift detected: $(printf '%s' "$_out" | head -n1)"
  fi
else
  sec_audit_report_fail 314 "augenrules is not available - running and on-disk audit rules cannot be compared"
fi
fi

if secaudit_rule_enabled 315; then
if ! sec_audit_is_package_installed auditd; then
  sec_audit__audit_absent_fail 315
elif [ ! -d "$_audit_log_dir" ] || [ ! -x "$_audit_log_dir" ]; then
  sec_audit_report_fail 315 "audit log directory ${_audit_log_dir} is missing or not readable (run as root)"
elif ! find "$_audit_log_dir" -maxdepth 1 -type f -perm /137 2>/dev/null | grep -q .; then
  sec_audit_report_pass 315 "audit log files have permissions 600 or stricter"
else
  sec_audit_report_fail 315 "audit log files have overly permissive access"
fi

fi
if secaudit_rule_enabled 316; then
if ! sec_audit_is_package_installed auditd; then
  sec_audit__audit_absent_fail 316
elif [ ! -d "$_audit_log_dir" ] || [ ! -x "$_audit_log_dir" ]; then
  sec_audit_report_fail 316 "audit log directory ${_audit_log_dir} is missing or not readable (run as root)"
elif ! find "$_audit_log_dir" -maxdepth 1 -type f ! -user root 2>/dev/null | grep -q .; then
  sec_audit_report_pass 316 "audit log files are owned by root"
else
  sec_audit_report_fail 316 "audit log files are not owned by root"
fi

fi
if secaudit_rule_enabled 317; then
if ! sec_audit_is_package_installed auditd; then
  sec_audit__audit_absent_fail 317
elif [ ! -d "$_audit_log_dir" ] || [ ! -x "$_audit_log_dir" ]; then
  sec_audit_report_fail 317 "audit log directory ${_audit_log_dir} is missing or not readable (run as root)"
elif ! find "$_audit_log_dir" -maxdepth 1 -type f ! -group root 2>/dev/null | grep -q .; then
  sec_audit_report_pass 317 "audit log files belong to group root"
else
  sec_audit_report_fail 317 "audit log files do not belong to group root"
fi

fi
if secaudit_rule_enabled 318; then
if ! sec_audit_is_package_installed auditd; then
  sec_audit__audit_absent_fail 318
elif stat -Lc '%a' "$_audit_log_dir" 2>/dev/null | grep -qE '^[0-7][0145]0$'; then
  sec_audit_report_pass 318 "audit log directory has permissions 700 or 750"
else
  sec_audit_report_fail 318 "audit log directory permissions are too permissive"
fi

fi
if secaudit_rule_enabled 319; then
if ! sec_audit_is_package_installed auditd; then
  sec_audit__audit_absent_fail 319
elif ! find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) 2>/dev/null | xargs stat -Lc '%a' 2>/dev/null | grep -qvE '^[0-6][04]0$'; then
  sec_audit_report_pass 319 "audit configuration files have permissions 640 or stricter"
else
  sec_audit_report_fail 319 "audit configuration files have overly permissive access"
fi

fi
if secaudit_rule_enabled 320; then
if ! sec_audit_is_package_installed auditd; then
  sec_audit__audit_absent_fail 320
elif ! find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -user root 2>/dev/null | grep -q .; then
  sec_audit_report_pass 320 "audit configuration files are owned by root"
else
  sec_audit_report_fail 320 "audit configuration files are not owned by root"
fi

fi
if secaudit_rule_enabled 321; then
if ! sec_audit_is_package_installed auditd; then
  sec_audit__audit_absent_fail 321
elif ! find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -group root 2>/dev/null | grep -q .; then
  sec_audit_report_pass 321 "audit configuration files belong to group root"
else
  sec_audit_report_fail 321 "audit configuration files do not belong to group root"
fi

fi
if secaudit_rule_enabled 322; then
if ! sec_audit_is_package_installed auditd; then
  sec_audit__audit_absent_fail 322
elif ! stat -Lc '%a' /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules 2>/dev/null | grep -qvE '^[0-7][0-5][0-5]$'; then
  sec_audit_report_pass 322 "audit tools have correct permissions 755 or stricter"
else
  sec_audit_report_fail 322 "audit tools have overly permissive access"
fi

fi
if secaudit_rule_enabled 323; then
if ! sec_audit_is_package_installed auditd; then
  sec_audit__audit_absent_fail 323
elif ! stat -Lc '%U' /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules 2>/dev/null | grep -qv '^root$'; then
  sec_audit_report_pass 323 "audit tools are owned by root"
else
  sec_audit_report_fail 323 "audit tools are not owned by root"
fi

fi
if secaudit_rule_enabled 324; then
if ! sec_audit_is_package_installed auditd; then
  sec_audit__audit_absent_fail 324
elif ! stat -Lc '%G' /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules 2>/dev/null | grep -qv '^root$'; then
  sec_audit_report_pass 324 "audit tools belong to group root"
else
  sec_audit_report_fail 324 "audit tools do not belong to group root"
fi

fi
if secaudit_rule_enabled 325; then
if dpkg-query -W -f='${Status}' aide 2>/dev/null | grep -q 'install ok installed'; then
  sec_audit_report_pass 325 "AIDE is installed"
else
  sec_audit_report_fail 325 "AIDE is not installed"
fi

fi
if secaudit_rule_enabled 326; then
if systemctl is-enabled aidecheck 2>/dev/null | grep -q '^enabled' || crontab -l 2>/dev/null | grep -q 'aide' || grep -rq 'aide' /etc/cron.* /var/spool/cron/ 2>/dev/null; then
  sec_audit_report_pass 326 "filesystem integrity check AIDE is scheduled in cron or systemd"
else
  sec_audit_report_fail 326 "no scheduled filesystem integrity check found"
fi

fi
if secaudit_rule_enabled 327; then
if ! sec_audit_is_package_installed aide && ! sec_audit_have_bin aide; then
  sec_audit_report_fail 327 "AIDE is not installed"
else
  _conf=$(find /etc -type f -name 'aide.conf' 2>/dev/null | head -n1)
  _bad=""
  for _t in auditctl auditd ausearch aureport augenrules; do
    _p=$(readlink -f "/sbin/$_t" 2>/dev/null)
    [ -n "$_p" ] || _p=$(readlink -f "/usr/sbin/$_t" 2>/dev/null)
    [ -n "$_p" ] || continue
    if [ -n "$_conf" ] && grep -Eq "^[^#]*${_p}[^#]*sha512" "$_conf" 2>/dev/null; then
      :
    else
      _bad+=" ${_t}"
    fi
  done
  if [ -z "$_bad" ]; then
    sec_audit_report_pass 327 "AIDE protects audit tools with cryptographic checksums (sha512)"
  else
    sec_audit_report_fail 327 "AIDE does not cover audit tools with sha512:${_bad}"
  fi
fi

fi
}

sec_audit_run_accounts() {
if secaudit_rule_enabled 328; then
_bad=""
_missing=""
for _p in /etc/passwd; do
  if [ ! -e "$_p" ]; then
    case "$_p" in
      *\**|*\?*) : ;;
      *) _missing+=" ${_p}" ;;
    esac
    continue
  fi
  sec_audit__path_access_ok "$_p" 644 'root' 'root' || _bad+=" $(sec_audit__path_access_describe "$_p")"
done
if [ -n "$_bad" ]; then
  sec_audit_report_fail 328 "insecure access on:${_bad} (expected 644 root:root or more restrictive)"
elif [ -n "$_missing" ]; then
  sec_audit_report_fail 328 "missing path(s):${_missing}"
else
  sec_audit_report_pass 328 "access is 644 root:root or more restrictive for all checked paths"
fi

fi
if secaudit_rule_enabled 329; then
_bad=""
_missing=""
for _p in /etc/passwd-; do
  if [ ! -e "$_p" ]; then
    case "$_p" in
      *\**|*\?*) : ;;
      *) _missing+=" ${_p}" ;;
    esac
    continue
  fi
  sec_audit__path_access_ok "$_p" 644 'root' 'root' || _bad+=" $(sec_audit__path_access_describe "$_p")"
done
if [ -n "$_bad" ]; then
  sec_audit_report_fail 329 "insecure access on:${_bad} (expected 644 root:root or more restrictive)"
elif [ -n "$_missing" ]; then
  sec_audit_report_fail 329 "missing path(s):${_missing}"
else
  sec_audit_report_pass 329 "access is 644 root:root or more restrictive for all checked paths"
fi

fi
if secaudit_rule_enabled 330; then
_bad=""
_missing=""
for _p in /etc/group; do
  if [ ! -e "$_p" ]; then
    case "$_p" in
      *\**|*\?*) : ;;
      *) _missing+=" ${_p}" ;;
    esac
    continue
  fi
  sec_audit__path_access_ok "$_p" 644 'root' 'root' || _bad+=" $(sec_audit__path_access_describe "$_p")"
done
if [ -n "$_bad" ]; then
  sec_audit_report_fail 330 "insecure access on:${_bad} (expected 644 root:root or more restrictive)"
elif [ -n "$_missing" ]; then
  sec_audit_report_fail 330 "missing path(s):${_missing}"
else
  sec_audit_report_pass 330 "access is 644 root:root or more restrictive for all checked paths"
fi

fi
if secaudit_rule_enabled 331; then
_bad=""
_missing=""
for _p in /etc/group-; do
  if [ ! -e "$_p" ]; then
    case "$_p" in
      *\**|*\?*) : ;;
      *) _missing+=" ${_p}" ;;
    esac
    continue
  fi
  sec_audit__path_access_ok "$_p" 644 'root' 'root' || _bad+=" $(sec_audit__path_access_describe "$_p")"
done
if [ -n "$_bad" ]; then
  sec_audit_report_fail 331 "insecure access on:${_bad} (expected 644 root:root or more restrictive)"
elif [ -n "$_missing" ]; then
  sec_audit_report_fail 331 "missing path(s):${_missing}"
else
  sec_audit_report_pass 331 "access is 644 root:root or more restrictive for all checked paths"
fi

fi
if secaudit_rule_enabled 332; then
_bad=""
_missing=""
for _p in /etc/shadow; do
  if [ ! -e "$_p" ]; then
    case "$_p" in
      *\**|*\?*) : ;;
      *) _missing+=" ${_p}" ;;
    esac
    continue
  fi
  sec_audit__path_access_ok "$_p" 640 'root' 'root|shadow' || _bad+=" $(sec_audit__path_access_describe "$_p")"
done
if [ -n "$_bad" ]; then
  sec_audit_report_fail 332 "insecure access on:${_bad} (expected 640 root:root|shadow or more restrictive)"
elif [ -n "$_missing" ]; then
  sec_audit_report_fail 332 "missing path(s):${_missing}"
else
  sec_audit_report_pass 332 "access is 640 root:root|shadow or more restrictive for all checked paths"
fi

fi
if secaudit_rule_enabled 333; then
_bad=""
_missing=""
for _p in /etc/shadow-; do
  if [ ! -e "$_p" ]; then
    case "$_p" in
      *\**|*\?*) : ;;
      *) _missing+=" ${_p}" ;;
    esac
    continue
  fi
  sec_audit__path_access_ok "$_p" 640 'root' 'root|shadow' || _bad+=" $(sec_audit__path_access_describe "$_p")"
done
if [ -n "$_bad" ]; then
  sec_audit_report_fail 333 "insecure access on:${_bad} (expected 640 root:root|shadow or more restrictive)"
elif [ -n "$_missing" ]; then
  sec_audit_report_fail 333 "missing path(s):${_missing}"
else
  sec_audit_report_pass 333 "access is 640 root:root|shadow or more restrictive for all checked paths"
fi

fi
if secaudit_rule_enabled 334; then
_bad=""
_missing=""
for _p in /etc/gshadow; do
  if [ ! -e "$_p" ]; then
    case "$_p" in
      *\**|*\?*) : ;;
      *) _missing+=" ${_p}" ;;
    esac
    continue
  fi
  sec_audit__path_access_ok "$_p" 640 'root' 'root|shadow' || _bad+=" $(sec_audit__path_access_describe "$_p")"
done
if [ -n "$_bad" ]; then
  sec_audit_report_fail 334 "insecure access on:${_bad} (expected 640 root:root|shadow or more restrictive)"
elif [ -n "$_missing" ]; then
  sec_audit_report_fail 334 "missing path(s):${_missing}"
else
  sec_audit_report_pass 334 "access is 640 root:root|shadow or more restrictive for all checked paths"
fi

fi
if secaudit_rule_enabled 335; then
_bad=""
_missing=""
for _p in /etc/gshadow-; do
  if [ ! -e "$_p" ]; then
    case "$_p" in
      *\**|*\?*) : ;;
      *) _missing+=" ${_p}" ;;
    esac
    continue
  fi
  sec_audit__path_access_ok "$_p" 640 'root' 'root|shadow' || _bad+=" $(sec_audit__path_access_describe "$_p")"
done
if [ -n "$_bad" ]; then
  sec_audit_report_fail 335 "insecure access on:${_bad} (expected 640 root:root|shadow or more restrictive)"
elif [ -n "$_missing" ]; then
  sec_audit_report_fail 335 "missing path(s):${_missing}"
else
  sec_audit_report_pass 335 "access is 640 root:root|shadow or more restrictive for all checked paths"
fi

fi
if secaudit_rule_enabled 336; then
_bad=""
_missing=""
for _p in /etc/shells; do
  if [ ! -e "$_p" ]; then
    case "$_p" in
      *\**|*\?*) : ;;
      *) _missing+=" ${_p}" ;;
    esac
    continue
  fi
  sec_audit__path_access_ok "$_p" 644 'root' 'root' || _bad+=" $(sec_audit__path_access_describe "$_p")"
done
if [ -n "$_bad" ]; then
  sec_audit_report_fail 336 "insecure access on:${_bad} (expected 644 root:root or more restrictive)"
elif [ -n "$_missing" ]; then
  sec_audit_report_fail 336 "missing path(s):${_missing}"
else
  sec_audit_report_pass 336 "access is 644 root:root or more restrictive for all checked paths"
fi

fi
if secaudit_rule_enabled 337; then
_checked=0
_obad=""
for _p in /etc/security/opasswd /etc/security/opasswd.old; do
  [ -e "$_p" ] || continue
  _checked=$((_checked + 1))
  sec_audit__path_access_ok "$_p" 600 'root' 'root' || _obad+=" $(sec_audit__path_access_describe "$_p")"
done
if [ -n "$_obad" ]; then
  sec_audit_report_fail 337 "insecure access on:${_obad} (expected 600 root:root or more restrictive)"
elif [ "$_checked" -eq 0 ]; then
  sec_audit_report_pass 337 "no such files exist (nothing to verify)"
else
  sec_audit_report_pass 337 "${_checked} file(s) verified: access is 600 root:root or more restrictive"
fi

fi
if secaudit_rule_enabled 338; then
_res=$(sec_audit__scan_local_mounts --all \( -path /tmp -o -path /var/tmp -o -path /dev/shm \) -prune -o \( \( -type f -perm -0002 \) -o \( -type d -perm -0002 ! -perm -1000 \) \))
case $? in
  0) sec_audit_report_fail 338 "world-writable files or directories exist on local filesystems: ${_res}" ;;
  1) sec_audit_report_pass 338 "no world-writable files or directories found on local filesystems" ;;
  2) sec_audit_report_fail 338 "world-writable files could not be scanned because the timeout utility is not available" ;;
  *) sec_audit_report_fail 338 "world-writable scan did not finish within ${SCAN_BUDGET}s (SCAN_BUDGET/SCAN_TIMEOUT), result unknown" ;;
esac

fi
if secaudit_rule_enabled 339; then
_res=$(sec_audit__scan_local_mounts --all \( -path /tmp -o -path /var/tmp -o -path /dev/shm \) -prune -o \( -nouser -o -nogroup \))
case $? in
  0) sec_audit_report_fail 339 "unowned or ungrouped files exist on local filesystems: ${_res}" ;;
  1) sec_audit_report_pass 339 "no unowned or ungrouped files found on local filesystems" ;;
  2) sec_audit_report_fail 339 "unowned files could not be scanned because the timeout utility is not available" ;;
  *) sec_audit_report_fail 339 "unowned-file scan did not finish within ${SCAN_BUDGET}s (SCAN_BUDGET/SCAN_TIMEOUT), result unknown" ;;
esac

fi
if secaudit_rule_enabled 340; then
sec_audit__suid_sgid_scan
_suid_rc=$?
_res=$_SUID_CACHE
_trunc=0
case "$_res" in
  *" (list limited to "*) _trunc=1; _res="${_res%% (list limited to *}" ;;
esac
if [ "$_suid_rc" -eq 2 ] || [ "$_suid_rc" -eq 3 ] || [ "$_trunc" -eq 1 ]; then
  sec_audit_report_fail 340 "setuid/setgid inventory could not be completed (scan unavailable, incomplete or truncated)"
elif [ "$_suid_rc" -eq 1 ]; then
  sec_audit_report_pass 340 "no setuid/setgid files found"
else
  _bad=""
  _n=0
  for _b in $_res; do
    _n=$((_n + 1))
    sec_audit__pkg_owns_path "$_b" || _bad+=" $_b"
  done
  if [ -z "$_bad" ]; then
    sec_audit_report_pass 340 "all ${_n} setuid/setgid files belong to installed packages"
  else
    sec_audit_report_fail 340 "setuid/setgid files not provided by any package:$(printf '%s' "$_bad" | tr ' ' '\n' | head -n 10 | tr '\n' ' ')"
  fi
fi

fi
if secaudit_rule_enabled 341; then
_bad=$(awk -F: '($2 != "x") {print $1}' /etc/passwd 2>/dev/null | tr '\n' ' ')
if [ -z "$_bad" ]; then
  sec_audit_report_pass 341 "all accounts in /etc/passwd use shadowed passwords"
else
  sec_audit_report_fail 341 "accounts without shadowed passwords: ${_bad}"
fi

fi
if secaudit_rule_enabled 342; then
if [ ! -e /etc/shadow ]; then
  sec_audit_report_fail 342 "/etc/shadow is missing"
elif [ ! -r /etc/shadow ]; then
  sec_audit_report_fail 342 "/etc/shadow is not readable (run as root)"
elif ! awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null | grep -q .; then
  sec_audit_report_pass 342 "no accounts in /etc/shadow have an empty password field"
else
  sec_audit_report_fail 342 "one or more accounts have an empty password field in /etc/shadow"
fi

fi
if secaudit_rule_enabled 343; then
_bad=$(awk -F: 'NR==FNR{g[$3]=1;next} !($4 in g){print $1" (GID "$4")"}' /etc/group /etc/passwd 2>/dev/null | tr '\n' ' ')
if [ -z "$_bad" ]; then
  sec_audit_report_pass 343 "all GIDs in /etc/passwd exist in /etc/group"
else
  sec_audit_report_fail 343 "users with a GID missing from /etc/group: ${_bad}"
fi

fi
if secaudit_rule_enabled 344; then
_m=$(awk -F: '$1=="shadow"{print $4}' /etc/group 2>/dev/null)
_sg=$(getent group shadow 2>/dev/null | awk -F: '{print $3}')
_bad=$(awk -F: -v g="${_sg:-42}" '$4==g{print $1}' /etc/passwd 2>/dev/null | tr '\n' ' ')
if [ -z "$_m" ] && [ -z "$_bad" ]; then
  sec_audit_report_pass 344 "shadow group is empty"
else
  sec_audit_report_fail 344 "shadow group is not empty (members: '${_m}'; users with shadow as primary group: ${_bad:-none})"
fi

fi
if secaudit_rule_enabled 345; then
if [ $(awk -F: '{print $3}' /etc/passwd 2>/dev/null | sort | uniq -d | wc -l) -eq 0 ]; then
  sec_audit_report_pass 345 "no duplicate UIDs exist in /etc/passwd"
else
  sec_audit_report_fail 345 "duplicate UIDs found in /etc/passwd"
fi

fi
if secaudit_rule_enabled 346; then
if [ $(awk -F: '{print $3}' /etc/group 2>/dev/null | sort | uniq -d | wc -l) -eq 0 ]; then
  sec_audit_report_pass 346 "no duplicate GIDs exist in /etc/group"
else
  sec_audit_report_fail 346 "duplicate GIDs found in /etc/group"
fi

fi
if secaudit_rule_enabled 347; then
if [ $(awk -F: '{print $1}' /etc/passwd 2>/dev/null | sort | uniq -d | wc -l) -eq 0 ]; then
  sec_audit_report_pass 347 "no duplicate usernames exist in /etc/passwd"
else
  sec_audit_report_fail 347 "duplicate usernames found in /etc/passwd"
fi

fi
if secaudit_rule_enabled 348; then
if [ $(awk -F: '{print $1}' /etc/group 2>/dev/null | sort | uniq -d | wc -l) -eq 0 ]; then
  sec_audit_report_pass 348 "no duplicate group names exist in /etc/group"
else
  sec_audit_report_fail 348 "duplicate group names found in /etc/group"
fi
fi

if secaudit_rule_enabled 349; then
_bad=""
while IFS=: read -r _u _p _uid _gid _gecos _home _shell; do
  if [ ! -d "$_home" ]; then
    _bad+=" ${_u}(missing $(sec_audit__sanitize "${_home}"))"
  elif [ "$(sec_audit__owner_of "$_home")" != "$_u" ] || ! sec_audit__perm_within "$(sec_audit__perm_of "$_home")" 750; then
    _bad+=" $(sec_audit__path_access_describe "$_home")"
  fi
done < <(sec_audit__interactive_users)
if [ -z "$_bad" ]; then
  sec_audit_report_pass 349 "interactive user home directories exist, are user-owned and 750 or more restrictive"
else
  sec_audit_report_fail 349 "interactive user home directories missing, wrongly owned or too open:${_bad}"
fi

fi
if secaudit_rule_enabled 350; then
_bad=""
while IFS=: read -r _u _p _uid _gid _gecos _home _shell; do
  [ -d "$_home" ] || continue
  if [ ! -r "$_home" ] || [ ! -x "$_home" ]; then
    _bad+=" ${_home}(not readable, run as root)"
    continue
  fi
  _grp=$(sec_audit__group_of "$_home")
  while IFS= read -r -d '' _f; do
    if [ "$(sec_audit__owner_of "$_f")" != "$_u" ] || [ "$(sec_audit__group_of "$_f")" != "$_grp" ] \
       || ! sec_audit__perm_within "$(sec_audit__perm_of "$_f")" 644; then
      _bad+=" $(sec_audit__path_access_describe "$_f")"
    fi
  done < <(find "$_home" -maxdepth 1 -mindepth 1 -type f -name '.*' -print0 2>/dev/null)
done < <(sec_audit__interactive_users)
if [ -z "$_bad" ]; then
  sec_audit_report_pass 350 "interactive user dot files are user-owned, user-group and 644 or more restrictive"
else
  sec_audit_report_fail 350 "interactive user dot files wrongly owned/grouped or more permissive than 644:${_bad}"
fi

fi
if secaudit_rule_enabled 351; then
_bad=""
while IFS=: read -r _u _p _uid _gid _gecos _home _shell; do
  [ -d "$_home" ] || continue
  if [ ! -r "$_home" ] || [ ! -x "$_home" ]; then
    _bad+=" ${_home}(not readable, run as root)"
    continue
  fi
  _grp=$(sec_audit__group_of "$_home")
  while IFS= read -r -d '' _d; do
    _max=750
    [ "${_d##*/}" = ".ssh" ] && _max=700
    if [ "$(sec_audit__owner_of "$_d")" != "$_u" ] || [ "$(sec_audit__group_of "$_d")" != "$_grp" ] \
       || ! sec_audit__perm_within "$(sec_audit__perm_of "$_d")" "$_max"; then
      _bad+=" $(sec_audit__path_access_describe "$_d")"
    fi
  done < <(find "$_home" -maxdepth 1 -mindepth 1 -type d -name '.*' -print0 2>/dev/null)
done < <(sec_audit__interactive_users)
if [ -z "$_bad" ]; then
  sec_audit_report_pass 351 "local interactive user dot directories are user-owned, user-group and 750 or more restrictive (700 for ~/.ssh)"
else
  sec_audit_report_fail 351 "insecure dot directories:${_bad}"
fi

fi
}

sec_audit_main() {
    sec_audit_run_initial_setup
    sec_audit_run_services
    sec_audit_run_network
    sec_audit_run_logging_and_auditing
    sec_audit_run_access_control
    sec_audit_run_system_maintenance
    sec_audit_run_accounts
    exit 0
}

sec_audit_main "$@"
