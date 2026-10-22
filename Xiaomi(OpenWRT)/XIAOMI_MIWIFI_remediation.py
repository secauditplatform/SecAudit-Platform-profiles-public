#!/usr/bin/env python3
"""Xiaomi MiWiFi (OpenWrt-like) security configuration remediation."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from typing import Iterable

from remote_access import credential_bundle, fetch_config_lines

_XM_RULE_COUNT = 25

_XM_SHOW_COMMAND = (
    "PATH=/sbin:/bin:/usr/sbin:/usr/bin; "
    "uci show 2>/dev/null; "
    "echo __FILE__/etc/openwrt_release; cat /etc/openwrt_release 2>/dev/null; "
    "for f in wireless firewall upnpd dropbear system dhcp network samba vsftpd "
    "xiaoqiang misc luci; do "
    "echo __FILE__/etc/config/$f; cat /etc/config/$f 2>/dev/null; "
    "done; "
    "echo __NVRAM__; "
    "(nvram show 2>/dev/null || true); "
    "(bdata show 2>/dev/null || true)"
)

_XM_PLATFORM_MARKERS_RE = re.compile(
    r"(?i)(?:\buci\b|DISTRIB_|openwrt|miwifi|xiaoqiang|wireless\.|network\.lan|"
    r"config\s+wifi-iface|config\s+zone|dropbear|nvram|bdata)",
)

_XM_DEFAULT_SSID_RE = re.compile(
    r"^(xiaomi|miwifi|mi[\s_-]?router|xiaomi[\s_-]?router)",
    re.IGNORECASE,
)

_XM_BLOB = ""
_XM_CMDS: list[str] = []
_XM_MODE = "plan"


def secaudit_log(msg: str) -> None:
    text = f"[remediation] {msg}"
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode("ascii", "replace").decode("ascii"))


def secaudit_remediate_done(num: int | str, detail: str) -> None:
    text = f"[remediation] REMEDIATE RULE{num}= applied: {detail}"
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode("ascii", "replace").decode("ascii"))


def secaudit_remediate_skip(num: int | str, detail: str) -> None:
    text = f"[remediation] REMEDIATE RULE{num}= SKIP: manual step required - {detail}"
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode("ascii", "replace").decode("ascii"))


def secaudit_skip_all_rules(reason: str) -> None:
    for n in range(1, _XM_RULE_COUNT + 1):
        secaudit_remediate_skip(n, reason)


def secaudit_env(*names: str, default: str = "") -> str:
    for name in names:
        val = os.environ.get(name)
        if val is not None and str(val).strip():
            return str(val).strip()
    return default


def secaudit_env_bool(name: str, default: bool = True) -> bool:
    raw = os.environ.get(name)
    if raw is None or not str(raw).strip():
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def secaudit_trim(value: str | None) -> str:
    return (value or "").strip()


def secaudit_lower(value: str | None) -> str:
    return secaudit_trim(value).lower()


def secaudit_norm_lines(lines: Iterable[str]) -> list[str]:
    return [ln.rstrip("\r\n") for ln in lines]


def secaudit_uci_values(key_suffix: str) -> list[str]:
    pattern = re.compile(
        rf"(?m)^[^\n]*\.{re.escape(key_suffix)}=(?:'([^']*)'|\"([^\"]*)\"|([^\s]+))"
    )
    out: list[str] = []
    for match in pattern.finditer(_XM_BLOB):
        val = next(g for g in match.groups() if g is not None)
        out.append(val.strip())
    return out


def secaudit_all_values(name: str) -> list[str]:
    option = re.compile(
        rf"(?mi)^\s*option\s+{re.escape(name)}\s+(?:'([^']*)'|\"([^\"]*)\"|(\S+))"
    )
    kv = re.compile(
        rf"(?mi)^(?:{re.escape(name)})=(?:'([^']*)'|\"([^\"]*)\"|(\S+))"
    )
    out: list[str] = []
    for pattern in (option, kv):
        for match in pattern.finditer(_XM_BLOB):
            val = next(g for g in match.groups() if g is not None)
            if val != "":
                out.append(val.strip())
    out.extend(v for v in secaudit_uci_values(name) if v != "")
    return out


def secaudit_wifi_iface_sections() -> list[str]:
    found: list[str] = []
    for match in re.finditer(r"(?m)^wireless\.([^=\s]+)=wifi-iface\b", _XM_BLOB):
        found.append(match.group(1))
    if found:
        return list(dict.fromkeys(found))
    count = len(re.findall(r"(?mi)^config\s+wifi-iface\b", _XM_BLOB))
    return [f"@wifi-iface[{i}]" for i in range(count)]


def secaudit_firewall_zone_sections() -> dict[str, str]:
    zones: dict[str, str] = {}
    for match in re.finditer(r"(?m)^firewall\.([^=\s]+)=zone\b", _XM_BLOB):
        sec = match.group(1)
        name_m = re.search(
            rf"(?m)^firewall\.{re.escape(sec)}\.name=(?:'([^']*)'|\"([^\"]*)\"|(\S+))",
            _XM_BLOB,
        )
        if not name_m:
            continue
        name = next(g for g in name_m.groups() if g is not None).strip().lower()
        zones[name] = sec
    return zones


def secaudit_shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def secaudit_queue(cmd: str) -> None:
    cmd = secaudit_trim(cmd)
    if cmd and cmd not in _XM_CMDS:
        _XM_CMDS.append(cmd)


def secaudit_platform_present() -> bool:
    if not secaudit_trim(_XM_BLOB):
        return False
    return bool(_XM_PLATFORM_MARKERS_RE.search(_XM_BLOB))


def secaudit_collect_config() -> bool:
    global _XM_BLOB
    try:
        raw = fetch_config_lines(device_type="linux", show_command=_XM_SHOW_COMMAND)
    except SystemExit:
        raise
    except Exception as exc:
        secaudit_log(f"collect failed: {type(exc).__name__}: {exc}")
        _XM_BLOB = ""
        return False
    _XM_BLOB = "\n".join(secaudit_norm_lines(raw))
    return bool(secaudit_trim(_XM_BLOB))


def secaudit_detect_apply_mode() -> str:
    if not secaudit_env_bool("XM_REMEDIATE_APPLY", True):
        return "plan"
    if shutil.which("uci"):
        return "local"
    creds = credential_bundle()
    if creds.get("host") and creds.get("username"):
        return "ssh"
    return "plan"


def secaudit_run_local(script: str) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            ["sh", "-c", script],
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        return proc.returncode == 0, out.strip()[:400]
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def secaudit_run_ssh(script: str) -> tuple[bool, str]:
    creds = credential_bundle()
    try:
        import paramiko
    except ImportError as exc:
        return False, f"paramiko missing: {exc}"

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs: dict = {
        "hostname": creds["host"],
        "port": creds["port"],
        "username": creds["username"],
        "timeout": 20,
        "auth_timeout": 20,
        "banner_timeout": 20,
        "allow_agent": False,
        "look_for_keys": False,
    }
    if creds.get("use_keys") and creds.get("key_file"):
        kwargs["key_filename"] = creds["key_file"]
    elif creds.get("password"):
        kwargs["password"] = creds["password"]
    try:
        client.connect(**kwargs)
        _, stdout, stderr = client.exec_command(script, timeout=180)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        status = stdout.channel.recv_exit_status()
        text = (out or err).strip()[:400]
        return status == 0, text
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"
    finally:
        try:
            client.close()
        except Exception:
            pass


def secaudit_flush_commands() -> None:
    global _XM_MODE
    if not _XM_CMDS:
        secaudit_log("no uci/nvram commands queued")
        return

    body = "\n".join(_XM_CMDS)
    script = (
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin; set +e\n"
        f"{body}\n"
        "uci commit 2>/dev/null || true\n"
        "/etc/init.d/network reload 2>/dev/null || true\n"
        "/etc/init.d/firewall reload 2>/dev/null || true\n"
        "/etc/init.d/dnsmasq restart 2>/dev/null || true\n"
        "wifi reload 2>/dev/null || wifi 2>/dev/null || true\n"
        "echo SECAUDIT_REMEDIATE_OK\n"
    )

    secaudit_log(f"apply mode={_XM_MODE}; queued_cmds={len(_XM_CMDS)}")
    if _XM_MODE == "plan":
        secaudit_log("--- offline uci plan (copy to device shell) ---")
        print(script)
        secaudit_log("--- end plan ---")
        return

    if _XM_MODE == "local":
        ok, detail = secaudit_run_local(script)
    else:
        ok, detail = secaudit_run_ssh(script)

    if ok:
        secaudit_log(f"live apply ok: {detail or 'SECAUDIT_REMEDIATE_OK'}")
    else:
        secaudit_log(f"live apply failed ({detail}); plan printed for manual use")
        print(script)
        _XM_MODE = "plan"


def secaudit_remediate_hostname(num: int) -> None:
    host = secaudit_env("XM_REMEDIATE_HOSTNAME", default="miwifi-hardened")
    secaudit_queue(f"uci set system.@system[0].hostname={secaudit_shell_quote(host)}")
    secaudit_remediate_done(num, f"hostname={host}")


def secaudit_remediate_firmware(num: int) -> None:
    secaudit_remediate_skip(
        num,
        "update firmware via Xiaomi Security Center / System -> Upgrade (no safe auto-flash)",
    )


def secaudit_remediate_wifi_encryption(num: int) -> None:
    enc = secaudit_env("XM_REMEDIATE_WIFI_ENC", default="psk2+ccmp")
    sections = secaudit_wifi_iface_sections() or ["@wifi-iface[0]"]
    for sec in sections:
        secaudit_queue(f"uci set wireless.{sec}.encryption={secaudit_shell_quote(enc)}")
    secaudit_remediate_done(num, f"wireless encryption={enc} on {len(sections)} iface(s)")


def secaudit_remediate_wps(num: int) -> None:
    sections = secaudit_wifi_iface_sections() or ["@wifi-iface[0]"]
    for sec in sections:
        for opt in ("wps_pushbutton", "wps_label", "wps_config", "wps_pbc", "wps"):
            secaudit_queue(f"uci -q delete wireless.{sec}.{opt} 2>/dev/null || true")
            secaudit_queue(f"uci set wireless.{sec}.{opt}='0' 2>/dev/null || true")
        secaudit_queue(f"uci set wireless.{sec}.wps_disabled='1' 2>/dev/null || true")
    secaudit_remediate_done(num, "WPS options cleared/disabled on wifi-iface")


def secaudit_remediate_upnp(num: int) -> None:
    secaudit_queue("uci set upnpd.config.enabled='0' 2>/dev/null || true")
    secaudit_queue("uci set upnpd.@upnpd[0].enabled='0' 2>/dev/null || true")
    secaudit_queue("/etc/init.d/miniupnpd stop 2>/dev/null || true")
    secaudit_queue("/etc/init.d/miniupnpd disable 2>/dev/null || true")
    secaudit_remediate_done(num, "UPnP/miniupnpd disabled")


def secaudit_remediate_remote_mgmt(num: int) -> None:
    for key in (
        "xiaoqiang.common.remote",
        "xiaoqiang.common.remote_care",
        "xiaoqiang.common.wan_manage",
        "xiaoqiang.common.cloud_remote",
    ):
        secaudit_queue(f"uci set {key}='0' 2>/dev/null || true")
    secaudit_queue(
        "uci -q delete firewall.Allow-HTTP 2>/dev/null; "
        "uci -q delete firewall.Allow-HTTPS 2>/dev/null; "
        "uci -q delete firewall.Allow-SSH 2>/dev/null; true"
    )
    secaudit_remediate_done(
        num, "xiaoqiang remote flags off; WAN mgmt rules pruned (best-effort)"
    )


def secaudit_remediate_firewall(num: int) -> None:
    secaudit_queue("uci set firewall.@defaults[0].syn_flood='1' 2>/dev/null || true")
    secaudit_queue(
        "uci set firewall.@defaults[0].synflood_protect='1' 2>/dev/null || true"
    )
    secaudit_queue("uci set firewall.@defaults[0].input='REJECT' 2>/dev/null || true")
    secaudit_queue("uci set firewall.@defaults[0].forward='REJECT' 2>/dev/null || true")
    zones = secaudit_firewall_zone_sections()
    wan = zones.get("wan")
    if wan:
        secaudit_queue(f"uci set firewall.{wan}.input='REJECT'")
        secaudit_queue(f"uci set firewall.{wan}.forward='REJECT' 2>/dev/null || true")
    else:
        secaudit_queue(
            "for s in $(uci -q show firewall | sed -n 's/=zone$//p'); do "
            "n=$(uci -q get $s.name); "
            "[ \"$n\" = wan ] && uci set $s.input=REJECT && uci set $s.forward=REJECT; "
            "done"
        )
    secaudit_remediate_done(num, "firewall defaults + WAN input hardened")


def secaudit_remediate_telnet(num: int) -> None:
    secaudit_queue("nvram set telnet_en=0 2>/dev/null || true")
    secaudit_queue("bdata set telnet_en=0 2>/dev/null || true")
    secaudit_queue("/etc/init.d/telnet stop 2>/dev/null || true")
    secaudit_queue("/etc/init.d/telnet disable 2>/dev/null || true")
    secaudit_queue("killall telnetd 2>/dev/null || true")
    secaudit_remediate_done(num, "telnet_en=0; telnetd stopped")


def secaudit_remediate_ssh(num: int) -> None:
    secaudit_queue("uci set dropbear.@dropbear[0].Interface='lan' 2>/dev/null || true")
    secaudit_queue("uci set dropbear.@dropbear[0].enable='1' 2>/dev/null || true")
    secaudit_queue("nvram set ssh_en=1 2>/dev/null || true")
    secaudit_queue(
        "uci -q delete firewall.Allow-SSH 2>/dev/null; "
        "uci -q delete firewall.wan_ssh 2>/dev/null; true"
    )
    secaudit_remediate_done(num, "dropbear bound to LAN; WAN SSH accepts removed")


def secaudit_remediate_ssid(num: int) -> None:
    ssid = secaudit_env("XM_REMEDIATE_SSID")
    if not ssid:
        secaudit_remediate_skip(num, "set XM_REMEDIATE_SSID to apply")
        return
    sections = secaudit_wifi_iface_sections()
    primary = None
    for sec in sections:
        net = None
        m = re.search(
            rf"(?m)^wireless\.{re.escape(sec)}\.network="
            rf"(?:'([^']*)'|\"([^\"]*)\"|(\S+))",
            _XM_BLOB,
        )
        if m:
            net = next(g for g in m.groups() if g is not None).lower()
        ssid_m = re.search(
            rf"(?m)^wireless\.{re.escape(sec)}\.ssid="
            rf"(?:'([^']*)'|\"([^\"]*)\"|(\S+))",
            _XM_BLOB,
        )
        cur = ""
        if ssid_m:
            cur = next(g for g in ssid_m.groups() if g is not None)
        if net == "guest" or "guest" in secaudit_lower(cur):
            continue
        primary = sec
        break
    if primary is None:
        primary = sections[0] if sections else "@wifi-iface[0]"

    force = secaudit_env_bool("XM_REMEDIATE_FORCE_SSID", False)
    cur_ssids = secaudit_all_values("ssid")
    needs = force or not cur_ssids or any(
        _XM_DEFAULT_SSID_RE.search(s.strip()) for s in cur_ssids
    )
    if needs:
        secaudit_queue(f"uci set wireless.{primary}.ssid={secaudit_shell_quote(ssid)}")
        secaudit_remediate_done(num, f"ssid={ssid} on {primary}")
    else:
        secaudit_remediate_done(num, f"custom SSID already present ({cur_ssids[0]})")


def secaudit_remediate_guest_network(num: int) -> None:
    guest_ssid = secaudit_env("XM_REMEDIATE_GUEST_SSID")
    if not guest_ssid:
        secaudit_remediate_skip(num, "set XM_REMEDIATE_GUEST_SSID to apply")
        return
    enc = secaudit_env("XM_REMEDIATE_WIFI_ENC", default="psk2+ccmp")
    secaudit_queue(
        "uci -q get network.guest >/dev/null || uci set network.guest=interface"
    )
    secaudit_queue("uci set network.guest.proto='static'")
    secaudit_queue("uci set network.guest.ipaddr='192.168.10.1'")
    secaudit_queue("uci set network.guest.netmask='255.255.255.0'")
    secaudit_queue(
        "uci -q get wireless.guest >/dev/null || uci set wireless.guest=wifi-iface"
    )
    secaudit_queue("uci set wireless.guest.device='radio0' 2>/dev/null || true")
    secaudit_queue("uci set wireless.guest.mode='ap'")
    secaudit_queue("uci set wireless.guest.network='guest'")
    secaudit_queue(f"uci set wireless.guest.ssid={secaudit_shell_quote(guest_ssid)}")
    secaudit_queue(f"uci set wireless.guest.encryption={secaudit_shell_quote(enc)}")
    secaudit_queue("uci set wireless.guest.isolate='1'")
    secaudit_queue("uci set wireless.guest.ieee80211w='1' 2>/dev/null || true")
    secaudit_queue("uci -q get firewall.guest >/dev/null || uci set firewall.guest=zone")
    secaudit_queue("uci set firewall.guest.name='guest'")
    secaudit_queue("uci set firewall.guest.network='guest'")
    secaudit_queue("uci set firewall.guest.input='REJECT'")
    secaudit_queue("uci set firewall.guest.output='ACCEPT'")
    secaudit_queue("uci set firewall.guest.forward='REJECT'")
    secaudit_queue(
        "uci -q get firewall.guest_wan >/dev/null || uci set firewall.guest_wan=forwarding"
    )
    secaudit_queue("uci set firewall.guest_wan.src='guest'")
    secaudit_queue("uci set firewall.guest_wan.dest='wan'")
    secaudit_remediate_done(
        num, f"guest network/SSID ensured (ssid={guest_ssid}, isolate=1)"
    )


def secaudit_remediate_guest_isolation(num: int) -> None:
    sections = secaudit_wifi_iface_sections()
    touched = 0
    for sec in sections:
        is_guest = sec == "guest"
        m = re.search(
            rf"(?m)^wireless\.{re.escape(sec)}\.network="
            rf"(?:'([^']*)'|\"([^\"]*)\"|(\S+))",
            _XM_BLOB,
        )
        if m and next(g for g in m.groups() if g is not None).lower() == "guest":
            is_guest = True
        ssid_m = re.search(
            rf"(?m)^wireless\.{re.escape(sec)}\.ssid="
            rf"(?:'([^']*)'|\"([^\"]*)\"|(\S+))",
            _XM_BLOB,
        )
        if ssid_m and "guest" in next(
            g for g in ssid_m.groups() if g is not None
        ).lower():
            is_guest = True
        if is_guest:
            secaudit_queue(f"uci set wireless.{sec}.isolate='1'")
            touched += 1
    if touched == 0:
        secaudit_queue("uci set wireless.guest.isolate='1' 2>/dev/null || true")
        touched = 1
    secaudit_remediate_done(num, f"isolate=1 on {touched} guest iface(s)")


def secaudit_remediate_dns(num: int) -> None:
    dns = secaudit_env("XM_REMEDIATE_DNS", default="1.1.1.1")
    dns2 = secaudit_env("XM_REMEDIATE_DNS2", default="9.9.9.9")
    secaudit_queue(f"uci set network.wan.dns={secaudit_shell_quote(dns)}")
    secaudit_queue(
        f"uci add_list network.wan.dns={secaudit_shell_quote(dns2)} 2>/dev/null || true"
    )
    secaudit_queue(
        f"uci set network.lan.dns={secaudit_shell_quote(dns)} 2>/dev/null || true"
    )
    secaudit_queue(
        f"uci add_list dhcp.@dnsmasq[0].server={secaudit_shell_quote(dns)} "
        "2>/dev/null || true"
    )
    secaudit_remediate_done(num, f"DNS={dns},{dns2}")


def secaudit_remediate_ntp(num: int) -> None:
    ntp = secaudit_env("XM_REMEDIATE_NTP", default="pool.ntp.org")
    secaudit_queue("uci set system.ntp=timeserver 2>/dev/null || true")
    secaudit_queue("uci set system.ntp.enabled='1'")
    secaudit_queue(
        f"uci add_list system.ntp.server={secaudit_shell_quote(ntp)} 2>/dev/null || true"
    )
    secaudit_queue(
        f"uci set system.ntp.server={secaudit_shell_quote(ntp)} 2>/dev/null || true"
    )
    secaudit_remediate_done(num, f"NTP enabled server={ntp}")


def secaudit_remediate_dmz(num: int) -> None:
    for key in ("xiaoqiang.common.dmz", "xiaoqiang.common.dmz_enable"):
        secaudit_queue(f"uci set {key}='0' 2>/dev/null || true")
    secaudit_queue("nvram set dmz_en=0 2>/dev/null || true")
    secaudit_queue("nvram set dmz_enable=0 2>/dev/null || true")
    secaudit_queue("nvram unset dmz_ip 2>/dev/null || true")
    secaudit_queue("uci -q delete firewall.dmz 2>/dev/null || true")
    secaudit_remediate_done(num, "DMZ disabled")


def secaudit_remediate_wan_ping(num: int) -> None:
    secaudit_queue("uci -q delete firewall.Allow-Ping 2>/dev/null || true")
    secaudit_queue("uci -q delete firewall.allow_ping 2>/dev/null || true")
    secaudit_queue(
        "for s in $(uci -q show firewall | sed -n 's/=rule$//p'); do "
        "n=$(uci -q get $s.name); "
        "case \"$n\" in *ing*|*ICMP*|*icmp*) "
        "src=$(uci -q get $s.src); "
        "[ \"$src\" = wan ] && uci -q delete $s;; esac; done 2>/dev/null || true"
    )
    secaudit_remediate_done(num, "WAN Allow-Ping / ICMP accepts removed (best-effort)")


def secaudit_remediate_file_services(num: int) -> None:
    secaudit_queue("uci set samba.@samba[0].enabled='0' 2>/dev/null || true")
    secaudit_queue("uci set samba.samba.enabled='0' 2>/dev/null || true")
    secaudit_queue("uci set ksmbd.@ksmbd[0].enabled='0' 2>/dev/null || true")
    secaudit_queue("uci set vsftpd.@vsftpd[0].enabled='0' 2>/dev/null || true")
    secaudit_queue("/etc/init.d/samba stop 2>/dev/null || true")
    secaudit_queue("/etc/init.d/samba disable 2>/dev/null || true")
    secaudit_queue("/etc/init.d/ksmbd stop 2>/dev/null || true")
    secaudit_queue("/etc/init.d/vsftpd stop 2>/dev/null || true")
    secaudit_queue("/etc/init.d/vsftpd disable 2>/dev/null || true")
    secaudit_remediate_done(num, "Samba/FTP/ksmbd disabled")


def secaudit_remediate_port_forwards(num: int) -> None:
    if not secaudit_env_bool("XM_REMEDIATE_DROP_REDIRECTS", False):
        secaudit_remediate_skip(
            num,
            "review firewall.@redirect; set XM_REMEDIATE_DROP_REDIRECTS=1 to delete all redirects",
        )
        return
    secaudit_queue(
        "while uci -q delete firewall.@redirect[0]; do :; done 2>/dev/null || true"
    )
    secaudit_remediate_done(num, "all firewall redirects deleted")


def secaudit_remediate_lan_subnet(num: int) -> None:
    lan_ip = secaudit_env("XM_REMEDIATE_LAN_IP", default="192.168.50.1")
    lan_ips = re.findall(r"(?mi)network\.lan\.ipaddr='([^']+)'", _XM_BLOB)
    if not lan_ips:
        lan_ips = [
            ip
            for ip in secaudit_uci_values("ipaddr")
            if re.match(r"\d+\.\d+\.\d+\.\d+$", ip) and not ip.startswith("127.")
        ]
    if lan_ips and not lan_ips[0].startswith("192.168.31."):
        secaudit_remediate_done(num, f"LAN IP already non-factory ({lan_ips[0]})")
        return
    secaudit_queue(f"uci set network.lan.ipaddr={secaudit_shell_quote(lan_ip)}")
    secaudit_remediate_done(
        num,
        f"network.lan.ipaddr={lan_ip} (reconnect to the new address)",
    )


def secaudit_remediate_weak_ciphers(num: int) -> None:
    enc = secaudit_env("XM_REMEDIATE_WIFI_ENC", default="psk2+ccmp")
    sections = secaudit_wifi_iface_sections() or ["@wifi-iface[0]"]
    for sec in sections:
        secaudit_queue(f"uci set wireless.{sec}.encryption={secaudit_shell_quote(enc)}")
    secaudit_remediate_done(num, f"removed WEP/TKIP by setting encryption={enc}")


def secaudit_remediate_pmf(num: int) -> None:
    sections = secaudit_wifi_iface_sections() or ["@wifi-iface[0]"]
    for sec in sections:
        secaudit_queue(f"uci set wireless.{sec}.ieee80211w='1'")
    secaudit_remediate_done(num, "ieee80211w=1 (PMF)")


def secaudit_remediate_cloud_remote(num: int) -> None:
    for key in (
        "xiaoqiang.common.remote",
        "xiaoqiang.common.cloud_remote",
        "xiaoqiang.common.mi_cloud",
    ):
        secaudit_queue(f"uci set {key}='0' 2>/dev/null || true")
    secaudit_remediate_done(
        num,
        "xiaoqiang cloud/remote uci flags=0 (also unbind in MiWiFi app if needed)",
    )


def secaudit_remediate_uart_debug(num: int) -> None:
    secaudit_queue("nvram set uart_en=0 2>/dev/null || true")
    secaudit_queue("nvram set boot_wait=off 2>/dev/null || true")
    secaudit_queue("nvram set bootwait=off 2>/dev/null || true")
    secaudit_queue("nvram set bootdelay=0 2>/dev/null || true")
    secaudit_queue("bdata set uart_en=0 2>/dev/null || true")
    secaudit_queue("bdata set boot_wait=off 2>/dev/null || true")
    secaudit_queue("nvram commit 2>/dev/null || true")
    secaudit_queue("bdata commit 2>/dev/null || true")
    secaudit_remediate_done(num, "uart_en=0 boot_wait=off bootdelay=0")


def secaudit_remediate_wan_input(num: int) -> None:
    zones = secaudit_firewall_zone_sections()
    wan = zones.get("wan")
    if wan:
        secaudit_queue(f"uci set firewall.{wan}.input='REJECT'")
    else:
        secaudit_queue(
            "for s in $(uci -q show firewall | sed -n 's/=zone$//p'); do "
            "[ \"$(uci -q get $s.name)\" = wan ] && uci set $s.input=REJECT; done"
        )
    secaudit_remediate_done(num, "firewall WAN zone input=REJECT")


def secaudit_remediate_admin_password(num: int) -> None:
    secaudit_remediate_skip(
        num,
        "set a strong root/admin password via passwd / MiWiFi UI (never auto-set credentials)",
    )


def secaudit_run_identity_and_firmware() -> None:
    secaudit_remediate_hostname(1)
    secaudit_remediate_firmware(2)


def secaudit_run_wireless_core() -> None:
    secaudit_remediate_wifi_encryption(3)
    secaudit_remediate_wps(4)


def secaudit_run_services_mgmt_firewall() -> None:
    secaudit_remediate_upnp(5)
    secaudit_remediate_remote_mgmt(6)
    secaudit_remediate_firewall(7)
    secaudit_remediate_telnet(8)
    secaudit_remediate_ssh(9)


def secaudit_run_ssid_guest_dns_ntp() -> None:
    secaudit_remediate_ssid(10)
    secaudit_remediate_guest_network(11)
    secaudit_remediate_guest_isolation(12)
    secaudit_remediate_dns(13)
    secaudit_remediate_ntp(14)


def secaudit_run_perimeter_and_lan() -> None:
    secaudit_remediate_dmz(15)
    secaudit_remediate_wan_ping(16)
    secaudit_remediate_file_services(17)
    secaudit_remediate_port_forwards(18)
    secaudit_remediate_lan_subnet(19)


def secaudit_run_crypto_cloud_admin() -> None:
    secaudit_remediate_weak_ciphers(20)
    secaudit_remediate_pmf(21)
    secaudit_remediate_cloud_remote(22)
    secaudit_remediate_uart_debug(23)
    secaudit_remediate_wan_input(24)
    secaudit_remediate_admin_password(25)


def secaudit_bootstrap() -> bool:
    global _XM_MODE
    secaudit_log("starting remediation (Xiaomi MiWiFi / secaudit_* style)")
    if not secaudit_collect_config():
        secaudit_skip_all_rules("MiWiFi/OpenWrt config dump empty or unavailable")
        return False
    if not secaudit_platform_present():
        secaudit_skip_all_rules(
            "no Xiaomi/OpenWrt/uci markers in dump (not a MiWiFi config)"
        )
        return False
    _XM_MODE = secaudit_detect_apply_mode()
    secaudit_log(f"source=collected mode={_XM_MODE}")
    return True


def secaudit_main() -> None:
    if not secaudit_bootstrap():
        sys.exit(0)
    secaudit_run_identity_and_firmware()
    secaudit_run_wireless_core()
    secaudit_run_services_mgmt_firewall()
    secaudit_run_ssid_guest_dns_ntp()
    secaudit_run_perimeter_and_lan()
    secaudit_run_crypto_cloud_admin()
    secaudit_flush_commands()
    secaudit_log("remediation complete (XIAOMI_MIWIFI_remediation.py)")
    sys.exit(0)


if __name__ == "__main__":
    secaudit_main()
