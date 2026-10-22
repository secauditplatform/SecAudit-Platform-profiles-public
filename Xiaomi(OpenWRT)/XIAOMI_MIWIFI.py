#!/usr/bin/env python3
"""Xiaomi MiWiFi (OpenWrt-like) security configuration audit."""

from __future__ import annotations

import re
import sys
from typing import Iterable

from remote_access import fetch_config_lines


_XM_RULE_COUNT = 25

_XM_SHOW_COMMAND = (
    "PATH=/sbin:/bin:/usr/sbin:/usr/bin; "
    "uci show 2>/dev/null; "
    "echo __FILE__/etc/openwrt_release; cat /etc/openwrt_release 2>/dev/null; "
    "echo __FILE__/etc/shadow; cat /etc/shadow 2>/dev/null; "
    "for f in wireless firewall upnpd dropbear system dhcp network samba vsftpd "
    "xiaoqiang misc luci; do "
    "echo __FILE__/etc/config/$f; cat /etc/config/$f 2>/dev/null; "
    "done; "
    "echo __NVRAM__; "
    "(nvram show 2>/dev/null || true); "
    "(bdata show 2>/dev/null || true)"
)

_XM_SECURE_WIFI = frozenset(
    {
        "psk2",
        "psk2+ccmp",
        "psk2+aes",
        "ccmp",
        "sae",
        "sae-mixed",
        "wpa3",
        "wpa3-mixed",
        "wpa2",
        "wpa2+ccmp",
    }
)

_XM_WEAK_WIFI_MARKERS = ("wep", "tkip", "psk+", "+tkip")

_XM_DEFAULT_SSID_RE = re.compile(
    r"^(xiaomi|miwifi|mi[\s_-]?router|xiaomi[\s_-]?router)",
    re.IGNORECASE,
)

_XM_DEFAULT_HOSTNAMES = frozenset(
    {
        "xiaomi",
        "miwifi",
        "mi-wifi",
        "openwrt",
        "xiaoqiang",
        "router",
        "localhost",
    }
)

_XM_PLATFORM_MARKERS_RE = re.compile(
    r"(?i)(?:\buci\b|DISTRIB_|openwrt|miwifi|xiaoqiang|wireless\.|network\.lan|"
    r"config\s+wifi-iface|config\s+zone|dropbear|nvram|bdata)",
)


_XM_BLOB = ""
_XM_LINES: list[str] = []
_XM_SOURCE = "none"


def secaudit_report_pass(num: int | str, detail: str) -> None:
    print(f"RULE{num}= PASS: {detail}")


def secaudit_report_fail(num: int | str, detail: str) -> None:
    print(f"RULE{num}= FAIL: {detail}")


def secaudit_report_skip(num: int | str, detail: str) -> None:
    print(f"RULE{num}= SKIP: {detail}")


def secaudit_report_error(num: int | str, detail: str) -> None:
    print(f"RULE{num}= ERROR: {detail}")


def secaudit_skip_all_rules(reason: str) -> None:
    for n in range(1, _XM_RULE_COUNT + 1):
        secaudit_report_skip(n, reason)


def secaudit_trim(value: str | None) -> str:
    return (value or "").strip()


def secaudit_lower(value: str | None) -> str:
    return secaudit_trim(value).lower()


def secaudit_norm_lines(lines: Iterable[str]) -> list[str]:
    return [ln.rstrip("\r\n") for ln in lines]


def secaudit_truthy(val: str | None) -> bool:
    return secaudit_lower(val) in {"1", "true", "yes", "on", "enabled"}


def secaudit_falsey(val: str | None) -> bool:
    return secaudit_lower(val) in {"0", "false", "no", "off", "disabled"}


def secaudit_blob_has(*needles: str, flags: int = re.IGNORECASE) -> bool:
    return any(re.search(n, _XM_BLOB, flags) for n in needles)


def secaudit_uci_values(key_suffix: str) -> list[str]:
    """Extract values for keys ending with .suffix='value' (uci show)."""
    pattern = re.compile(
        rf"(?m)^[^\n]*\.{re.escape(key_suffix)}=(?:'([^']*)'|\"([^\"]*)\"|([^\s]+))"
    )
    out: list[str] = []
    for match in pattern.finditer(_XM_BLOB):
        val = next(g for g in match.groups() if g is not None)
        out.append(val.strip())
    return out


def secaudit_option_values(option: str) -> list[str]:
    """Extract `option name 'value'` from OpenWrt config syntax."""
    pattern = re.compile(
        rf"(?mi)^\s*option\s+{re.escape(option)}\s+(?:'([^']*)'|\"([^\"]*)\"|(\S+))"
    )
    out: list[str] = []
    for match in pattern.finditer(_XM_BLOB):
        val = next(g for g in match.groups() if g is not None)
        out.append(val.strip())
    return out


def secaudit_kv_values(key: str) -> list[str]:
    """Extract key=value (nvram/bdata) forms."""
    pattern = re.compile(
        rf"(?mi)^(?:{re.escape(key)})=(?:'([^']*)'|\"([^\"]*)\"|(\S+))"
    )
    out: list[str] = []
    for match in pattern.finditer(_XM_BLOB):
        val = next(g for g in match.groups() if g is not None)
        out.append(val.strip())
    return out


def secaudit_all_values(name: str) -> list[str]:
    vals = (
        secaudit_uci_values(name)
        + secaudit_option_values(name)
        + secaudit_kv_values(name)
    )
    return [v for v in vals if v != ""]


def secaudit_wifi_encryptions() -> list[str]:
    return [v.lower() for v in secaudit_all_values("encryption")]


def secaudit_guest_present() -> bool:
    if secaudit_blob_has(
        r"(?mi)(?:network\.guest|config\s+interface\s+'guest'|wifi-iface.*guest|"
        r"ssid\s+'[^']*guest|option\s+network\s+'guest')"
    ):
        return True
    return any("guest" in s.lower() for s in secaudit_all_values("ssid"))


def secaudit_platform_present() -> bool:
    if not secaudit_trim(_XM_BLOB):
        return False
    return bool(_XM_PLATFORM_MARKERS_RE.search(_XM_BLOB))


def secaudit_collect_config() -> bool:
    """Fetch dump via file or SSH; populate runtime blob."""
    global _XM_BLOB, _XM_LINES, _XM_SOURCE
    try:
        raw = fetch_config_lines(device_type="linux", show_command=_XM_SHOW_COMMAND)
    except SystemExit:
        raise
    except Exception as exc:
        _XM_BLOB = ""
        _XM_LINES = []
        _XM_SOURCE = "error"
        print(
            f'{{"errorCode":"COLLECT_ERROR","errorMessage":"{type(exc).__name__}: {exc}"}}',
            file=sys.stderr,
        )
        return False

    _XM_LINES = secaudit_norm_lines(raw)
    _XM_BLOB = "\n".join(_XM_LINES)
    if not secaudit_trim(_XM_BLOB):
        _XM_SOURCE = "empty"
        return False
    _XM_SOURCE = "collected"
    return True


def secaudit_bootstrap() -> bool:
    if not secaudit_collect_config():
        secaudit_skip_all_rules("MiWiFi/OpenWrt config dump empty or unavailable")
        return False
    if not secaudit_platform_present():
        secaudit_skip_all_rules(
            "no Xiaomi/OpenWrt/uci markers in dump (not a MiWiFi config)"
        )
        return False
    return True


def secaudit_check_hostname(num: int) -> None:
    hosts = secaudit_all_values("hostname")
    if not hosts:
        secaudit_report_fail(num, "hostname not found in config")
        return
    bad = [h for h in hosts if secaudit_lower(h) in _XM_DEFAULT_HOSTNAMES or not h.strip()]
    if bad:
        secaudit_report_fail(num, f"default/empty hostname: {', '.join(bad)}")
        return
    secaudit_report_pass(num, f"hostname set: {hosts[0]}")


def secaudit_check_firmware(num: int) -> None:
    markers: list[str] = []
    for pattern in (
        r"(?mi)^DISTRIB_RELEASE=['\"]?([^\s'\"]+)",
        r"(?mi)^DISTRIB_REVISION=['\"]?([^\s'\"]+)",
        r"(?mi)(?:firmware|rom|version)[=:]['\"]?([0-9][^\s'\"]+)",
        r"(?mi)^xiaoqiang\.[^=]*version='([^']+)'",
    ):
        for match in re.finditer(pattern, _XM_BLOB):
            markers.append(match.group(1))
    if markers:
        uniq = list(dict.fromkeys(markers))[:5]
        secaudit_report_pass(num, f"firmware markers present: {', '.join(uniq)}")
        return
    if secaudit_blob_has(r"DISTRIB_|openwrt_release|miwifi|xiaoqiang"):
        secaudit_report_pass(
            num, "platform release markers found; verify update status manually"
        )
        return
    secaudit_report_fail(
        num, "firmware/version markers not found — cannot confirm patch level"
    )


def secaudit_check_wifi_encryption(num: int) -> None:
    encs = secaudit_wifi_encryptions()
    if not encs:
        secaudit_report_fail(num, "no wireless encryption settings found")
        return
    bad = [
        e
        for e in encs
        if e in {"none", "wep", "psk", "open"} or e.startswith("wep")
    ]
    weakish = [e for e in encs if e not in _XM_SECURE_WIFI and e not in bad]
    if bad:
        secaudit_report_fail(num, f"insecure encryption: {', '.join(sorted(set(bad)))}")
        return
    if weakish:
        secaudit_report_fail(
            num, f"non-approved encryption modes: {', '.join(sorted(set(weakish)))}"
        )
        return
    secaudit_report_pass(num, f"secure encryption in use: {', '.join(sorted(set(encs)))}")


def secaudit_check_wps(num: int) -> None:
    enabled_flags: list[str] = []
    for key in ("wps_pushbutton", "wps_label", "wps_config", "wps_pbc", "wps"):
        for val in secaudit_all_values(key):
            if secaudit_truthy(val) or val.lower() in {"push_button", "label", "1"}:
                enabled_flags.append(f"{key}={val}")
    if secaudit_blob_has(
        r"wps[_-]?(?:enable|enabled)\s*[=:]?\s*['\"]?(?:1|true|yes|on)"
    ):
        enabled_flags.append("wps_enabled")
    if enabled_flags:
        secaudit_report_fail(num, f"WPS appears enabled: {', '.join(enabled_flags)}")
        return
    if secaudit_blob_has(r"wireless\.|config\s+wifi-iface|option\s+ssid"):
        secaudit_report_pass(num, "no enabled WPS flags detected")
        return
    secaudit_report_fail(num, "wireless section missing; cannot verify WPS")


def secaudit_check_ssid(num: int) -> None:
    ssids = secaudit_all_values("ssid")
    if not ssids:
        secaudit_report_fail(num, "no SSID found")
        return
    bad = [s for s in ssids if _XM_DEFAULT_SSID_RE.search(s.strip())]
    if bad:
        secaudit_report_fail(num, f"default-like SSID: {', '.join(bad)}")
        return
    secaudit_report_pass(num, f"custom SSID(s): {', '.join(ssids[:4])}")


def secaudit_check_guest_network(num: int) -> None:
    if secaudit_guest_present():
        secaudit_report_pass(num, "guest network/SSID detected")
        return
    secaudit_report_fail(num, "guest network not configured")


def secaudit_check_guest_isolation(num: int) -> None:
    if not secaudit_guest_present():
        secaudit_report_fail(num, "guest network missing — isolation N/A")
        return
    isolates = secaudit_all_values("isolate")
    if any(secaudit_truthy(v) for v in isolates):
        secaudit_report_pass(num, "client isolation enabled")
        return
    if any(secaudit_truthy(v) for v in secaudit_all_values("ap_isolate")):
        secaudit_report_pass(num, "ap_isolate enabled")
        return
    secaudit_report_fail(num, "guest present but isolate not enabled")


def secaudit_check_weak_ciphers(num: int) -> None:
    encs = secaudit_wifi_encryptions()
    if not encs:
        secaudit_report_fail(num, "no encryption settings to evaluate")
        return
    weak = [
        e
        for e in encs
        if any(m in e for m in _XM_WEAK_WIFI_MARKERS) or e in {"wep", "psk"}
    ]
    if weak:
        secaudit_report_fail(num, f"weak ciphers/modes: {', '.join(sorted(set(weak)))}")
        return
    secaudit_report_pass(num, "no WEP/TKIP/WPA-TKIP modes detected")


def secaudit_check_pmf(num: int) -> None:
    vals = secaudit_all_values("ieee80211w")
    encs = secaudit_wifi_encryptions()
    uses_modern = any(
        e in {"sae", "sae-mixed", "wpa3", "psk2", "psk2+ccmp"} for e in encs
    )
    if any(v.strip() in {"1", "2"} for v in vals):
        secaudit_report_pass(num, f"ieee80211w={vals[0]}")
        return
    if uses_modern:
        secaudit_report_fail(num, "modern Wi-Fi without ieee80211w/PMF")
        return
    if not encs:
        secaudit_report_fail(num, "cannot evaluate PMF without wireless config")
        return
    secaudit_report_fail(num, "PMF not enabled")


def secaudit_check_upnp(num: int) -> None:
    upnp_enabled = False
    if re.search(r"(?mi)^upnpd\.[^=]*enabled='1'", _XM_BLOB):
        upnp_enabled = True
    if re.search(
        r"(?is)upnpd[\s\S]{0,200}(?:enabled|enable)\s*[=']+\s*['\"]?1", _XM_BLOB
    ):
        upnp_enabled = True
    if upnp_enabled:
        secaudit_report_fail(num, "UPnP/miniupnpd enabled")
        return
    if secaudit_blob_has(r"upnpd|miniupnpd|config\s+upnpd"):
        if re.search(
            r"(?mi)upnpd\.[^=]*enabled='0'|option\s+enabled\s+'0'", _XM_BLOB
        ):
            secaudit_report_pass(num, "UPnP explicitly disabled")
            return
        secaudit_report_pass(num, "UPnP config present without enable=1")
        return
    secaudit_report_pass(num, "UPnP config not present (assumed disabled)")


def secaudit_check_remote_management(num: int) -> None:
    findings: list[str] = []
    if re.search(
        r"(?mi)(?:remote_management|remote_access|wan_admin|web_wan|remote_web)"
        r"\s*[=:]\s*['\"]?(?:1|true|yes|on)",
        _XM_BLOB,
    ):
        findings.append("remote management flag enabled")
    if re.search(
        r"(?mi)xiaoqiang\.[^=]*(?:remote|wan_manage|cloud_remote)[^=]*='1'", _XM_BLOB
    ):
        findings.append("xiaoqiang remote/cloud flag enabled")
    if re.search(
        r"(?is)src[=']+wan[\s\S]{0,120}dest_port[=']+(?:80|443|8080|8443|22|23|8291)"
        r"[\s\S]{0,80}(?:ACCEPT|accept)",
        _XM_BLOB,
    ) or re.search(
        r"(?is)(?:ACCEPT|accept)[\s\S]{0,80}src[=']+wan[\s\S]{0,120}"
        r"dest_port[=']+(?:80|443|8080|8443|22|23)",
        _XM_BLOB,
    ):
        findings.append("firewall ACCEPT from wan to management ports")
    if findings:
        secaudit_report_fail(num, "; ".join(findings))
        return
    secaudit_report_pass(num, "no WAN remote management indicators found")


def secaudit_check_telnet(num: int) -> None:
    telnet_vals = secaudit_kv_values("telnet_en") + secaudit_all_values("telnet_en")
    if any(secaudit_truthy(v) for v in telnet_vals):
        secaudit_report_fail(num, "telnet_en=1")
        return
    if secaudit_blob_has(r"(?mi)telnetd|service\s+telnet\b.*enable"):
        if re.search(r"(?mi)telnet.*disabled|disable.*telnet", _XM_BLOB):
            secaudit_report_pass(num, "telnet disabled by config")
            return
        secaudit_report_fail(num, "telnet service references found without disable")
        return
    if telnet_vals and all(secaudit_falsey(v) for v in telnet_vals):
        secaudit_report_pass(num, "telnet_en=0")
        return
    secaudit_report_pass(num, "telnet not enabled")


def secaudit_check_ssh(num: int) -> None:
    ssh_en = secaudit_kv_values("ssh_en") + secaudit_all_values("ssh_en")
    wan_ssh = bool(
        re.search(
            r"(?is)src[=']+wan[\s\S]{0,120}dest_port[=']+22[\s\S]{0,80}(?:ACCEPT|accept)",
            _XM_BLOB,
        )
    )
    if wan_ssh:
        secaudit_report_fail(num, "SSH allowed from WAN (firewall)")
        return
    if ssh_en and all(secaudit_falsey(v) for v in ssh_en):
        secaudit_report_pass(num, "ssh_en=0")
        return
    interfaces = [
        v.lower()
        for v in secaudit_all_values("Interface") + secaudit_all_values("interface")
    ]
    lan_only = any(v in {"lan", "br-lan", "br_lan"} for v in interfaces)
    if any(secaudit_truthy(v) for v in ssh_en) or secaudit_blob_has(r"dropbear"):
        if lan_only:
            secaudit_report_pass(num, "SSH present but bound to LAN interface")
            return
        if not wan_ssh:
            secaudit_report_pass(
                num, "SSH enabled without WAN firewall accept (ensure LAN-only)"
            )
            return
        secaudit_report_fail(num, "SSH enabled without LAN restriction")
        return
    secaudit_report_pass(num, "SSH not enabled / dropbear absent")


def secaudit_check_file_services(num: int) -> None:
    findings: list[str] = []
    if re.search(
        r"(?mi)(?:samba|ksmbd)[\s\S]{0,120}(?:enabled|enable)\s*[=']+\s*['\"]?1",
        _XM_BLOB,
    ):
        findings.append("samba enabled")
    if re.search(
        r"(?mi)(?:vsftpd|proftpd|pure-ftpd)[\s\S]{0,120}(?:enabled|enable)\s*[=']+\s*['\"]?1",
        _XM_BLOB,
    ):
        findings.append("ftp enabled")
    if re.search(r"(?mi)^(?:samba|vsftpd)\.[^=]*enabled='1'", _XM_BLOB):
        findings.append("file service enabled via uci")
    if findings:
        secaudit_report_fail(num, "; ".join(findings))
        return
    secaudit_report_pass(num, "Samba/FTP not enabled")


def secaudit_check_cloud_remote(num: int) -> None:
    if re.search(
        r"(?mi)(?:cloud_remote|remote_cloud|mi_cloud|bind_status|countrycode_remote)"
        r"\s*[=:]\s*['\"]?(?:1|true|yes|binded|bound)",
        _XM_BLOB,
    ):
        secaudit_report_fail(num, "cloud/remote bind indicators enabled")
        return
    if re.search(r"(?mi)xiaoqiang\.[^=]*(?:remote|cloud)[^=]*='1'", _XM_BLOB):
        secaudit_report_fail(num, "xiaoqiang cloud/remote enabled")
        return
    secaudit_report_pass(num, "no cloud remote enable flags found")


def secaudit_check_uart_debug(num: int) -> None:
    findings: list[str] = []
    for key in ("uart_en", "boot_wait", "bootwait", "bootdelay"):
        vals = secaudit_kv_values(key) + secaudit_all_values(key)
        for v in vals:
            if key == "uart_en" and secaudit_truthy(v):
                findings.append(f"{key}={v}")
            if key in {"boot_wait", "bootwait"} and v.lower() in {
                "on",
                "1",
                "yes",
                "true",
            }:
                findings.append(f"{key}={v}")
            if key == "bootdelay":
                try:
                    if int(v) > 0:
                        findings.append(f"{key}={v}")
                except ValueError:
                    pass
    if findings:
        secaudit_report_fail(
            num, "debug boot/UART flags: " + ", ".join(dict.fromkeys(findings))
        )
        return
    secaudit_report_pass(num, "UART/boot debug flags not enabled")


def secaudit_check_admin_password(num: int) -> None:
    shadow = re.search(r"(?m)^root:([^:]*):", _XM_BLOB)
    if shadow:
        hashed = shadow.group(1)
        if hashed in {"", "*", "!", "!!"}:
            secaudit_report_fail(num, "root password empty/locked without hash")
            return
        if hashed.startswith(("x", "$")) or len(hashed) >= 8:
            secaudit_report_pass(num, "root password hash present")
            return
        secaudit_report_fail(num, "root password hash looks invalid")
        return
    if re.search(r"(?mi)(?:admin_password|syspwd|password)\s*=\s*['\"]?$", _XM_BLOB):
        secaudit_report_fail(num, "empty admin password field")
        return
    if secaudit_blob_has(
        r"(?mi)password\s*=\s*['\"]?(admin|root|password|12345678)['\"]?$"
    ):
        secaudit_report_fail(num, "weak/default password marker found")
        return
    if secaudit_blob_has(r"wireless\.|network\.lan"):
        secaudit_report_fail(
            num,
            "cannot confirm admin password (no /etc/shadow in dump) — verify manually",
        )
        return
    secaudit_report_fail(num, "insufficient data to verify admin password")


def secaudit_check_firewall(num: int) -> None:
    if not secaudit_blob_has(r"firewall\.|config\s+defaults|config\s+zone"):
        secaudit_report_fail(num, "firewall configuration not found")
        return
    syn = secaudit_all_values("syn_flood") + secaudit_all_values("synflood_protect")
    input_default = [v.lower() for v in secaudit_all_values("input")]
    ok_bits: list[str] = []
    if any(secaudit_truthy(v) for v in syn):
        ok_bits.append("syn_flood on")
    if any(v in {"reject", "drop"} for v in input_default):
        ok_bits.append(f"defaults.input={input_default[0]}")
    if ok_bits:
        secaudit_report_pass(num, "firewall present: " + ", ".join(ok_bits))
        return
    if secaudit_blob_has(r"config\s+zone|firewall\.@zone|firewall\.wan"):
        secaudit_report_pass(num, "firewall zones present")
        return
    secaudit_report_fail(num, "firewall incomplete")


def secaudit_check_dns(num: int) -> None:
    servers: list[str] = []
    servers.extend(re.findall(r"(?mi)network\.(?:wan|lan)\.dns='([^']+)'", _XM_BLOB))
    servers.extend(re.findall(r"(?mi)dhcp\.[^=]*\.server='([^']+)'", _XM_BLOB))
    servers.extend(re.findall(r"(?mi)list\s+server\s+'([^']+)'", _XM_BLOB))
    servers.extend(re.findall(r"(?mi)option\s+dns\s+'([^']+)'", _XM_BLOB))
    servers = [s.strip() for s in servers if s.strip()]
    if servers:
        uniq = list(dict.fromkeys(servers))[:6]
        secaudit_report_pass(num, f"DNS configured: {', '.join(uniq)}")
        return
    secaudit_report_fail(num, "no explicit DNS servers configured")


def secaudit_check_ntp(num: int) -> None:
    if re.search(
        r"(?mi)system\.ntp\.enabled='0'|system\.ntp[^\n]*enabled='0'", _XM_BLOB
    ):
        secaudit_report_fail(num, "NTP disabled")
        return
    if re.search(
        r"(?is)config\s+timeserver[\s\S]{0,200}?option\s+enabled\s+'0'", _XM_BLOB
    ):
        secaudit_report_fail(num, "NTP disabled")
        return
    ntp_servers = re.findall(
        r"(?mi)(?:system\.ntp\.(?:server|list)|list\s+server)=(?:'|\"|)(\S+)",
        _XM_BLOB,
    )
    if re.search(r"(?is)system\.ntp|config\s+timeserver|config\s+ntp", _XM_BLOB):
        if ntp_servers or secaudit_blob_has(r"pool\.ntp|\.ntp\.|ntp\.org"):
            secaudit_report_pass(num, "NTP configured")
            return
        if re.search(r"(?mi)system\.ntp\.enabled='1'", _XM_BLOB):
            secaudit_report_pass(num, "NTP enabled")
            return
        secaudit_report_pass(num, "NTP section present")
        return
    if secaudit_blob_has(r"\bntp\b"):
        secaudit_report_pass(num, "ntp references found")
        return
    secaudit_report_fail(num, "NTP not configured")


def secaudit_check_dmz(num: int) -> None:
    if re.search(
        r"(?mi)(?:dmz_enable|dmz_en|enable_dmz)\s*[=:]\s*['\"]?(?:1|true|yes|on)",
        _XM_BLOB,
    ):
        secaudit_report_fail(num, "DMZ enabled")
        return
    if re.search(r"(?mi)xiaoqiang\.[^=]*dmz[^=]*='1'", _XM_BLOB):
        secaudit_report_fail(num, "xiaoqiang DMZ enabled")
        return
    dmz_ip = (
        secaudit_all_values("dmz")
        + secaudit_all_values("dmz_ip")
        + secaudit_kv_values("dmz_ip")
    )
    if any(re.match(r"\d+\.\d+\.\d+\.\d+", v) for v in dmz_ip):
        secaudit_report_fail(num, f"DMZ host set: {dmz_ip[0]}")
        return
    secaudit_report_pass(num, "DMZ not enabled")


def secaudit_check_wan_ping(num: int) -> None:
    if re.search(
        r"(?is)(?:Allow-Ping|Allow[-_ ]Ping|ping)[\s\S]{0,200}src[=']+wan"
        r"[\s\S]{0,120}(?:target|action)\s*[=']+\s*(?:ACCEPT|accept)",
        _XM_BLOB,
    ) or re.search(
        r"(?is)src[=']+wan[\s\S]{0,80}icmp[\s\S]{0,80}(?:ACCEPT|accept)",
        _XM_BLOB,
    ):
        secaudit_report_fail(num, "WAN ICMP/ping accepted")
        return
    secaudit_report_pass(num, "no WAN ping accept rule detected")


def secaudit_check_port_forwards(num: int) -> None:
    redirects = re.findall(
        r"(?mi)^firewall\.[^=]*redirect|^config\s+redirect\b", _XM_BLOB
    )
    count = len(redirects)
    if count == 0:
        secaudit_report_pass(num, "no port forwards configured")
        return
    if count <= 3:
        secaudit_report_pass(num, f"limited port forwards: {count} (review necessity)")
        return
    secaudit_report_fail(num, f"excessive port forwards detected: {count}")


def secaudit_check_lan_subnet(num: int) -> None:
    ips = secaudit_all_values("ipaddr")
    lan_ips = re.findall(r"(?mi)network\.lan\.ipaddr='([^']+)'", _XM_BLOB)
    if not lan_ips:
        lan_ips = [
            ip
            for ip in ips
            if re.match(r"\d+\.\d+\.\d+\.\d+$", ip) and not ip.startswith("127.")
        ]
    if not lan_ips:
        secaudit_report_fail(num, "LAN ipaddr not found")
        return
    bad = [ip for ip in lan_ips if ip.startswith("192.168.31.")]
    if bad:
        secaudit_report_fail(num, f"factory Xiaomi LAN subnet in use: {bad[0]}")
        return
    secaudit_report_pass(num, f"LAN IP: {lan_ips[0]}")


def secaudit_check_wan_input(num: int) -> None:
    wan_inputs = re.findall(
        r"(?is)(?:firewall\.[^=\n]*name='wan'[\s\S]{0,200}?input='([^']+)')|"
        r"(?:config\s+zone[\s\S]{0,120}?option\s+name\s+'wan'[\s\S]{0,200}?"
        r"option\s+input\s+'([^']+)')",
        _XM_BLOB,
    )
    values = [a or b for a, b in wan_inputs]
    if not values:
        m = re.search(
            r"(?is)name['\s=]+wan[\s\S]{0,180}?input['\s=]+['\"]?(reject|drop|accept)",
            _XM_BLOB,
        )
        if m:
            values = [m.group(1)]
    if not values:
        if secaudit_blob_has(r"firewall"):
            secaudit_report_fail(num, "WAN zone input policy not found")
            return
        secaudit_report_fail(num, "firewall config missing")
        return
    bad = [v for v in values if v.lower() == "accept"]
    if bad:
        secaudit_report_fail(num, "WAN input=ACCEPT")
        return
    secaudit_report_pass(num, f"WAN input={values[0]}")


def secaudit_run_identity_and_firmware() -> None:
    secaudit_check_hostname(1)
    secaudit_check_firmware(2)


def secaudit_run_wireless_core() -> None:
    secaudit_check_wifi_encryption(3)
    secaudit_check_wps(4)


def secaudit_run_services_mgmt_firewall() -> None:
    secaudit_check_upnp(5)
    secaudit_check_remote_management(6)
    secaudit_check_firewall(7)
    secaudit_check_telnet(8)
    secaudit_check_ssh(9)


def secaudit_run_ssid_guest_dns_ntp() -> None:
    secaudit_check_ssid(10)
    secaudit_check_guest_network(11)
    secaudit_check_guest_isolation(12)
    secaudit_check_dns(13)
    secaudit_check_ntp(14)


def secaudit_run_perimeter_and_lan() -> None:
    secaudit_check_dmz(15)
    secaudit_check_wan_ping(16)
    secaudit_check_file_services(17)
    secaudit_check_port_forwards(18)
    secaudit_check_lan_subnet(19)


def secaudit_run_crypto_cloud_admin() -> None:
    secaudit_check_weak_ciphers(20)
    secaudit_check_pmf(21)
    secaudit_check_cloud_remote(22)
    secaudit_check_uart_debug(23)
    secaudit_check_wan_input(24)
    secaudit_check_admin_password(25)


def secaudit_main() -> None:
    if not secaudit_bootstrap():
        sys.exit(0)
    secaudit_run_identity_and_firmware()
    secaudit_run_wireless_core()
    secaudit_run_services_mgmt_firewall()
    secaudit_run_ssid_guest_dns_ntp()
    secaudit_run_perimeter_and_lan()
    secaudit_run_crypto_cloud_admin()
    sys.exit(0)


if __name__ == "__main__":
    secaudit_main()
