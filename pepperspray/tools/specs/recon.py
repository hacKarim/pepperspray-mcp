"""Recon / discovery / enumeration tool specs.

Each ToolSpec builds an argv list (no shell). Defaults mirror the legacy Flask
handlers. ``active=True`` marks tools that touch a target over the network.
For authorized security testing only.
"""

from __future__ import annotations

from pepperspray.core.registry import REGISTRY, ToolRegistry, ToolSpec
from pepperspray.tools.specs._helpers import extra, flag, opt


def _nmap(p: dict) -> list[str]:
    argv = ["nmap"] + extra({"a": p.get("scan_type", "-sCV")}, "a")
    argv += opt("-p", p.get("ports"))
    argv += extra(p, "additional_args") or ["-T4", "-Pn"]
    argv += [p.get("target", "")]
    return argv


def _nmap_advanced(p: dict) -> list[str]:
    argv = ["nmap", p.get("scan_type", "-sS"), f"-{p.get('timing', 'T4')}"]
    argv += opt("-p", p.get("ports"))
    argv += opt("--script", p.get("nse_scripts"))
    argv += flag("-O", p.get("os_detection"))
    argv += flag("-sV", p.get("version_detection"))
    argv += flag("-A", p.get("aggressive"))
    argv += extra(p)
    argv += [p.get("target", "")]
    return argv


def _rustscan(p: dict) -> list[str]:
    argv = [
        "rustscan",
        "-a",
        p.get("target", ""),
        "--ulimit",
        str(p.get("ulimit", 5000)),
        "-b",
        str(p.get("batch_size", 4500)),
        "-t",
        str(p.get("timeout", 1500)),
    ]
    argv += opt("-p", p.get("ports"))
    argv += extra(p)
    return argv


def _masscan(p: dict) -> list[str]:
    argv = [
        "masscan",
        p.get("target", ""),
        f"-p{p.get('ports', '1-65535')}",
        f"--rate={p.get('rate', 1000)}",
    ]
    argv += opt("-e", p.get("interface"))
    argv += opt("--router-mac", p.get("router_mac"))
    argv += opt("--source-ip", p.get("source_ip"))
    argv += flag("--banners", p.get("banners"))
    argv += extra(p)
    return argv


def _autorecon(p: dict) -> list[str]:
    return ["autorecon", p.get("target", "")] + extra(p)


def _amass(p: dict) -> list[str]:
    return ["amass", p.get("mode", "enum"), "-d", p.get("domain", "")] + extra(p)


def _subfinder(p: dict) -> list[str]:
    argv = ["subfinder", "-d", p.get("domain", "")]
    argv += flag("-silent", p.get("silent", True))
    argv += flag("-all", p.get("all_sources"))
    argv += extra(p)
    return argv


def _fierce(p: dict) -> list[str]:
    argv = ["fierce", "--domain", p.get("domain", "")]
    argv += opt("--dns-servers", p.get("dns_server"))
    argv += extra(p)
    return argv


def _dnsenum(p: dict) -> list[str]:
    argv = ["dnsenum", p.get("domain", "")]
    argv += opt("--dnsserver", p.get("dns_server"))
    argv += opt("--file", p.get("wordlist"))
    argv += extra(p)
    return argv


def _wafw00f(p: dict) -> list[str]:
    return ["wafw00f", p.get("target", "")] + extra(p)


def _enum4linux(p: dict) -> list[str]:
    return (
        ["enum4linux"] + extra({"a": p.get("additional_args", "-a")}, "a") + [p.get("target", "")]
    )


def _enum4linux_ng(p: dict) -> list[str]:
    return (
        ["enum4linux-ng"]
        + extra({"a": p.get("additional_args", "-A")}, "a")
        + [p.get("target", "")]
    )


def _rpcclient(p: dict) -> list[str]:
    argv = ["rpcclient", "-U", p.get("user", "")]
    argv += opt("-c", p.get("command"))
    argv += extra(p)
    argv += [p.get("target", "")]
    return argv


def _nbtscan(p: dict) -> list[str]:
    return ["nbtscan"] + extra(p) + [p.get("target", "")]


def _arp_scan(p: dict) -> list[str]:
    argv = ["arp-scan"]
    argv += flag("--localnet", p.get("localnet"))
    argv += extra(p)
    if not p.get("localnet"):
        argv += [p.get("target", "")]
    return argv


def _responder(p: dict) -> list[str]:
    return ["responder", "-I", p.get("interface", "eth0")] + extra(p)


def _smbmap(p: dict) -> list[str]:
    argv = ["smbmap", "-H", p.get("target", "")]
    argv += opt("-u", p.get("username"))
    argv += opt("-p", p.get("password"))
    argv += opt("-d", p.get("domain"))
    argv += extra(p)
    return argv


def _netexec(p: dict) -> list[str]:
    argv = ["nxc", p.get("protocol", "smb"), p.get("target", "")]
    argv += opt("-u", p.get("username"))
    argv += opt("-p", p.get("password"))
    argv += opt("-H", p.get("hash"))
    argv += opt("-M", p.get("module"))
    argv += extra(p)
    return argv


def _gau(p: dict) -> list[str]:
    argv = ["gau", p.get("domain", "")]
    argv += opt("--providers", p.get("providers"))
    argv += flag("--subs", p.get("include_subs", True))
    argv += opt("--blacklist", p.get("blacklist"))
    argv += extra(p)
    return argv


def _waybackurls(p: dict) -> list[str]:
    argv = ["waybackurls", p.get("domain", "")]
    argv += flag("--get-versions", p.get("get_versions"))
    argv += flag("--no-subs", p.get("no_subs"))
    argv += extra(p)
    return argv


def _hakrawler(p: dict) -> list[str]:
    argv = ["hakrawler", "-d", str(p.get("depth", 2)), "-u"]
    argv += flag("-s", p.get("forms", True))
    argv += flag("-subs", p.get("subs"))
    argv += extra(p)
    return argv


def _katana(p: dict) -> list[str]:
    argv = ["katana", "-u", p.get("url", ""), "-d", str(p.get("depth", 3))]
    argv += flag("-jc", p.get("js_crawl", True))
    argv += flag("-fx", p.get("form_extraction", True))
    argv += flag("-jsonl", p.get("output_format", "json") == "json")
    argv += extra(p)
    return argv


# (name, builder, active, kwargs) — all recon tools touch the network -> active
_SHELL_SPECS = [
    ("nmap_scan", "nmap", _nmap, {"description": "Nmap port/service scan"}),
    ("nmap_advanced_scan", "nmap", _nmap_advanced, {"description": "Nmap advanced scan"}),
    ("rustscan_fast_scan", "rustscan", _rustscan, {"description": "RustScan fast port scan"}),
    ("masscan_high_speed", "masscan", _masscan, {"description": "Masscan high-speed scan"}),
    (
        "autorecon_comprehensive",
        "autorecon",
        _autorecon,
        {"description": "AutoRecon multi-tool recon"},
    ),
    ("amass_scan", "amass", _amass, {"description": "Amass subdomain enumeration"}),
    ("subfinder_scan", "subfinder", _subfinder, {"description": "Subfinder subdomain discovery"}),
    ("fierce_scan", "fierce", _fierce, {"description": "Fierce DNS recon"}),
    ("dnsenum_scan", "dnsenum", _dnsenum, {"description": "dnsenum DNS enumeration"}),
    ("wafw00f_scan", "wafw00f", _wafw00f, {"description": "wafw00f WAF fingerprinting"}),
    ("enum4linux_scan", "enum4linux", _enum4linux, {"description": "enum4linux SMB enumeration"}),
    (
        "enum4linux_ng_advanced",
        "enum4linux-ng",
        _enum4linux_ng,
        {"description": "enum4linux-ng enumeration"},
    ),
    (
        "rpcclient_enumeration",
        "rpcclient",
        _rpcclient,
        {"description": "rpcclient MSRPC enumeration"},
    ),
    ("nbtscan_netbios", "nbtscan", _nbtscan, {"description": "nbtscan NetBIOS discovery"}),
    ("arp_scan_discovery", "arp-scan", _arp_scan, {"description": "arp-scan host discovery"}),
    (
        "responder_credential_harvest",
        "responder",
        _responder,
        {"description": "Responder LLMNR/NBT-NS", "exploitation": True},
    ),
    ("smbmap_scan", "smbmap", _smbmap, {"description": "smbmap SMB share enumeration"}),
    ("netexec_scan", "nxc", _netexec, {"description": "NetExec (nxc) network execution"}),
    ("gau_discovery", "gau", _gau, {"description": "gau historical URL discovery"}),
    (
        "waybackurls_discovery",
        "waybackurls",
        _waybackurls,
        {"description": "waybackurls URL discovery"},
    ),
    (
        "hakrawler_crawl",
        "hakrawler",
        _hakrawler,
        {"description": "hakrawler web crawler", "build_input": lambda p: p.get("url", "")},
    ),
    ("katana_crawl", "katana", _katana, {"description": "katana web crawler"}),
]


def register(registry: ToolRegistry = REGISTRY) -> None:
    for name, binary, builder, kw in _SHELL_SPECS:
        kwargs = dict(kw)
        build_input = kwargs.pop("build_input", None)
        registry.register(
            ToolSpec(
                name=name,
                family="recon",
                executor_kind="shell",
                binary=binary,
                build_argv=builder,
                build_input=build_input,
                active=True,
                cacheable=True,
                **kwargs,
            )
        )


register()
