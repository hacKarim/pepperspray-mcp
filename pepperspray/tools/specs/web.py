"""Web app / content-discovery / vuln / parameter tool specs.

Each ToolSpec builds an argv list (no shell). Defaults mirror the legacy Flask
handlers. ``active=True`` marks tools that touch a target over the network.
Core parameters (url/target/domain/data/param and friends) are always appended
as single argv elements; only free-form ``additional_args`` is tokenized via
``extra()`` (shlex). For authorized security testing only.
"""

from __future__ import annotations

from pepperspray.core.registry import REGISTRY, ToolRegistry, ToolSpec
from pepperspray.tools.specs._helpers import extra, flag, opt

_DIRB_WORDLIST = "/usr/share/wordlists/dirb/common.txt"


# --- content discovery / fuzzing ------------------------------------------


def _gobuster(p: dict) -> list[str]:
    argv = [
        "gobuster",
        p.get("mode", "dir"),
        "-u",
        p.get("url", ""),
        "-w",
        p.get("wordlist", _DIRB_WORDLIST),
    ]
    argv += extra(p)
    return argv


def _dirb(p: dict) -> list[str]:
    return ["dirb", p.get("url", ""), p.get("wordlist", _DIRB_WORDLIST)] + extra(p)


def _ffuf(p: dict) -> list[str]:
    url = p.get("url", "")
    wordlist = p.get("wordlist", _DIRB_WORDLIST)
    mode = p.get("mode", "directory")
    argv = ["ffuf"]
    if mode == "directory":
        argv += ["-u", url + "/FUZZ", "-w", wordlist]
    elif mode == "vhost":
        argv += ["-u", url, "-H", "Host: FUZZ", "-w", wordlist]
    elif mode == "parameter":
        argv += ["-u", url + "?FUZZ=value", "-w", wordlist]
    else:
        argv += ["-u", url, "-w", wordlist]
    argv += ["-mc", p.get("match_codes", "200,204,301,302,307,401,403")]
    argv += extra(p)
    return argv


def _feroxbuster(p: dict) -> list[str]:
    argv = [
        "feroxbuster",
        "-u",
        p.get("url", ""),
        "-w",
        p.get("wordlist", _DIRB_WORDLIST),
        "-t",
        str(p.get("threads", 10)),
    ]
    argv += extra(p)
    return argv


def _dirsearch(p: dict) -> list[str]:
    argv = [
        "dirsearch",
        "-u",
        p.get("url", ""),
        "-e",
        p.get("extensions", "php,html,js,txt,xml,json"),
        "-w",
        p.get("wordlist", "/usr/share/wordlists/dirsearch/common.txt"),
        "-t",
        str(p.get("threads", 30)),
    ]
    argv += flag("-r", p.get("recursive", False))
    argv += extra(p)
    return argv


def _wfuzz(p: dict) -> list[str]:
    argv = ["wfuzz", "-w", p.get("wordlist", _DIRB_WORDLIST), p.get("url", "")]
    argv += extra(p)
    return argv


# --- traversal / xss -------------------------------------------------------


def _dotdotpwn(p: dict) -> list[str]:
    argv = ["dotdotpwn", "-m", p.get("module", "http"), "-h", p.get("target", "")]
    argv += extra(p)
    argv += ["-b"]
    return argv


def _xsser(p: dict) -> list[str]:
    argv = ["xsser", "--url", p.get("url", "")]
    argv += opt("--param", p.get("params"))
    argv += extra(p)
    return argv


def _dalfox(p: dict) -> list[str]:
    if p.get("pipe_mode"):
        argv = ["dalfox", "pipe"]
    else:
        argv = ["dalfox", "url", p.get("url", "")]
    argv += flag("--blind", p.get("blind", False))
    argv += flag("--mining-dom", p.get("mining_dom", True))
    argv += flag("--mining-dict", p.get("mining_dict", True))
    argv += opt("--custom-payload", p.get("custom_payload"))
    argv += extra(p)
    return argv


# --- probing / vuln scanning ----------------------------------------------


def _httpx(p: dict) -> list[str]:
    # -u probes a single host directly; -l expects a FILE of targets (wrong here).
    argv = ["httpx", "-u", p.get("target", ""), "-t", str(p.get("threads", 50))]
    argv += flag("-probe", p.get("probe", True))
    argv += flag("-tech-detect", p.get("tech_detect", False))
    argv += flag("-sc", p.get("status_code", False))
    argv += flag("-cl", p.get("content_length", False))
    argv += flag("-title", p.get("title", False))
    argv += flag("-server", p.get("web_server", False))
    argv += extra(p)
    return argv


def _nikto(p: dict) -> list[str]:
    return ["nikto", "-h", p.get("target", "")] + extra(p)


def _nuclei(p: dict) -> list[str]:
    argv = ["nuclei", "-u", p.get("target", "")]
    argv += opt("-severity", p.get("severity"))
    argv += opt("-tags", p.get("tags"))
    argv += opt("-t", p.get("template"))
    argv += extra(p)
    return argv


def _wpscan(p: dict) -> list[str]:
    return ["wpscan", "--url", p.get("url", "")] + extra(p)


def _jaeles(p: dict) -> list[str]:
    argv = [
        "jaeles",
        "scan",
        "-u",
        p.get("url", ""),
        "-c",
        str(p.get("threads", 20)),
        "--timeout",
        str(p.get("timeout", 20)),
    ]
    argv += opt("-s", p.get("signatures"))
    argv += opt("--config", p.get("config"))
    argv += extra(p)
    return argv


def _burpsuite_alt(p: dict) -> list[str]:
    # Legacy was an in-process python orchestrator (browser agent + HTTP spider +
    # vuln scanner), not a shell command. Ported to a simple nuclei-based active
    # scan of the target (see report note).
    argv = ["nuclei", "-u", p.get("target", "")]
    argv += extra(p)
    return argv


def _zap(p: dict) -> list[str]:
    target = p.get("target", "")
    scan_type = p.get("scan_type", "baseline")
    api_key = p.get("api_key", "")
    host = p.get("host", "0.0.0.0")
    port = p.get("port", "8090")
    fmt = p.get("format", "xml")
    output_file = p.get("output_file", "")
    if p.get("daemon") or scan_type == "daemon":
        argv = ["zap", "-daemon", "-host", host, "-port", str(port)]
        if api_key:
            argv += ["-config", "api.key=" + api_key]
    else:
        argv = ["zap", "-cmd", "-quickurl", target]
        if fmt:
            argv += ["-quickout", fmt]
        if output_file:
            argv += ["-quickprogress", "-dir", output_file]
        if api_key:
            argv += ["-config", "api.key=" + api_key]
    argv += extra(p)
    return argv


# --- parameter discovery ---------------------------------------------------


def _arjun(p: dict) -> list[str]:
    argv = [
        "arjun",
        "-u",
        p.get("url", ""),
        "-m",
        p.get("method", "GET"),
        "-t",
        str(p.get("threads", 25)),
    ]
    argv += opt("-w", p.get("wordlist"))
    argv += opt("-d", p.get("delay", 0))
    argv += flag("--stable", p.get("stable", False))
    argv += extra(p)
    return argv


def _paramspider(p: dict) -> list[str]:
    argv = ["paramspider", "-d", p.get("domain", ""), "-l", str(p.get("level", 2))]
    argv += opt("--exclude", p.get("exclude", "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico"))
    argv += opt("-o", p.get("output"))
    argv += extra(p)
    return argv


def _x8(p: dict) -> list[str]:
    argv = [
        "x8",
        "-u",
        p.get("url", ""),
        "-w",
        p.get("wordlist", "/usr/share/wordlists/x8/params.txt"),
        "-X",
        p.get("method", "GET"),
    ]
    argv += opt("-b", p.get("body"))
    argv += opt("-H", p.get("headers"))
    argv += extra(p)
    return argv


# --- stdin pipeline tools (value flows through stdin, never argv) ----------


def _anew(p: dict) -> list[str]:
    return ["anew"] + extra(p)


def _qsreplace(p: dict) -> list[str]:
    return ["qsreplace"] + extra(p)


def _uro(p: dict) -> list[str]:
    return ["uro"] + extra(p)


def _stdin(p: dict) -> str:
    return p.get("text", "") or p.get("input", "")


# (name, binary, builder, kwargs) — all web tools touch the network -> active
_SHELL_SPECS = [
    (
        "gobuster_scan",
        "gobuster",
        _gobuster,
        {"description": "Gobuster content/DNS/vhost brute force"},
    ),
    ("dirb_scan", "dirb", _dirb, {"description": "Dirb directory brute force"}),
    ("ffuf_scan", "ffuf", _ffuf, {"description": "ffuf web fuzzer"}),
    (
        "feroxbuster_scan",
        "feroxbuster",
        _feroxbuster,
        {"description": "feroxbuster recursive content discovery"},
    ),
    ("dirsearch_scan", "dirsearch", _dirsearch, {"description": "dirsearch directory brute force"}),
    ("wfuzz_scan", "wfuzz", _wfuzz, {"description": "wfuzz web fuzzer"}),
    (
        "dotdotpwn_scan",
        "dotdotpwn",
        _dotdotpwn,
        {"description": "DotDotPwn directory traversal fuzzer"},
    ),
    ("xsser_scan", "xsser", _xsser, {"description": "XSSer cross-site scripting scanner"}),
    ("dalfox_xss_scan", "dalfox", _dalfox, {"description": "Dalfox XSS scanner"}),
    (
        "httpx_probe",
        "httpx",
        _httpx,
        {"description": "httpx HTTP probe"},
    ),
    ("nikto_scan", "nikto", _nikto, {"description": "Nikto web server scanner"}),
    ("nuclei_scan", "nuclei", _nuclei, {"description": "Nuclei template-based vulnerability scan"}),
    ("wpscan_analyze", "wpscan", _wpscan, {"description": "WPScan WordPress scanner"}),
    (
        "jaeles_vulnerability_scan",
        "jaeles",
        _jaeles,
        {"description": "Jaeles signature-based vulnerability scan"},
    ),
    (
        "arjun_parameter_discovery",
        "arjun",
        _arjun,
        {"description": "Arjun HTTP parameter discovery"},
    ),
    (
        "paramspider_mining",
        "paramspider",
        _paramspider,
        {"description": "ParamSpider parameter mining"},
    ),
    ("x8_parameter_discovery", "x8", _x8, {"description": "x8 hidden parameter discovery"}),
    (
        "anew_data_processing",
        "anew",
        _anew,
        {"description": "anew append-unique stream filter", "build_input": _stdin},
    ),
    (
        "qsreplace_parameter_replacement",
        "qsreplace",
        _qsreplace,
        {"description": "qsreplace query-string replacer", "build_input": _stdin},
    ),
    (
        "uro_url_filtering",
        "uro",
        _uro,
        {"description": "uro URL list deduplication/filtering", "build_input": _stdin},
    ),
    (
        "burpsuite_alternative_scan",
        "nuclei",
        _burpsuite_alt,
        {"description": "Burp Suite alternative active scan (nuclei-based)"},
    ),
    ("zap_scan", "zap", _zap, {"description": "OWASP ZAP baseline/daemon scan"}),
]


def register(registry: ToolRegistry = REGISTRY) -> None:
    for name, binary, builder, kw in _SHELL_SPECS:
        kwargs = dict(kw)
        build_input = kwargs.pop("build_input", None)
        registry.register(
            ToolSpec(
                name=name,
                family="web",
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
