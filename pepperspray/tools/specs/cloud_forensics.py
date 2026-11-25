"""Cloud / container / IaC scanner and digital-forensics tool specs.

Two families live here:

* ``cloud`` — cloud, container and infrastructure-as-code scanners. They reach
  out to live cloud accounts / registries / clusters, so ``active=True``.
* ``forensics`` — memory, disk and file artifact analysis. They operate on
  LOCAL files only and touch no network, so ``active=False``.

Each ToolSpec builds an argv list (no shell). Defaults mirror the legacy Flask
handlers. User-supplied values (target, file, account, directory, ...) are
always appended as single argv elements; free-form ``additional_args`` is split
with shlex via ``extra()``. For authorized security testing only.
"""

from __future__ import annotations

from pepperspray.core.registry import REGISTRY, ToolRegistry, ToolSpec
from pepperspray.tools.specs._helpers import extra, flag, opt


# --------------------------------------------------------------------------- #
# FAMILY: cloud (active)
# --------------------------------------------------------------------------- #
def _prowler(p: dict) -> list[str]:
    argv = ["prowler", p.get("provider", "aws")]
    argv += opt("--profile", p.get("profile", "default"))
    argv += opt("--region", p.get("region"))
    argv += opt("--checks", p.get("checks"))
    argv += ["--output-directory", str(p.get("output_dir", "/tmp/prowler_output"))]
    argv += ["--output-format", str(p.get("output_format", "json"))]
    argv += extra(p)
    return argv


def _scout_suite(p: dict) -> list[str]:
    argv = ["scout", p.get("provider", "aws")]
    argv += opt("--profile", p.get("profile", "default"))
    argv += opt("--services", p.get("services"))
    argv += opt("--exceptions", p.get("exceptions"))
    argv += ["--report-dir", str(p.get("report_dir", "/tmp/scout-suite"))]
    argv += extra(p)
    return argv


def _cloudmapper(p: dict) -> list[str]:
    argv = ["cloudmapper", p.get("action", "collect")]
    argv += opt("--account", p.get("account"))
    argv += opt("--config", p.get("config", "config.json"))
    argv += extra(p)
    return argv


def _kube_hunter(p: dict) -> list[str]:
    argv = ["kube-hunter"]
    argv += opt("--remote", p.get("target") or p.get("remote"))
    argv += opt("--cidr", p.get("cidr"))
    argv += opt("--interface", p.get("interface"))
    argv += flag("--active", p.get("active"))
    argv += opt("--report", p.get("report", "json"))
    argv += extra(p)
    return argv


def _kube_bench(p: dict) -> list[str]:
    argv = ["kube-bench"]
    argv += opt("--targets", p.get("targets"))
    argv += opt("--version", p.get("version"))
    argv += opt("--config-dir", p.get("config_dir"))
    fmt = str(p.get("output_format", "json"))
    argv += ["--outputfile", f"/tmp/kube-bench-results.{fmt}", "--json"]
    argv += extra(p)
    return argv


def _docker_bench(p: dict) -> list[str]:
    argv = ["docker-bench-security"]
    argv += opt("-c", p.get("checks"))
    argv += opt("-e", p.get("exclude"))
    argv += opt("-l", p.get("output_file", "/tmp/docker-bench-results.json"))
    argv += extra(p)
    return argv


def _clair(p: dict) -> list[str]:
    argv = ["clairctl", "analyze", p.get("image", "")]
    argv += opt("--config", p.get("config", "/etc/clair/config.yaml"))
    argv += opt("--format", p.get("output_format", "json"))
    argv += extra(p)
    return argv


def _falco(p: dict) -> list[str]:
    argv = ["falco"]
    argv += opt("--config", p.get("config_file", "/etc/falco/falco.yaml"))
    argv += opt("--rules", p.get("rules_file"))
    argv += flag("--json", True)
    argv += extra(p)
    return argv


def _checkov(p: dict) -> list[str]:
    if p.get("file"):
        argv = ["checkov", "-f", p.get("file", "")]
    else:
        argv = ["checkov", "-d", str(p.get("directory", "."))]
    argv += opt("--framework", p.get("framework"))
    argv += opt("--check", p.get("check"))
    argv += opt("--skip-check", p.get("skip_check"))
    argv += opt("--output", p.get("output_format", "json"))
    argv += extra(p)
    return argv


def _terrascan(p: dict) -> list[str]:
    argv = [
        "terrascan",
        "scan",
        "-t",
        str(p.get("scan_type", "all")),
        "-d",
        str(p.get("iac_dir", ".")),
    ]
    argv += opt("-p", p.get("policy_type"))
    argv += opt("-o", p.get("output_format", "json"))
    argv += opt("--severity", p.get("severity"))
    argv += extra(p)
    return argv


def _trivy(p: dict) -> list[str]:
    argv = ["trivy", str(p.get("scan_type", "image")), p.get("target", "")]
    argv += opt("--format", p.get("output_format", "json"))
    argv += opt("--severity", p.get("severity"))
    argv += opt("--output", p.get("output_file"))
    argv += extra(p)
    return argv


# --------------------------------------------------------------------------- #
# FAMILY: forensics (local files, not active)
# --------------------------------------------------------------------------- #
def _volatility(p: dict) -> list[str]:
    argv = ["volatility", "-f", p.get("memory_file") or p.get("file", "")]
    if p.get("profile"):
        argv += [f"--profile={p.get('profile')}"]
    argv += [p.get("plugin", "")]
    argv += extra(p)
    return argv


def _volatility3(p: dict) -> list[str]:
    argv = ["vol", "-f", p.get("memory_file") or p.get("file", ""), p.get("plugin", "")]
    argv += opt("-o", p.get("output_file"))
    argv += extra(p)
    return argv


def _foremost(p: dict) -> list[str]:
    argv = ["foremost", "-o", str(p.get("output_dir", "/tmp/foremost_output"))]
    argv += opt("-t", p.get("file_types"))
    argv += extra(p)
    argv += [p.get("input_file") or p.get("file", "")]
    return argv


def _steghide(p: dict) -> list[str]:
    action = p.get("action", "extract")
    cover = p.get("cover_file") or p.get("file", "")
    if action == "embed":
        argv = ["steghide", "embed", "-cf", cover, "-ef", p.get("embed_file", "")]
    elif action == "info":
        argv = ["steghide", "info", cover]
    else:
        argv = ["steghide", "extract", "-sf", cover]
        argv += opt("-xf", p.get("output_file"))
    argv += ["-p", str(p.get("passphrase", ""))]
    argv += extra(p)
    return argv


def _exiftool(p: dict) -> list[str]:
    argv = ["exiftool"]
    if p.get("output_format"):
        argv += [f"-{p.get('output_format')}"]
    if p.get("tags"):
        argv += [f"-{p.get('tags')}"]
    argv += extra(p)
    argv += [p.get("file_path") or p.get("file", "")]
    return argv


# (name, family, binary, builder, kwargs)
_SHELL_SPECS = [
    # --- cloud ---
    (
        "prowler_scan",
        "cloud",
        "prowler",
        _prowler,
        {"description": "Prowler cloud security assessment"},
    ),
    (
        "scout_suite_assessment",
        "cloud",
        "scout",
        _scout_suite,
        {"description": "Scout Suite multi-cloud assessment"},
    ),
    (
        "cloudmapper_analysis",
        "cloud",
        "cloudmapper",
        _cloudmapper,
        {"description": "CloudMapper AWS environment analysis"},
    ),
    (
        "kube_hunter_scan",
        "cloud",
        "kube-hunter",
        _kube_hunter,
        {"description": "kube-hunter Kubernetes scan"},
    ),
    (
        "kube_bench_cis",
        "cloud",
        "kube-bench",
        _kube_bench,
        {"description": "kube-bench CIS Kubernetes benchmark"},
    ),
    (
        "docker_bench_security_scan",
        "cloud",
        "docker-bench-security",
        _docker_bench,
        {"description": "Docker Bench Security assessment"},
    ),
    (
        "clair_vulnerability_scan",
        "cloud",
        "clairctl",
        _clair,
        {"description": "Clair container vulnerability scan"},
    ),
    (
        "falco_runtime_monitoring",
        "cloud",
        "falco",
        _falco,
        {"description": "Falco runtime monitoring"},
    ),
    (
        "checkov_iac_scan",
        "cloud",
        "checkov",
        _checkov,
        {"description": "Checkov IaC static analysis"},
    ),
    ("terrascan_iac_scan", "cloud", "terrascan", _terrascan, {"description": "Terrascan IaC scan"}),
    ("trivy_scan", "cloud", "trivy", _trivy, {"description": "Trivy vulnerability scanner"}),
    # --- forensics ---
    (
        "volatility_analyze",
        "forensics",
        "volatility",
        _volatility,
        {"description": "Volatility 2 memory analysis"},
    ),
    (
        "volatility3_analyze",
        "forensics",
        "vol",
        _volatility3,
        {"description": "Volatility 3 memory analysis"},
    ),
    (
        "foremost_carving",
        "forensics",
        "foremost",
        _foremost,
        {"description": "Foremost file carving"},
    ),
    (
        "steghide_analysis",
        "forensics",
        "steghide",
        _steghide,
        {"description": "Steghide steganography analysis"},
    ),
    (
        "exiftool_extract",
        "forensics",
        "exiftool",
        _exiftool,
        {"description": "ExifTool metadata extraction"},
    ),
]


def register(registry: ToolRegistry = REGISTRY) -> None:
    for name, family, binary, builder, kw in _SHELL_SPECS:
        kwargs = dict(kw)
        build_input = kwargs.pop("build_input", None)
        registry.register(
            ToolSpec(
                name=name,
                family=family,
                executor_kind="shell",
                binary=binary,
                build_argv=builder,
                build_input=build_input,
                active=(family == "cloud"),
                cacheable=True,
                **kwargs,
            )
        )


register()
