"""Cloud / container / IaC scanner tool specs.

These reach out to live cloud accounts, registries or clusters, so they are
``active=True`` (and cacheable). Each builds an argv list — no shell; user
values are single argv elements, only ``additional_args`` is tokenized (shlex).
For authorized security testing only.
"""

from __future__ import annotations

from pepperspray.core.registry import REGISTRY, ToolRegistry, ToolSpec
from pepperspray.tools.specs._helpers import extra, flag, opt


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


# (name, binary, builder, kwargs)
_SHELL_SPECS = [
    ("prowler_scan", "prowler", _prowler, {"description": "Prowler cloud security assessment"}),
    (
        "scout_suite_assessment",
        "scout",
        _scout_suite,
        {"description": "Scout Suite multi-cloud assessment"},
    ),
    (
        "cloudmapper_analysis",
        "cloudmapper",
        _cloudmapper,
        {"description": "CloudMapper AWS environment analysis"},
    ),
    (
        "kube_hunter_scan",
        "kube-hunter",
        _kube_hunter,
        {"description": "kube-hunter Kubernetes scan"},
    ),
    (
        "kube_bench_cis",
        "kube-bench",
        _kube_bench,
        {"description": "kube-bench CIS Kubernetes benchmark"},
    ),
    (
        "docker_bench_security_scan",
        "docker-bench-security",
        _docker_bench,
        {"description": "Docker Bench Security assessment"},
    ),
    (
        "clair_vulnerability_scan",
        "clairctl",
        _clair,
        {"description": "Clair container vulnerability scan"},
    ),
    ("falco_runtime_monitoring", "falco", _falco, {"description": "Falco runtime monitoring"}),
    ("checkov_iac_scan", "checkov", _checkov, {"description": "Checkov IaC static analysis"}),
    ("terrascan_iac_scan", "terrascan", _terrascan, {"description": "Terrascan IaC scan"}),
    ("trivy_scan", "trivy", _trivy, {"description": "Trivy vulnerability scanner"}),
]


def register(registry: ToolRegistry = REGISTRY) -> None:
    for name, binary, builder, kw in _SHELL_SPECS:
        registry.register(
            ToolSpec(
                name=name,
                family="cloud",
                executor_kind="shell",
                binary=binary,
                build_argv=builder,
                active=True,
                cacheable=True,
                **kw,
            )
        )


register()
