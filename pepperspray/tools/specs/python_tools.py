"""In-process python tool specs: JWT analysis, payload generation, sandboxed
file operations, and local python execution. No external binaries required
(except pip/python3 for the install/execute helpers).

For authorized security testing only.
"""

from __future__ import annotations

import base64
import json
import tempfile
import time
from pathlib import Path

from pepperspray.core.executor import ToolResult
from pepperspray.core.registry import REGISTRY, ToolContext, ToolRegistry, ToolSpec


def _ok(name: str, payload) -> ToolResult:
    return ToolResult(
        tool=name,
        status="success",
        stdout=payload if isinstance(payload, str) else json.dumps(payload, indent=2),
    )


def _fail(name: str, msg: str) -> ToolResult:
    return ToolResult(tool=name, status="failed", error=msg)


# --- JWT -------------------------------------------------------------------


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def analyze_jwt(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        return {"valid_structure": False, "error": "JWT must have 3 dot-separated parts"}
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError) as exc:
        return {"valid_structure": False, "error": f"decode failed: {exc}"}

    alg = str(header.get("alg", "")).lower()
    vulns: list[dict] = []
    if alg == "none":
        vulns.append(
            {
                "type": "alg_none",
                "severity": "critical",
                "description": "Token accepts 'none' algorithm (signature bypass)",
            }
        )
    if alg.startswith("hs"):
        vulns.append(
            {
                "type": "hmac_key_confusion",
                "severity": "info",
                "description": "HMAC algorithm — test RS256→HS256 key-confusion if server uses RSA",
            }
        )
    exp = payload.get("exp")
    if isinstance(exp, (int, float)) and exp < time.time():
        vulns.append({"type": "expired", "severity": "info", "description": "Token is expired"})

    return {
        "valid_structure": True,
        "algorithm": header.get("alg", "unknown"),
        "header": header,
        "payload": payload,
        "vulnerabilities": vulns,
    }


# --- Payloads --------------------------------------------------------------

_PAYLOADS = {
    "xss": ["<script>alert(1)</script>", '"><svg/onload=alert(1)>', "javascript:alert(1)"],
    "sqli": ["' OR '1'='1", "' UNION SELECT NULL--", "1; DROP TABLE users--"],
    "lfi": [
        "../../../../etc/passwd",
        "....//....//etc/passwd",
        "php://filter/convert.base64-encode/resource=index.php",
    ],
    "ssti": ["{{7*7}}", "${7*7}", "<%= 7*7 %>"],
    "cmdi": [";id", "|id", "$(id)", "`id`"],
    "ssrf": ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:80"],
}


def generate_payload(payload_type: str) -> dict:
    key = payload_type.lower()
    return {"type": key, "payloads": _PAYLOADS.get(key, []), "available_types": sorted(_PAYLOADS)}


# --- Sandboxed file ops ----------------------------------------------------


def _sandbox_root(ctx: ToolContext) -> Path:
    root = (
        Path(getattr(ctx.settings, "results_dir", "results")) if ctx.settings else Path("results")
    )
    root = root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def _resolve_in_sandbox(ctx: ToolContext, rel: str) -> Path:
    root = _sandbox_root(ctx)
    target = (root / rel).resolve()
    if root not in target.parents and target != root:
        raise ValueError(f"path escapes sandbox: {rel}")
    return target


def _run_create_file(params: dict, ctx: ToolContext) -> ToolResult:
    try:
        target = _resolve_in_sandbox(ctx, params.get("path", ""))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(params.get("content", ""))
    except (ValueError, OSError) as exc:
        return _fail("create_file", str(exc))
    return _ok("create_file", {"created": str(target)})


def _run_modify_file(params: dict, ctx: ToolContext) -> ToolResult:
    try:
        target = _resolve_in_sandbox(ctx, params.get("path", ""))
        if not target.exists():
            return _fail("modify_file", "file does not exist")
        target.write_text(params.get("content", ""))
    except (ValueError, OSError) as exc:
        return _fail("modify_file", str(exc))
    return _ok("modify_file", {"modified": str(target)})


def _run_delete_file(params: dict, ctx: ToolContext) -> ToolResult:
    try:
        target = _resolve_in_sandbox(ctx, params.get("path", ""))
        if target.exists():
            target.unlink()
    except (ValueError, OSError) as exc:
        return _fail("delete_file", str(exc))
    return _ok("delete_file", {"deleted": str(target)})


def _run_list_files(params: dict, ctx: ToolContext) -> ToolResult:
    try:
        base = _resolve_in_sandbox(ctx, params.get("path", "."))
        entries = sorted(str(p.relative_to(_sandbox_root(ctx))) for p in base.glob("**/*"))
    except (ValueError, OSError) as exc:
        return _fail("list_files", str(exc))
    return _ok("list_files", {"entries": entries})


def _run_jwt(params: dict, ctx: ToolContext) -> ToolResult:
    return _ok("jwt_analyzer", analyze_jwt(params.get("jwt_token", params.get("token", ""))))


def _run_generate_payload(params: dict, ctx: ToolContext) -> ToolResult:
    return _ok("generate_payload", generate_payload(params.get("payload_type", "xss")))


def _run_install_package(params: dict, ctx: ToolContext) -> ToolResult:
    pkg = params.get("package", "")
    if not pkg:
        return _fail("install_python_package", "package required")
    return ctx.executor.run("install_python_package", ["pip", "install", pkg])


def _run_execute_script(params: dict, ctx: ToolContext) -> ToolResult:
    code = params.get("script", params.get("code", ""))
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as fh:
        fh.write(code)
        path = fh.name
    try:
        return ctx.executor.run("execute_python_script", ["python3", path])
    finally:
        Path(path).unlink(missing_ok=True)


_PY_SPECS = [
    ("jwt_analyzer", _run_jwt, {"description": "Analyze a JWT for structure and weaknesses"}),
    (
        "generate_payload",
        _run_generate_payload,
        {"description": "Generate attack payloads by type"},
    ),
    ("create_file", _run_create_file, {"description": "Create a file in the results sandbox"}),
    ("modify_file", _run_modify_file, {"description": "Modify a file in the results sandbox"}),
    ("delete_file", _run_delete_file, {"description": "Delete a file in the results sandbox"}),
    ("list_files", _run_list_files, {"description": "List files in the results sandbox"}),
    (
        "install_python_package",
        _run_install_package,
        # RCE primitives: gate behind both authorization and the HITL interrupt.
        {"description": "pip install a package", "active": True, "exploitation": True},
    ),
    (
        "execute_python_script",
        _run_execute_script,
        {"description": "Run a python script locally", "active": True, "exploitation": True},
    ),
]


def register(registry: ToolRegistry = REGISTRY) -> None:
    for name, fn, kw in _PY_SPECS:
        registry.register(
            ToolSpec(name=name, family="utility", executor_kind="python", run=fn, **kw)
        )


register()
