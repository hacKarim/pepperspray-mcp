"""Tool registry: the declarative catalog the agents and MCP server share.

A ``ToolSpec`` describes one capability — a shell CLI (argv builder), an
in-process python function, an HTTP routine, or an orchestrator. The registry
executes it through a single safe path, enforcing authorization and caching.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Literal

from pepperspray.core.cache import ResultCache
from pepperspray.core.errors import AuthorizationError
from pepperspray.core.executor import SafeCommandExecutor, ToolResult

ExecutorKind = Literal["shell", "python", "orchestrator", "http"]

# The primary-input keys a build_argv / run may read. The specialist and MCP
# wrappers spread their single ``target`` value across all of these so a tool
# that keys off a file path, image, account, etc. still receives the input.
PRIMARY_ALIASES = (
    "target",
    "url",
    "domain",
    "base_url",
    "host",
    "ip",
    "file",
    "file_path",
    "binary",
    "memory_file",
    "input_file",
    "cover_file",
    "image",
    "directory",
    "account",
    "hash_file",
    "libc_path",
    "iac_dir",
)


def spread_target(value: str, extra: str = "") -> dict[str, Any]:
    """Build a params dict mapping ``value`` to every primary alias (+ extra)."""
    params: dict[str, Any] = {k: value for k in PRIMARY_ALIASES}
    if extra:
        params["additional_args"] = extra
    return params


@dataclass
class ToolContext:
    """Shared services handed to every tool at execution time."""

    executor: SafeCommandExecutor
    cache: ResultCache
    settings: Any | None = None


@dataclass
class ToolSpec:
    """Declarative description of one tool."""

    name: str
    family: str
    executor_kind: ExecutorKind = "shell"
    binary: str | None = None
    build_argv: Callable[[dict], list[str]] | None = None
    build_input: Callable[[dict], str | None] | None = None
    run: Callable[[dict, ToolContext], ToolResult] | None = None
    timeout: int | None = None
    cacheable: bool = False
    active: bool = False
    exploitation: bool = False
    description: str = ""
    param_defaults: dict[str, Any] = field(default_factory=dict)


class ToolRegistry:
    def __init__(self) -> None:
        self._specs: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> ToolSpec:
        if spec.name in self._specs:
            raise ValueError(f"duplicate tool name: {spec.name}")
        self._specs[spec.name] = spec
        return spec

    def get(self, name: str) -> ToolSpec:
        if name not in self._specs:
            raise KeyError(f"unknown tool: {name}")
        return self._specs[name]

    def all(self) -> list[ToolSpec]:
        return list(self._specs.values())

    def families(self) -> list[str]:
        return sorted({s.family for s in self._specs.values()})

    def by_family(self, family: str) -> list[ToolSpec]:
        return [s for s in self._specs.values() if s.family == family]

    def execute(
        self,
        name: str,
        params: dict,
        ctx: ToolContext,
        authorized: bool,
    ) -> ToolResult:
        spec = self.get(name)
        if spec.active and not authorized:
            raise AuthorizationError(
                f"tool '{name}' is active and requires authorization "
                "(pass authorized=True only for targets you may test)"
            )

        merged = {**spec.param_defaults, **(params or {})}

        cache_key = None
        if spec.cacheable:
            cache_key = ctx.cache.key(name, merged)
            cached = ctx.cache.get(cache_key)
            if cached is not None:
                return cached

        result = self._dispatch(spec, merged, ctx)

        if cache_key is not None and result.status == "success":
            ctx.cache.set(cache_key, result)
        return result

    def _dispatch(self, spec: ToolSpec, params: dict, ctx: ToolContext) -> ToolResult:
        if spec.executor_kind == "shell":
            if spec.build_argv is None:
                return ToolResult(
                    tool=spec.name, status="failed", error="shell tool has no build_argv"
                )
            argv = spec.build_argv(params)
            injected = _option_injection(argv, params)
            if injected is not None:
                return ToolResult(
                    tool=spec.name,
                    status="failed",
                    argv=argv,
                    error=f"refusing: value {injected!r} looks like an option "
                    "(leading '-'); a target/path must not start with '-'",
                )
            input_text = spec.build_input(params) if spec.build_input else None
            return ctx.executor.run(spec.name, argv, timeout=spec.timeout, input_text=input_text)
        # python / http / orchestrator
        if spec.run is None:
            return ToolResult(
                tool=spec.name, status="failed", error=f"{spec.executor_kind} tool has no run()"
            )
        return spec.run(params, ctx)


def _option_injection(argv: list[str], params: dict) -> str | None:
    """Return a user-supplied primary value that appears in argv as an option.

    Guards against argument injection: a target/path that begins with '-' would
    otherwise be interpreted by the tool as a flag. Only values the caller
    supplied for a primary-input key are checked, so legitimate tool flags are
    never rejected.
    """
    user_values = {
        v
        for k, v in params.items()
        if k in PRIMARY_ALIASES and isinstance(v, str) and v.startswith("-")
    }
    if not user_values:
        return None
    for token in argv:
        if token in user_values:
            return token
    return None


# Process-wide singleton shared by tool spec modules, agents, and the MCP server.
REGISTRY = ToolRegistry()


def tool(**kwargs: Any) -> Callable:
    """Decorator registering a python/http/orchestrator tool from a function."""

    def decorator(fn: Callable[[dict, ToolContext], ToolResult]) -> Callable:
        spec = ToolSpec(
            name=kwargs.get("name", fn.__name__),
            family=kwargs["family"],
            executor_kind=kwargs.get("executor_kind", "python"),
            run=fn,
            timeout=kwargs.get("timeout"),
            cacheable=kwargs.get("cacheable", False),
            active=kwargs.get("active", False),
            exploitation=kwargs.get("exploitation", False),
            description=kwargs.get("description", fn.__doc__ or ""),
        )
        REGISTRY.register(spec)
        return fn

    return decorator
