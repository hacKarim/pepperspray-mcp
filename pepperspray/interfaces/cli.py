"""PepperSpray command-line interface.

Commands:
  run         Run the full multi-agent assessment graph against a target.
  chain       Run a named fixed workflow (chain).
  list-tools  List registered tools (optionally by family).
  mcp         Launch the MCP server (stdio).

Active assessments require explicit authorization. Authorized testing only.
"""

from __future__ import annotations

import typer

from pepperspray.graph.build import run_assessment
from pepperspray.graph.chains import CHAINS, run_chain
from pepperspray.llm.provider import get_llm
from pepperspray.tools import load_all

app = typer.Typer(help="PepperSpray — LangGraph multi-agent security assessment framework.")


def _require_auth(authorized: bool) -> None:
    if not authorized:
        typer.echo(
            "Refusing to run: active assessment requires --authorized. "
            "Only test systems you own or have explicit written permission to test.",
        )
        raise typer.Exit(code=2)


@app.command()
def run(
    target: str = typer.Option(..., help="Target host, URL or domain."),
    objective: str = typer.Option("comprehensive", help="Assessment objective."),
    authorized: bool = typer.Option(
        False, "--authorized/--no-authorized", help="Confirm you are authorized to test the target."
    ),
    model: str = typer.Option(None, help="Override the LLM model id."),
    allow_exploitation: bool = typer.Option(
        False,
        "--allow-exploitation/--no-allow-exploitation",
        help="Run exploitation-class steps without pausing for approval.",
    ),
) -> None:
    """Run the full supervisor/specialist assessment graph."""
    _require_auth(authorized)
    load_all()
    llm = get_llm(model=model) if model else get_llm()
    final = run_assessment(
        target=target,
        objective=objective,
        authorized=authorized,
        llm=llm,
        interrupt_exploitation=not allow_exploitation,
    )
    typer.echo(final.get("report") or "(no report produced)")
    if final.get("awaiting_approval"):
        typer.echo(
            "\n⏸  Paused before exploitation-class actions "
            f"({', '.join(final['awaiting_approval'])}). "
            "Re-run with --allow-exploitation to proceed (authorized targets only)."
        )


@app.command()
def chain(
    name: str = typer.Argument(..., help=f"Chain name: {', '.join(sorted(CHAINS))}"),
    target: str = typer.Option(..., help="Target host, URL or domain."),
    authorized: bool = typer.Option(False, "--authorized/--no-authorized"),
) -> None:
    """Run a named fixed workflow."""
    _require_auth(authorized)
    load_all()
    llm = get_llm()
    final = run_chain(name, target=target, authorized=authorized, llm=llm)
    typer.echo(final.get("report") or "(no report produced)")


@app.command("list-tools")
def list_tools(family: str = typer.Option(None, help="Filter by family.")) -> None:
    """List registered tools."""
    load_all()
    from pepperspray.core.registry import REGISTRY

    specs = REGISTRY.by_family(family) if family else REGISTRY.all()
    specs = sorted(specs, key=lambda s: (s.family, s.name))
    typer.echo(f"{len(specs)} tools" + (f" in family '{family}'" if family else "") + ":")
    for s in specs:
        flags = []
        if s.active:
            flags.append("active")
        if s.exploitation:
            flags.append("exploit")
        tag = f" [{','.join(flags)}]" if flags else ""
        typer.echo(f"  {s.family:12} {s.name:34}{tag}  {s.description}")


@app.command()
def mcp() -> None:
    """Launch the MCP server over stdio."""
    from pepperspray.interfaces.mcp_server import main as mcp_main

    mcp_main()


if __name__ == "__main__":
    app()
