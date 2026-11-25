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

from pepperspray.config import get_settings
from pepperspray.graph.build import run_assessment, stream_assessment, stream_resume
from pepperspray.graph.chains import CHAINS, run_chain
from pepperspray.llm.provider import get_llm
from pepperspray.tools import load_all

app = typer.Typer(help="PepperSpray — LangGraph multi-agent security assessment framework.")


def _render_stream(events) -> None:
    """Print a live line per graph step, then the report or an approval prompt."""
    for ev in events:
        if ev["type"] == "step":
            extra = f"  (+{ev['findings_delta']} findings)" if ev["findings_delta"] else ""
            typer.echo(f"  → {ev['node']}{extra}")
        elif ev["type"] == "approval":
            req = ev.get("request") or {}
            typer.echo(
                "\n⏸  Paused before exploitation-class actions "
                f"({', '.join(ev['awaiting'])}).\n"
                f"    {req.get('message', '')}\n"
                "    Resume:  pepperspray resume <thread-id>                       # approve\n"
                "             pepperspray resume <thread-id> --no-allow-exploitation  # deny"
            )
        elif ev["type"] == "report":
            typer.echo("\n" + (ev.get("report") or "(no report produced)"))


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
    reflect: bool = typer.Option(
        True,
        "--reflect/--no-reflect",
        help="Run the critic/verify reflection loop before reporting.",
    ),
    verify_budget: int = typer.Option(1, help="Max reflection verify passes."),
    stream: bool = typer.Option(
        False, "--stream/--no-stream", help="Show each agent/step live as it runs."
    ),
    thread_id: str = typer.Option("assessment", help="Run id (use to resume a paused run)."),
) -> None:
    """Run the full supervisor/specialist assessment graph."""
    _require_auth(authorized)
    load_all()
    llm = get_llm(model=model) if model else get_llm()

    if stream:
        typer.echo(f"▶  Streaming assessment of {target} (thread: {thread_id})")
        _render_stream(
            stream_assessment(
                target=target,
                objective=objective,
                authorized=authorized,
                llm=llm,
                interrupt_exploitation=not allow_exploitation,
                reflect=reflect,
                verify_budget=verify_budget,
                thread_id=thread_id,
            )
        )
        return

    final = run_assessment(
        target=target,
        objective=objective,
        authorized=authorized,
        llm=llm,
        interrupt_exploitation=not allow_exploitation,
        reflect=reflect,
        verify_budget=verify_budget,
        thread_id=thread_id,
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
    name: str = typer.Argument(..., help=f"Chain name: {', '.join(sorted(CHAINS))}, parallel_scan"),
    target: str = typer.Option(..., help="Target host, URL or domain."),
    authorized: bool = typer.Option(False, "--authorized/--no-authorized"),
    subtargets: str = typer.Option(
        "", help="parallel_scan only: comma-separated hosts/URLs to fan out over."
    ),
) -> None:
    """Run a named fixed workflow (or 'parallel_scan' for concurrent fan-out)."""
    _require_auth(authorized)
    load_all()
    if name == "parallel_scan":
        # Fan-out scanning is deterministic — no LLM required.
        from pepperspray.graph.parallel import run_parallel_scan

        subs = [s.strip() for s in subtargets.split(",") if s.strip()]
        final = run_parallel_scan(target, subtargets=subs, authorized=authorized)
    else:
        final = run_chain(name, target=target, authorized=authorized, llm=get_llm())
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
def resume(
    thread_id: str = typer.Argument(..., help="Thread id of a paused run."),
    allow_exploitation: bool = typer.Option(
        True,
        "--allow-exploitation/--no-allow-exploitation",
        help="Approve the pending exploitation step and continue.",
    ),
    stream: bool = typer.Option(
        False, "--stream/--no-stream", help="Show each agent/step live as it runs."
    ),
) -> None:
    """Resume a durable run that paused at the exploitation gate.

    Requires PEPPERSPRAY_CHECKPOINT_DB to be set (same db as the original run).
    """
    load_all()
    from pepperspray.core.cache import ResultCache
    from pepperspray.core.executor import SafeCommandExecutor
    from pepperspray.core.registry import ToolContext
    from pepperspray.graph.build import resume_after_approval

    if not get_settings().checkpoint_db:
        typer.echo("Set PEPPERSPRAY_CHECKPOINT_DB to the run's db to resume.")
        raise typer.Exit(code=2)
    ctx = ToolContext(executor=SafeCommandExecutor(300), cache=ResultCache())
    decision = "approve" if allow_exploitation else "deny"
    verb = "approved" if allow_exploitation else "denied"

    if stream:
        typer.echo(f"▶  Exploitation {verb}; streaming resume (thread: {thread_id})")
        _render_stream(stream_resume(ctx, thread_id=thread_id, decision=decision, llm=get_llm()))
        return

    final = resume_after_approval(ctx, thread_id=thread_id, decision=decision, llm=get_llm())
    typer.echo(f"Exploitation {verb}; run resumed.\n")
    typer.echo(final.get("report") or "(no report produced)")


@app.command()
def history(thread_id: str = typer.Argument(..., help="Thread id to inspect.")) -> None:
    """Show the checkpoint history (time-travel) of a durable run."""
    load_all()
    from pepperspray.core.cache import ResultCache
    from pepperspray.core.executor import SafeCommandExecutor
    from pepperspray.core.registry import ToolContext
    from pepperspray.graph.build import build_graph
    from pepperspray.graph.persistence import get_checkpointer, list_checkpoints

    cp = get_checkpointer(get_settings().checkpoint_db)
    ctx = ToolContext(executor=SafeCommandExecutor(5), cache=ResultCache())
    graph = build_graph(ctx, checkpointer=cp)
    rows = list_checkpoints(graph, thread_id)
    if not rows:
        typer.echo(f"No checkpoints for thread '{thread_id}'.")
        return
    typer.echo(f"{len(rows)} checkpoints for '{thread_id}' (newest first):")
    for r in rows:
        nxt = ",".join(r["next"]) or "END"
        typer.echo(
            f"  {r['checkpoint_id'][:8]}  next={nxt:12} "
            f"steps={r['completed_steps']} findings={r['findings']}"
        )


@app.command()
def mcp() -> None:
    """Launch the MCP server over stdio."""
    from pepperspray.interfaces.mcp_server import main as mcp_main

    mcp_main()


if __name__ == "__main__":
    app()
